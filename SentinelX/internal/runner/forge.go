package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rana1911/exploitforge/internal/trace"
)

// RunResult is the structured outcome of one forge execution. This replaces
// the old (forgeOut, trace string) pair: it carries the PARSED trace so the
// verdict engine can do provenance/mechanism checks, plus enough text for
// retry prompts when something failed.
type RunResult struct {
	Compiled    bool   // did the test file compile?
	CompileErr  string // compiler diagnostics if !Compiled
	ForgePassed bool   // did test_exploit() report [PASS]?
	ForgeReason string // revert/assertion reason if it ran but failed

	RawOutput string // trimmed human-readable output, for retry feedback
	Rendered  string // the full rendered test file (for harness-integrity check)

	TestRun       *trace.TestRun // parsed structured trace (nil if compile failed)
	TargetAddress string         // resolved target address (see resolveTarget)
	AttackerEOA   string         // attacker address, from the startPrank calldata

	InfraErr error // non-nil ONLY for infra failure (timeout, backend crash)
}

// Backend abstracts HOW forge is executed, so a local-exec backend (tested
// here) and a Docker-sandbox backend (used in production, where AI-written
// code must be isolated) are interchangeable. A backend runs one command in
// workDir and returns combined stdout+stderr; it must enforce `timeout`.
type Backend interface {
	Exec(ctx context.Context, workDir string, timeout time.Duration, name string, args ...string) (stdout string, combined string, err error)
}

// ForgeRunner renders the harness, writes it into an existing forge project,
// runs forge, and parses the result. The project at ProjectDir must already
// contain foundry.toml, lib/forge-std, and src/ with the target contracts
// (in production the ingestion stage produces this; tests build it).
//
// ISOLATION: a single ForgeRunner is NOT safe for concurrent Run calls — it
// writes a fixed TestPath and `forge test` recompiles the whole project, so
// two concurrent runs in the same ProjectDir clobber each other. Concurrency
// is the RunnerFactory's responsibility: hand each parallel task its own
// ProjectDir (a fresh copy, or a separate Docker container).
type ForgeRunner struct {
	ProjectDir string
	Config     Config
	Backend    Backend
	SolcPath   string        // passed as --use; "" lets forge resolve solc
	Timeout    time.Duration // per forge invocation
	TestPath   string        // relative path to write the test, e.g. "test/Exploit.t.sol"
	ForkTarget string        // ModeFork: the known deployed target address
}

// NewForgeRunner fills sensible defaults.
func NewForgeRunner(projectDir string, cfg Config, backend Backend) *ForgeRunner {
	return &ForgeRunner{
		ProjectDir: projectDir,
		Config:     cfg,
		Backend:    backend,
		Timeout:    90 * time.Second,
		TestPath:   "test/Exploit.t.sol",
	}
}

// Run renders modelCode into the harness, executes forge, and returns a
// fully parsed RunResult. A failing/reverting test is NOT an InfraErr — it
// is a normal result the loop feeds back to the model.
func (r *ForgeRunner) Run(ctx context.Context, modelCode string) RunResult {
	if err := r.Config.Validate(); err != nil {
		return RunResult{InfraErr: err}
	}
	file := r.Config.Render(modelCode)
	abs := filepath.Join(r.ProjectDir, r.TestPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return RunResult{Rendered: file, InfraErr: fmt.Errorf("runner: mkdir test dir: %w", err)}
	}
	if err := os.WriteFile(abs, []byte(file), 0o644); err != nil {
		return RunResult{Rendered: file, InfraErr: fmt.Errorf("runner: write test file: %w", err)}
	}

	args := []string{"test", "--match-contract", "ExploitTest", "--json", "-vvvv"}
	if r.SolcPath != "" {
		args = append(args, "--use", r.SolcPath)
	}
	stdout, combined, err := r.Backend.Exec(ctx, r.ProjectDir, r.Timeout, "forge", args...)

	// forge exits non-zero when tests fail; that's expected, not infra error.
	// We distinguish compile failure vs test failure from the output itself.
	res := RunResult{RawOutput: trimOutput(combined, 60), Rendered: file}

	if looksLikeCompileFailure(combined) {
		res.Compiled = false
		res.CompileErr = trimOutput(combined, 60)
		return res
	}
	res.Compiled = true

	// Parse the structured JSON. If forge produced no parseable JSON at all
	// (and it wasn't a compile failure), that's an infra problem.
	key := ContractKey(r.TestPath)
	tr, perr := trace.Parse([]byte(stdout), key, "test_exploit()")
	if perr != nil {
		// Some forge versions print a banner before the JSON; try to salvage
		// the JSON object from the stream.
		if js := extractJSONObject(stdout); js != "" {
			tr, perr = trace.Parse([]byte(js), key, "test_exploit()")
		}
	}
	if perr != nil {
		res.InfraErr = fmt.Errorf("runner: could not parse forge --json output: %w (exit err: %v)", perr, err)
		return res
	}

	res.TestRun = tr
	res.ForgePassed = tr.Status == "Success"
	res.ForgeReason = tr.Reason

	exec := tr.Arena("Execution")
	res.TargetAddress = r.resolveTarget(tr)
	res.AttackerEOA = firstStartPrankArg(exec)
	return res
}

// resolveTarget returns the target contract's address. In fork mode it is
// the known deployed address from config. In local-deploy mode it is
// discovered from the first CREATE in the Setup arena (the harness's
// `target = new X()`), which is how the verdict engine's address-based
// checks locate it.
func (r *ForgeRunner) resolveTarget(tr *trace.TestRun) string {
	if r.Config.Mode == ModeFork && r.ForkTarget != "" {
		return r.ForkTarget
	}
	for _, n := range tr.Arena("Setup") {
		if n.Trace.Kind == "CREATE" {
			return n.Trace.Address
		}
	}
	return ""
}

func firstStartPrankArg(exec []trace.Node) string {
	const startPrankSel = "0x06447d56" // startPrank(address)
	for _, n := range exec {
		if n.Trace.Selector() == startPrankSel {
			d := n.Trace.Data
			if len(d) >= 2+8+64 {
				argHex := d[2+8:]
				return "0x" + argHex[len(argHex)-40:]
			}
		}
	}
	return ""
}

func looksLikeCompileFailure(out string) bool {
	return strings.Contains(out, "Compiler run failed") ||
		strings.Contains(out, "Error (") ||
		strings.Contains(out, "ParserError") ||
		strings.Contains(out, "Compilation failed")
}

// extractJSONObject returns the substring from the first '{' to the last
// '}', to tolerate any non-JSON banner forge may print before the object.
func extractJSONObject(s string) string {
	i := strings.Index(s, "{")
	j := strings.LastIndex(s, "}")
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return ""
}

func trimOutput(s string, maxLines int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	head := maxLines / 2
	tail := maxLines - head
	return strings.Join(lines[:head], "\n") +
		fmt.Sprintf("\n... [%d lines omitted] ...\n", len(lines)-maxLines) +
		strings.Join(lines[len(lines)-tail:], "\n")
}

// --- Local-exec backend (testable here; NOT sandboxed) ---------------------

// LocalBackend runs forge directly on the host via os/exec. Use it for
// development and CI where the input contracts are trusted. For untrusted
// AI-written code in production, use a DockerBackend (same interface) that
// runs the same command inside a network-isolated container.
type LocalBackend struct{}

func (LocalBackend) Exec(ctx context.Context, workDir string, timeout time.Duration, name string, args ...string) (string, string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Dir = workDir

	var stdout strings.Builder
	var combined strings.Builder
	// forge prints the JSON to stdout and diagnostics to stderr; capture
	// stdout alone (for parsing) and both together (for error classification
	// and retry feedback).
	mw := &multiWriter{a: &stdout, b: &combined}
	cmd.Stdout = mw
	cmd.Stderr = &combined

	err := cmd.Run()
	if cctx.Err() == context.DeadlineExceeded {
		return stdout.String(), combined.String(), fmt.Errorf("forge timed out after %s", timeout)
	}
	return stdout.String(), combined.String(), err
}

type multiWriter struct{ a, b *strings.Builder }

func (m *multiWriter) Write(p []byte) (int, error) {
	m.a.Write(p)
	m.b.Write(p)
	return len(p), nil
}
