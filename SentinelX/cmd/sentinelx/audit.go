package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/rana1911/sentinelx/internal/agent"
	"github.com/rana1911/sentinelx/internal/hypothesize"
	"github.com/rana1911/sentinelx/internal/ingest"
	"github.com/rana1911/sentinelx/internal/orchestrator"
	"github.com/rana1911/sentinelx/internal/report"
	"github.com/rana1911/sentinelx/internal/runner"
	"github.com/rana1911/sentinelx/internal/verify"
)

// AuditSpec describes a whole-contract audit: the shared forge-project and
// harness setup (identical across every hypothesis), plus the contract to
// read. The per-hypothesis details (class, target function, attack steps)
// are produced by the hypothesize stage, not written here. Ingestion (#3)
// will eventually generate this from a repo; for now it is hand-written
// once per target instead of once per hypothesis.
type AuditSpec struct {
	Mode             string `json:"mode"`              // "local-deploy" or "fork"
	Imports          string `json:"imports"`           // e.g. import "../src/VulnerableVault.sol";
	TargetDecl       string `json:"target_decl"`       // e.g. VulnerableVault internal target;
	TargetSetup      string `json:"target_setup"`      // setUp() body that deploys+seeds the target
	StartBalanceWei  string `json:"start_balance_wei"` // attacker's starting ETH, Solidity literal
	SuccessAssertion string `json:"success_assertion"` // the one harness-owned assertion line
	ForkTarget       string `json:"fork_target"`       // fork mode: deployed target address
	ClaimsProfit     bool   `json:"claims_profit"`     // whether to run value-flow corroboration

	Contract        string `json:"contract"`          // primary contract name
	ContractSrc     string `json:"contract_src"`      // source shown to the model...
	ContractSrcFile string `json:"contract_src_file"` // ...or a path to read it from
}

func (a *AuditSpec) config() (runner.Config, runner.Mode, error) {
	mode := runner.ModeLocalDeploy
	if a.Mode == "fork" {
		mode = runner.ModeFork
	}
	cfg := runner.Config{
		Mode:             mode,
		Imports:          a.Imports,
		TargetDecl:       a.TargetDecl,
		TargetSetup:      a.TargetSetup,
		StartBalanceWei:  a.StartBalanceWei,
		SuccessAssertion: a.SuccessAssertion,
	}
	return cfg, mode, cfg.Validate()
}

func loadAuditSpec(path, projectDir string) (*AuditSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit spec: %w", err)
	}
	var a AuditSpec
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("parse audit spec JSON: %w", err)
	}
	if a.ContractSrc == "" && a.ContractSrcFile != "" {
		src := a.ContractSrcFile
		if !filepath.IsAbs(src) {
			src = filepath.Join(projectDir, src)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("read contract_src_file: %w", err)
		}
		a.ContractSrc = string(b)
	}
	if a.Contract == "" {
		return nil, fmt.Errorf("audit spec: contract name is required")
	}
	if a.ContractSrc == "" {
		return nil, fmt.Errorf("audit spec: contract_src or contract_src_file is required")
	}
	return &a, nil
}

// cfgFor derives the per-hypothesis runner config: identical to the shared
// base except the success assertion, which is the hypothesis's own invariant
// (the spec's assertion is only a fallback). Both the real render and the
// integrity template render must use this exact config.
func (a *AuditSpec) cfgFor(base runner.Config, h agent.Hypothesis) runner.Config {
	c := base
	if strings.TrimSpace(h.SuccessAssertion) != "" {
		c.SuccessAssertion = h.SuccessAssertion
	}
	return c
}

// taskFor builds one ExploitTask from the base config and one hypothesis.
func (a *AuditSpec) taskFor(base runner.Config, h agent.Hypothesis) orchestrator.ExploitTask {
	cfg := a.cfgFor(base, h)
	return orchestrator.ExploitTask{
		Hypothesis:       h,
		ContractSrc:      a.ContractSrc,
		Class:            vulnClass(h.Class),
		TargetSignatures: []string{h.TargetSignature},
		ClaimsProfit:     h.ClaimsProfit,
		SuccessAssertion: cfg.SuccessAssertion,
		TemplateRender:   cfg.TemplateRender(),
		ExpectedHarnessCalls: []verify.ExpectedHarnessCall{
			{Signature: "startPrank(address)", Count: 1},
			{Signature: "stopPrank()", Count: 1},
		},
	}
}

// runAudit is the full pipeline: hypothesize over the contract, prove each
// hypothesis in its own isolated forge project (concurrently), then render a
// report. opts carries the resolved flags.
func runAudit(opts auditOpts) int {
	var spec *AuditSpec
	var err error
	if opts.autoIngest {
		spec, err = ingestSpec(opts.projectDir, opts.contract, opts.solc, opts.timeout)
	} else {
		spec, err = loadAuditSpec(opts.specPath, opts.projectDir)
	}
	if err != nil {
		fail(err)
	}
	cfg, mode, err := spec.config()
	if err != nil {
		fail(err)
	}

	client, err := agent.NewFromEnv()
	if err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "sentinelx: provider=%s model=%s auditing %s\n", client.Provider, client.Model, spec.Contract)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Stage 1: hypothesize.
	hyp := hypothesize.New(client)
	hyp.Max = opts.maxHypotheses
	hs, err := hyp.Propose(ctx, spec.Contract, spec.ContractSrc)
	if err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "sentinelx: %d hypothesis(es) to prove\n", len(hs))
	if len(hs) == 0 {
		fmt.Fprintln(os.Stderr, "sentinelx: no hypotheses — nothing to prove")
	}

	// Stage 2: prove each, concurrently, each in its own project copy so
	// parallel forge runs never clobber a shared test file.
	tasks := make([]orchestrator.ExploitTask, len(hs))
	for i, h := range hs {
		tasks[i] = spec.taskFor(cfg, h)
	}

	var cleanup []string
	defer func() {
		for _, d := range cleanup {
			os.RemoveAll(d)
		}
	}()
	factory := func(task orchestrator.ExploitTask) orchestrator.Runner {
		dir, err := freshProjectCopy(opts.projectDir)
		if err != nil {
			fail(fmt.Errorf("isolate project: %w", err))
		}
		cleanup = append(cleanup, dir)
		// Each task runs with its OWN success invariant rendered into the
		// harness; the exploit author still cannot edit it.
		r := runner.NewForgeRunner(dir, spec.cfgFor(cfg, task.Hypothesis), runner.LocalBackend{})
		r.SolcPath = opts.solc
		r.Timeout = opts.timeout
		if mode == runner.ModeFork {
			r.ForkTarget = spec.ForkTarget
		}
		return r
	}

	results := orchestrator.RunAllWith(ctx, client, factory, tasks, opts.concurrency, opts.maxAttempts)

	// Stage 3: report.
	s := report.Summarize(spec.Contract, results)
	fmt.Fprintf(os.Stderr, "sentinelx: %d verified, %d rejected, %d inconclusive\n", s.Verified, s.Rejected, s.Inconclusive)

	out := os.Stdout
	if opts.reportPath != "" {
		f, err := os.Create(opts.reportPath)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		out = f
	}
	report.Markdown(out, spec.Contract, results)
	if opts.reportPath != "" {
		fmt.Fprintf(os.Stderr, "sentinelx: report written to %s\n", opts.reportPath)
	}

	if s.Verified == 0 {
		return 1
	}
	return 0
}

type auditOpts struct {
	specPath      string
	projectDir    string
	autoIngest    bool   // generate the spec via ingestion instead of reading specPath
	contract      string // optional contract name for ingestion
	solc          string
	reportPath    string
	maxHypotheses int
	maxAttempts   int
	concurrency   int
	timeout       time.Duration
}

// ingestSpec builds the project and synthesizes an AuditSpec from its
// contract, printing the assumptions it had to make to stderr.
func ingestSpec(projectDir, contract, solc string, timeout time.Duration) (*AuditSpec, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	tgt, err := ingest.Inspect(ctx, projectDir, contract, solc, runner.LocalBackend{}, timeout)
	if err != nil {
		return nil, err
	}
	gen := ingest.Synthesize(tgt, ingest.SynthOptions{})
	for _, n := range gen.Notes {
		fmt.Fprintf(os.Stderr, "sentinelx: ingest note: %s\n", n)
	}
	return &AuditSpec{
		Mode:             gen.Mode,
		Imports:          gen.Imports,
		TargetDecl:       gen.TargetDecl,
		TargetSetup:      gen.TargetSetup,
		StartBalanceWei:  gen.StartBalanceWei,
		SuccessAssertion: gen.SuccessAssertion,
		ClaimsProfit:     gen.ClaimsProfit,
		Contract:         gen.Contract,
		ContractSrc:      tgt.Source,
		ContractSrcFile:  gen.ContractSrcFile,
	}, nil
}

// runIngest generates a spec and prints it as JSON (for review / editing).
func runIngest(projectDir, contract, solc string, timeout time.Duration) {
	spec, err := ingestSpec(projectDir, contract, solc, timeout)
	if err != nil {
		fail(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(spec)
}

// freshProjectCopy makes an isolated copy of a forge project: foundry.toml
// and src/ are copied, lib/ is symlinked (it is large and read-only), so a
// per-task runner can write its own test/Exploit.t.sol without racing other
// tasks. Mirrors the isolation the test suite uses.
func freshProjectCopy(base string) (string, error) {
	dst, err := os.MkdirTemp("", "sentinelx-proj-")
	if err != nil {
		return "", err
	}
	if b, err := os.ReadFile(filepath.Join(base, "foundry.toml")); err == nil {
		if err := os.WriteFile(filepath.Join(dst, "foundry.toml"), b, 0o644); err != nil {
			return "", err
		}
	}
	if out, err := exec.Command("cp", "-r", filepath.Join(base, "src"), filepath.Join(dst, "src")).CombinedOutput(); err != nil {
		return "", fmt.Errorf("copy src: %v: %s", err, out)
	}
	if err := os.Symlink(filepath.Join(base, "lib"), filepath.Join(dst, "lib")); err != nil {
		return "", fmt.Errorf("symlink lib: %w", err)
	}
	return dst, nil
}

const exampleAudit = `{
  "mode": "local-deploy",
  "imports": "import \"../src/VulnerableVault.sol\";",
  "target_decl": "VulnerableVault internal target;",
  "target_setup": "target = new VulnerableVault();\n        vm.deal(address(0xBEEF), 10 ether);\n        vm.prank(address(0xBEEF));\n        target.deposit{value: 10 ether}();",
  "start_balance_wei": "1 ether",
  "success_assertion": "assertGt(attacker.balance, preAttackerBalance, \"no profit\");",
  "claims_profit": true,
  "contract": "VulnerableVault",
  "contract_src_file": "src/VulnerableVault.sol"
}`
