// Package pipeline is the reusable audit core: given a prepared Foundry
// project and a model client, it ingests the contract, hypothesizes
// vulnerabilities, proves each in an isolated forge sandbox, and produces a
// report — emitting Progress events along the way. Both the CLI and the HTTP
// server drive it, so the "what an audit does" logic lives here, not in a
// main package.
package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/rana1911/sentinelx/internal/agent"
	"github.com/rana1911/sentinelx/internal/hypothesize"
	"github.com/rana1911/sentinelx/internal/ingest"
	"github.com/rana1911/sentinelx/internal/orchestrator"
	"github.com/rana1911/sentinelx/internal/report"
	"github.com/rana1911/sentinelx/internal/runner"
	"github.com/rana1911/sentinelx/internal/verify"
)

// Spec is the harness/runner configuration plus the contract to read. It is
// produced by ingestion or supplied directly.
type Spec struct {
	Mode             string
	Imports          string
	TargetDecl       string
	TargetSetup      string
	StartBalanceWei  string
	SuccessAssertion string
	ForkTarget       string
	ClaimsProfit     bool
	Contract         string
	ContractSrc      string
}

// Options tunes an audit run.
type Options struct {
	ProjectDir    string
	Solc          string
	MaxHypotheses int
	MaxAttempts   int
	Concurrency   int
	Timeout       time.Duration
}

func (o Options) withDefaults() Options {
	if o.MaxHypotheses <= 0 {
		o.MaxHypotheses = hypothesize.DefaultMax
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = orchestrator.MaxAttemptsDefault
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 3
	}
	if o.Timeout == 0 {
		o.Timeout = 90 * time.Second
	}
	return o
}

// Event is one progress update. Report is populated only on the final "done".
type Event struct {
	Stage        string             `json:"stage"` // ingest|hypothesize|prove|verdict|report|done|error|note
	Message      string             `json:"message"`
	HypothesisID string             `json:"hypothesisId,omitempty"`
	Verdict      string             `json:"verdict,omitempty"`
	Report       *report.JSONReport `json:"report,omitempty"`
}

// Progress receives events; nil is tolerated.
type Progress func(Event)

func (p Progress) emit(e Event) {
	if p != nil {
		p(e)
	}
}

// Ingest builds the project and synthesizes a Spec from its target contract.
func Ingest(ctx context.Context, opts Options, contract string, progress Progress) (*Spec, error) {
	opts = opts.withDefaults()
	progress.emit(Event{Stage: "ingest", Message: "compiling project and reading ABI"})
	tgt, err := ingest.Inspect(ctx, opts.ProjectDir, contract, opts.Solc, runner.LocalBackend{}, opts.Timeout)
	if err != nil {
		return nil, err
	}
	gen := ingest.Synthesize(tgt, ingest.SynthOptions{})
	for _, n := range gen.Notes {
		progress.emit(Event{Stage: "note", Message: n})
	}
	progress.emit(Event{Stage: "ingest", Message: "target contract: " + tgt.Contract})
	return &Spec{
		Mode:             gen.Mode,
		Imports:          gen.Imports,
		TargetDecl:       gen.TargetDecl,
		TargetSetup:      gen.TargetSetup,
		StartBalanceWei:  gen.StartBalanceWei,
		SuccessAssertion: gen.SuccessAssertion,
		ClaimsProfit:     gen.ClaimsProfit,
		Contract:         gen.Contract,
		ContractSrc:      tgt.Source,
	}, nil
}

// Run hypothesizes over the spec's contract, proves each hypothesis in its
// own isolated forge project (concurrently), and returns the results plus a
// UI-facing JSON report.
func Run(ctx context.Context, client *agent.Client, spec *Spec, opts Options, progress Progress) ([]orchestrator.Result, report.JSONReport, error) {
	opts = opts.withDefaults()
	cfg, mode, err := spec.config()
	if err != nil {
		return nil, report.JSONReport{}, err
	}

	// Stage 1: hypothesize.
	progress.emit(Event{Stage: "hypothesize", Message: "asking the model for vulnerability hypotheses"})
	hyp := hypothesize.New(client)
	hyp.Max = opts.MaxHypotheses
	hs, err := hyp.Propose(ctx, spec.Contract, spec.ContractSrc)
	if err != nil {
		return nil, report.JSONReport{}, fmt.Errorf("hypothesize: %w", err)
	}
	progress.emit(Event{Stage: "hypothesize", Message: fmt.Sprintf("%d hypothesis(es) to prove", len(hs))})

	// Stage 2: prove each concurrently, each in its own project copy.
	tasks := make([]orchestrator.ExploitTask, len(hs))
	for i, h := range hs {
		tasks[i] = spec.taskFor(cfg, h)
		progress.emit(Event{Stage: "prove", HypothesisID: h.ID, Message: fmt.Sprintf("%s: %s in %s.%s", h.ID, h.Class, h.Contract, h.Function)})
	}

	var cleanup []string
	defer func() {
		for _, d := range cleanup {
			os.RemoveAll(d)
		}
	}()
	var mu sync.Mutex
	factory := func(task orchestrator.ExploitTask) orchestrator.Runner {
		dir, err := freshProjectCopy(opts.ProjectDir)
		if err != nil {
			// surfaced later as an infra error on the result
			return failingRunner{err}
		}
		mu.Lock()
		cleanup = append(cleanup, dir)
		mu.Unlock()
		r := runner.NewForgeRunner(dir, spec.cfgFor(cfg, task.Hypothesis), runner.LocalBackend{})
		r.SolcPath = opts.Solc
		r.Timeout = opts.Timeout
		if mode == runner.ModeFork {
			r.ForkTarget = spec.ForkTarget
		}
		return r
	}

	results := runWithProgress(ctx, client, factory, tasks, opts.Concurrency, opts.MaxAttempts, progress)

	// Stage 3: report.
	jr := report.BuildJSON(spec.Contract, string(client.Provider), client.Model, results)
	progress.emit(Event{Stage: "report", Message: fmt.Sprintf("%d verified, %d rejected, %d inconclusive", jr.Summary.Verified, jr.Summary.Rejected, jr.Summary.Inconclusive)})
	return results, jr, nil
}

// runWithProgress mirrors orchestrator.RunAllWith but emits a verdict event as
// each hypothesis finishes, so the UI can update live.
func runWithProgress(ctx context.Context, client *agent.Client, factory orchestrator.RunnerFactory, tasks []orchestrator.ExploitTask, concurrency, maxAttempts int, progress Progress) []orchestrator.Result {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	results := make([]orchestrator.Result, len(tasks))
	var wg sync.WaitGroup
	for i, task := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, task orchestrator.ExploitTask) {
			defer wg.Done()
			defer func() { <-sem }()
			loop := orchestrator.New(client, factory(task))
			loop.MaxAttempts = maxAttempts
			res := loop.Execute(ctx, task)
			results[i] = res
			progress.emit(Event{Stage: "verdict", HypothesisID: task.Hypothesis.ID, Verdict: string(res.Verdict), Message: fmt.Sprintf("%s: %s", task.Hypothesis.ID, res.Verdict)})
		}(i, task)
	}
	wg.Wait()
	return results
}

// --- Spec -> runner config / tasks (moved here from the CLI) ---------------

func (s *Spec) config() (runner.Config, runner.Mode, error) {
	mode := runner.ModeLocalDeploy
	if s.Mode == "fork" {
		mode = runner.ModeFork
	}
	cfg := runner.Config{
		Mode:             mode,
		Imports:          s.Imports,
		TargetDecl:       s.TargetDecl,
		TargetSetup:      s.TargetSetup,
		StartBalanceWei:  s.StartBalanceWei,
		SuccessAssertion: s.SuccessAssertion,
	}
	return cfg, mode, cfg.Validate()
}

func (s *Spec) cfgFor(base runner.Config, h agent.Hypothesis) runner.Config {
	c := base
	if h.SuccessAssertion != "" {
		c.SuccessAssertion = h.SuccessAssertion
	}
	return c
}

func (s *Spec) taskFor(base runner.Config, h agent.Hypothesis) orchestrator.ExploitTask {
	cfg := s.cfgFor(base, h)
	return orchestrator.ExploitTask{
		Hypothesis:       h,
		ContractSrc:      s.ContractSrc,
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

func vulnClass(s string) verify.VulnClass {
	switch verify.VulnClass(s) {
	case verify.ClassReentrancy, verify.ClassAccessControl, verify.ClassShareInflation, verify.ClassOracle:
		return verify.VulnClass(s)
	default:
		return verify.ClassGeneric
	}
}

// freshProjectCopy makes an isolated copy of a forge project (foundry.toml +
// src copied, lib symlinked) so per-task runners never race on test files.
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

// failingRunner reports an infra error for a task whose sandbox couldn't be
// created, so one bad copy doesn't crash the whole audit.
type failingRunner struct{ err error }

func (f failingRunner) Run(_ context.Context, _ string) runner.RunResult {
	return runner.RunResult{InfraErr: f.err}
}
