package orchestrator

import (
	"context"

	"github.com/rana1911/sentinelx/internal/agent"
	"github.com/rana1911/sentinelx/internal/runner"
	"github.com/rana1911/sentinelx/internal/verify"
)

// Verdict mirrors verify.Verdict at the orchestrator boundary.
type Verdict = verify.Verdict

const (
	Verified     = verify.Verified
	Rejected     = verify.Rejected
	Inconclusive = verify.Inconclusive
)

// Completer is the subset of the Spark client the loop needs. Making it an
// interface lets tests drive the whole loop with a scripted fake AI while
// the real runner executes real forge.
type Completer interface {
	Complete(ctx context.Context, msgs []agent.Message, temp float64, jsonMode bool) (string, error)
}

// Runner executes one rendered exploit and returns a fully parsed result.
// *runner.ForgeRunner satisfies this; tests can supply a fake.
type Runner interface {
	Run(ctx context.Context, modelCode string) runner.RunResult
}

// ExploitTask is one hypothesis plus the metadata the verdict engine needs
// to judge it. In production the target fields come from the ingestion
// stage; for now the caller supplies them.
type ExploitTask struct {
	Hypothesis  agent.Hypothesis
	ContractSrc string

	// Class and target info for verify.Decide.
	Class            verify.VulnClass
	TargetSignatures []string // the claimed function, all overload forms
	ClaimsProfit     bool

	// SuccessAssertion is the harness-owned invariant for this hypothesis
	// (the same string rendered into runner.Config.SuccessAssertion and into
	// TemplateRender). verify.Decide guards it; it is the class-independent
	// basis of the verdict.
	SuccessAssertion string

	// TemplateRender is the harness rendered with an EMPTY model region, for
	// the harness-integrity check (the runner renders the real file; this is
	// what it must match outside the model markers). Supply via
	// runner.Config.TemplateRender().
	TemplateRender string

	// ExpectedHarnessCalls are the cheatcodes the fixed harness itself makes
	// within test_exploit() (normally startPrank + stopPrank).
	ExpectedHarnessCalls []verify.ExpectedHarnessCall
}

// Attempt records one round of the generate -> run -> judge loop.
type Attempt struct {
	N          int
	Code       string
	Stage      string // source-cheat | compile | revert | assertion | rejected | ok
	ForgeOut   string
	Violations []string
}

// Result is the final outcome for a single hypothesis.
type Result struct {
	Hypothesis agent.Hypothesis
	Verdict    Verdict
	Attempts   []Attempt
	Reason     string
	Evidence   verify.Evidence // populated once the loop reaches the verdict engine
}
