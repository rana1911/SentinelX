// Package orchestrator drives one hypothesis through:
// generate exploit -> source pre-filter -> run in sandbox -> verdict engine,
// feeding every failure back to Spark for up to MaxAttempts retries. The
// final verdict comes from verify.Decide on the STRUCTURED trace, not from
// text matching.
package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"github.com/rana1911/exploitforge/internal/agent"
	"github.com/rana1911/exploitforge/internal/runner"
	"github.com/rana1911/exploitforge/internal/verify"
)

const MaxAttemptsDefault = 5

type Loop struct {
	Spark       Completer
	Runner      Runner
	MaxAttempts int
}

func New(spark Completer, r Runner) *Loop {
	return &Loop{Spark: spark, Runner: r, MaxAttempts: MaxAttemptsDefault}
}

// Execute runs the generate/run/judge loop for a single hypothesis.
func (l *Loop) Execute(ctx context.Context, task ExploitTask) Result {
	res := Result{Hypothesis: task.Hypothesis}

	// Guard the success predicate up front: it is harness-owned (from the
	// hypothesize stage), so the exploit author cannot fix a hollow one —
	// retrying would only burn attempts. A bad invariant means this
	// hypothesis cannot be proven, full stop.
	if task.SuccessAssertion != "" {
		if pv := verify.CheckSuccessPredicate(task.SuccessAssertion); !pv.OK {
			res.Verdict = Rejected
			res.Reason = "unprovable hypothesis: " + pv.Reason
			res.Evidence = verify.Evidence{Predicate: pv, Notes: []string{"success predicate rejected before execution: " + pv.Reason}}
			return res
		}
	}

	msgs := []agent.Message{
		{Role: "system", Content: exploitSystemPrompt},
		{Role: "user", Content: buildExploitUserPrompt(task.Hypothesis, task.ContractSrc)},
	}

	for n := 1; n <= l.MaxAttempts; n++ {
		raw, err := l.Spark.Complete(ctx, msgs, 0.2, false)
		if err != nil {
			res.Verdict = Inconclusive
			res.Reason = fmt.Sprintf("spark call failed on attempt %d: %v", n, err)
			return res
		}
		// Models write helper contracts as ordinary top-level Solidity; the
		// harness needs them in its own shape. Normalize first so every
		// later stage sees exactly what forge will compile.
		norm := runner.NormalizeModelCode(agent.ExtractCode(raw))
		code := norm.Code
		att := Attempt{N: n, Code: code}

		// Stage A: cheap source pre-filter. Catches blatant cheats before
		// spending a forge run. NOT trusted as proof — the trace-based
		// provenance check in verify.Decide is the real guarantee — but it
		// saves a compile+run on obvious cases. CheckMemberShadowing closes a
		// hole the trace cannot see: an ExploitTest member that overrides an
		// inherited forge-std assertion, which would neutralize the
		// harness-owned success check without editing any harness bytes.
		v := append(verify.CheckSource(code), verify.CheckMemberShadowing(norm.Members)...)
		if len(v) > 0 {
			att.Stage = "source-cheat"
			att.Violations = v
			res.Attempts = append(res.Attempts, att)
			msgs = l.retry(msgs, raw, cheatRetryPrompt(v))
			continue
		}

		// Stage B: render + run REAL forge (in a sandbox, in production).
		rr := l.Runner.Run(ctx, code)
		if rr.InfraErr != nil {
			res.Verdict = Inconclusive
			res.Reason = fmt.Sprintf("runner infra error on attempt %d: %v", n, rr.InfraErr)
			res.Attempts = append(res.Attempts, att)
			return res
		}
		att.ForgeOut = rr.RawOutput

		// Stage C: compile failure -> feed the diagnostics back.
		if !rr.Compiled {
			att.Stage = "compile"
			res.Attempts = append(res.Attempts, att)
			msgs = l.retry(msgs, raw, retryPrompt(n, l.MaxAttempts, "compile", rr.CompileErr))
			continue
		}

		// Stage D: harness integrity — the model may only have edited the
		// marked region. If it tampered with setUp/assertion, nothing below
		// can be trusted, so reject-and-retry.
		if err := verify.CheckHarnessIntegrity(rr.Rendered, task.TemplateRender); err != nil {
			att.Stage = "rejected"
			att.Violations = []string{err.Error()}
			res.Attempts = append(res.Attempts, att)
			msgs = l.retry(msgs, raw, harnessTamperRetryPrompt(err))
			continue
		}

		// Stage E: did the test even run to a pass? If it reverted or the
		// assertion failed, feed that back.
		if !rr.ForgePassed {
			att.Stage = "revert/assertion"
			res.Attempts = append(res.Attempts, att)
			reason := rr.ForgeReason
			if reason == "" {
				reason = rr.RawOutput
			}
			msgs = l.retry(msgs, raw, retryPrompt(n, l.MaxAttempts, "revert/assertion", reason))
			continue
		}

		// Stage F: the verdict engine on the STRUCTURED trace. This is the
		// real decision: cheatcode provenance, target invocation, mechanism,
		// value flow — not "the text said PASS".
		exec := rr.TestRun.Arena("Execution")
		in := verify.VerdictInput{
			Class:                task.Class,
			ForgePassed:          true,
			HarnessIntact:        true,
			SuccessAssertion:     task.SuccessAssertion,
			ExecArena:            exec,
			TestContract:         verify.RootCallAddress(exec),
			TargetAddress:        rr.TargetAddress,
			TargetSignatures:     task.TargetSignatures,
			AttackerEOA:          rr.AttackerEOA,
			ClaimsProfit:         task.ClaimsProfit,
			ExpectedHarnessCalls: task.ExpectedHarnessCalls,
		}
		verdict, ev := verify.Decide(in)
		res.Evidence = ev

		switch verdict {
		case verify.Verified:
			att.Stage = "ok"
			res.Attempts = append(res.Attempts, att)
			res.Verdict = verify.Verified
			res.Reason = fmt.Sprintf("exploit verified in %d attempt(s)", n)
			return res
		case verify.Inconclusive:
			att.Stage = "rejected"
			res.Attempts = append(res.Attempts, att)
			res.Verdict = verify.Inconclusive
			res.Reason = strings.Join(ev.Notes, "; ")
			return res
		default: // Rejected: the exploit ran but proved nothing / cheated.
			att.Stage = "rejected"
			att.Violations = ev.Notes
			res.Attempts = append(res.Attempts, att)
			msgs = l.retry(msgs, raw, verdictRetryPrompt(ev))
			continue
		}
	}

	res.Verdict = verify.Rejected
	if res.Reason == "" {
		res.Reason = fmt.Sprintf("no verified exploit after %d attempts", l.MaxAttempts)
	}
	return res
}

func (l *Loop) retry(msgs []agent.Message, assistantRaw, userPrompt string) []agent.Message {
	return append(msgs,
		agent.Message{Role: "assistant", Content: assistantRaw},
		agent.Message{Role: "user", Content: userPrompt},
	)
}

func cheatRetryPrompt(violations []string) string {
	var b strings.Builder
	b.WriteString("Your code was rejected by the source cheat guard, before running. Issues:\n")
	for _, v := range violations {
		b.WriteString("- " + v + "\n")
	}
	b.WriteString("Rewrite attack() using ONLY normal external/public contract calls an unprivileged EOA could make. No cheatcodes, no forge-std Test/Script, no calls to the cheatcode address.")
	return b.String()
}

func harnessTamperRetryPrompt(err error) string {
	return "Your code modified the fixed test harness, which is not allowed: " + err.Error() +
		"\nWrite ONLY the body of attack() and any helper contracts, strictly between the markers. Do not redeclare setUp, the assertion, or close the test contract early."
}

func verdictRetryPrompt(ev verify.Evidence) string {
	var b strings.Builder
	b.WriteString("Your exploit ran and the test passed, but it does NOT demonstrate the claimed vulnerability. Reasons:\n")
	for _, note := range ev.Notes {
		b.WriteString("- " + note + "\n")
	}
	b.WriteString("Write a real exploit that actually calls the claimed target function and demonstrates the specific vulnerability class, using no test-environment cheatcodes.")
	return b.String()
}

func retryPrompt(n, max int, stage, detail string) string {
	return fmt.Sprintf(
		"Attempt %d of %d failed.\nStage: %s\nDetail (trimmed):\n%s\n\nFix the code. Keep the overall strategy unless this shows it's impossible; then try the closest viable variant.",
		n, max, stage, verify.TrimOutput(detail, 40),
	)
}

const exploitSystemPrompt = `You are a smart-contract security engineer writing a Foundry proof-of-concept test for an authorized audit. Given a contract and a suspected bug, you write the attack() function (plus any helper contracts) that a verification layer then runs to confirm whether the bug is real. A proof only counts if it uses moves a real unprivileged attacker could make on the live chain — test-only shortcuts would prove nothing about the deployed contract, so they are rejected.

The fixed harness you plug into looks like this (you never see or edit it):

    contract ExploitTest is Test {
        address internal attacker;                 // unprivileged EOA, pre-funded
        <target declaration>;
        function setUp() public { <deploys/funds the target>; }
        function test_exploit() public {
            vm.startPrank(attacker);
            attack();                              // <-- YOUR code runs here, as the attacker
            vm.stopPrank();
            <harness-owned SUCCESS INVARIANT>;     // fixed; you cannot change it
        }
        // MODEL_BEGIN
        <-- your output goes here -->
        // MODEL_END
    }

Your goal: make attack() BREAK the success invariant shown below. That assertion is fixed by the harness — your job is to drive the contract into the state it describes, using only what a real attacker could do. You cannot weaken or edit it.

Rules:
- Write attack() and, if you need them, helper contracts (e.g. a malicious receiver for reentrancy).
- You act only as the attacker EOA, through public/external calls on the target. No cheatcodes or test tooling of any kind: nothing from vm.* / hevm, no inheriting forge-std Test/Script, no deal/etch/store/mockCall/prank, no calls to the cheatcode address, no inline assembly that writes state. These are stripped by a real attacker's reality, so a PoC that relies on them is treated as a non-proof.
- Do not redefine or override any inherited function (assertions included) and do not add other test_*/setUp members.
- attack() must actually call the target function named in the hypothesis, and must end with the success invariant holding (i.e. the vulnerability actually exploited), achieved by a genuine attack path — not by any shortcut.

Output format: ONE solidity code block, no prose. Put attack() (and any other ExploitTest members) first; then write each helper contract as a normal top-level contract. Do NOT add pragma, imports, or SPDX lines — the harness provides them.`

func buildExploitUserPrompt(h agent.Hypothesis, contractSrc string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Hypothesis:\n- class: %s\n- contract: %s\n- function: %s\n- steps: %s\n- preconditions: %s\n- success metric: %s\n",
		h.Class, h.Contract, h.Function, strings.Join(h.AttackSteps, "; "), strings.Join(h.Preconditions, "; "), h.SuccessMetric)
	if h.SuccessAssertion != "" {
		fmt.Fprintf(&b, "- success invariant your attack must break (fixed in the harness): %s\n", h.SuccessAssertion)
	}
	b.WriteString("\n")
	b.WriteString("Relevant contract source:\n```solidity\n")
	b.WriteString(contractSrc)
	b.WriteString("\n```\n")
	return b.String()
}

// compile-time assertion that the real client satisfies Completer.
var _ Completer = (*agent.Client)(nil)

// compile-time assertion that the real runner satisfies Runner.
var _ Runner = (*runner.ForgeRunner)(nil)
