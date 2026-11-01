// The verdict engine composes every independent check into a single,
// evidence-backed decision. A finding is VERIFIED only if ALL of these hold:
//
//  1. forge reported the test PASSED (the exploit executed and the
//     harness-owned assertion held);
//  2. harness integrity: the model edited ONLY the marked region, so the
//     assertion it passed is the real one (CheckHarnessIntegrity, run by the
//     caller before this — see VerdictInput.HarnessIntact);
//  3. no cheatcode provenance violations (CheckCheatcodeProvenance): no
//     cheatcode was reached from model code, by any route;
//  4. the claimed TARGET function was actually invoked on the target
//     contract (CheckTargetFunctionInvoked) — profit through an unrelated
//     path does not count;
//  5. the per-hypothesis SUCCESS PREDICATE is meaningful
//     (CheckSuccessPredicate): the harness-owned invariant that forge just
//     broke reads real contract/attacker state, is non-trivial, and uses no
//     cheatcodes. This is class-INDEPENDENT and replaces per-class dispatch
//     as the gate — the tool proves "an attacker broke a stated invariant",
//     not "this matches a known bug pattern";
//  6. if the claim is theft-of-funds, independent trace-derived value flow
//     shows positive net attacker profit (a gate, not a caveat).
//
// A dedicated mechanism detector (e.g. reentrancy re-entry) may add BONUS
// evidence when the advisory class has one, but never gates the verdict.
//
// Any failure of 1–6 yields REJECTED (the exploit proved nothing / cheated)
// or INCONCLUSIVE (we couldn't run or parse it). This is the difference
// between "a test passed" and "an attacker provably broke a real invariant."
package verify

import (
	"fmt"

	"github.com/rana1911/exploitforge/internal/trace"
)

type Verdict string

const (
	Verified     Verdict = "verified"
	Rejected     Verdict = "rejected"
	Inconclusive Verdict = "inconclusive"
)

// VulnClass enumerates the mechanism a hypothesis claims.
type VulnClass string

const (
	ClassReentrancy     VulnClass = "reentrancy"
	ClassAccessControl  VulnClass = "access-control"
	ClassShareInflation VulnClass = "share-inflation"
	ClassOracle         VulnClass = "oracle-manipulation"
	// ClassGeneric: no mechanism-specific check beyond target invocation +
	// the harness assertion (used for classes without a dedicated detector
	// yet; still far stronger than "assertion passed" alone).
	ClassGeneric VulnClass = "generic"
)

// VerdictInput is everything the engine needs for one hypothesis's result.
type VerdictInput struct {
	Class VulnClass

	// From the runner / forge:
	ForgePassed bool   // forge reported [PASS] for test_exploit()
	ForgeReason string // revert/assertion reason if it failed
	ParseError  error  // non-nil if --json output couldn't be parsed

	// SuccessAssertion is the harness-owned invariant the exploit had to
	// break for forge to pass. The engine guards it statically (it does not
	// re-run it) via CheckSuccessPredicate.
	SuccessAssertion string

	// Harness integrity (computed by caller via CheckHarnessIntegrity):
	HarnessIntact bool

	// Structured trace:
	ExecArena        []trace.Node
	TestContract     string   // Execution root call address
	TargetAddress    string   // the hypothesis's target contract
	TargetSignatures []string // the claimed function, all overload forms

	// Attacker EOA (for value-flow), and whether the claim is theft-of-funds.
	AttackerEOA  string
	ClaimsProfit bool

	// Legitimate harness cheatcode calls within Execution.
	ExpectedHarnessCalls []ExpectedHarnessCall
}

// Evidence records what each check found, so a report can show WHY a verdict
// was reached (every verified finding is reproducible and explained).
type Evidence struct {
	Predicate        PredicateVerdict
	CheatViolations  []CheatProvenanceViolation
	TargetInvocation TargetInvocation
	Reentrancy       ReentrancyEvidence
	ValueFlow        ValueFlow
	Notes            []string
}

// Decide runs every applicable check and returns a verdict plus evidence.
func Decide(in VerdictInput) (Verdict, Evidence) {
	var ev Evidence

	// Stage 0: could we even run/parse it?
	if in.ParseError != nil {
		ev.Notes = append(ev.Notes, "could not parse forge output: "+in.ParseError.Error())
		return Inconclusive, ev
	}
	if len(in.ExecArena) == 0 {
		ev.Notes = append(ev.Notes, "no Execution trace available")
		return Inconclusive, ev
	}

	// Stage 1: did the test actually pass?
	if !in.ForgePassed {
		ev.Notes = append(ev.Notes, "forge did not report PASS: "+in.ForgeReason)
		return Rejected, ev
	}

	// Stage 2: is the assertion it passed the REAL one?
	if !in.HarnessIntact {
		ev.Notes = append(ev.Notes, "harness integrity failed: model edited fixed harness code, so the passing assertion cannot be trusted")
		return Rejected, ev
	}

	// Stage 3: cheatcode provenance (catches inline AND obfuscated cheats).
	ev.CheatViolations = CheckCheatcodeProvenance(in.ExecArena, in.TestContract, in.ExpectedHarnessCalls)
	if len(ev.CheatViolations) > 0 {
		ev.Notes = append(ev.Notes, fmt.Sprintf("%d cheatcode provenance violation(s): the exploit used test-environment tooling, not a real attack", len(ev.CheatViolations)))
		return Rejected, ev
	}

	// Stage 4: did it actually touch the claimed target function?
	ev.TargetInvocation = CheckTargetFunctionInvoked(in.ExecArena, in.TargetAddress, in.TargetSignatures)
	if !ev.TargetInvocation.Invoked {
		ev.Notes = append(ev.Notes, "the exploit never invoked the claimed target function — a passing assertion here proves nothing about this hypothesis")
		return Rejected, ev
	}

	// Stage 5: the success predicate is meaningful. This replaces per-class
	// dispatch as the gate: regardless of what the bug is called, the exploit
	// is only proof if it BROKE a non-trivial invariant that reads real state
	// (the harness-owned assertion forge just passed). CheckSuccessPredicate
	// guards the predicate's shape; forge already executed it.
	ev.Predicate = CheckSuccessPredicate(in.SuccessAssertion)
	if !ev.Predicate.OK {
		ev.Notes = append(ev.Notes, "success predicate rejected: "+ev.Predicate.Reason)
		return Rejected, ev
	}
	ev.Notes = append(ev.Notes, "success invariant is meaningful and was broken by the exploit (forge PASS on a guarded predicate)")

	// Stage 6: if the claim is theft-of-funds, corroborate attacker profit
	// INDEPENDENTLY from the trace's value flow. For a profit claim this is a
	// gate, not a caveat: a profit assertion that passes with zero net flow is
	// not a real theft (the value moved somewhere else or not at all).
	if in.ClaimsProfit && in.AttackerEOA != "" {
		ev.ValueFlow = ComputeAttackerValueFlow(in.ExecArena, in.AttackerEOA)
		if ev.ValueFlow.NetWei == 0 {
			ev.Notes = append(ev.Notes, "hypothesis claims attacker profit, but independent trace-derived net value flow is not positive — the profit assertion is not corroborated")
			return Rejected, ev
		}
		ev.Notes = append(ev.Notes, fmt.Sprintf("independent value-flow corroboration: attacker cluster netted %d wei", ev.ValueFlow.NetWei))
	}

	// Bonus evidence (never gating): if the hypothesis is labelled reentrancy
	// and the target was genuinely re-entered, say so. Absence is only a note
	// — the verdict already stands on the guarded predicate + corroboration,
	// so we neither require nor trust the class label.
	if in.Class == ClassReentrancy {
		ev.Reentrancy = CheckReentrancy(in.ExecArena, in.TargetAddress)
		if ev.Reentrancy.Occurred {
			ev.Notes = append(ev.Notes, fmt.Sprintf("mechanism detail: confirmed re-entry — node #%d is a call into the target nested inside still-open node #%d", ev.Reentrancy.InnerNodeIdx, ev.Reentrancy.OuterNodeIdx))
		} else {
			ev.Notes = append(ev.Notes, "mechanism detail: labelled reentrancy, but no nested re-entry observed (the invariant was still broken by some means)")
		}
	}

	return Verified, ev
}
