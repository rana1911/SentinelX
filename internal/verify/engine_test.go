package verify

import (
	"strings"
	"testing"
)

// buildInput loads a fixture and assembles a VerdictInput as the orchestrator
// would, assuming forge reported PASS and harness integrity held (the cases
// where it didn't are tested separately). The four fixtures all PASSED in
// forge — the whole point is that a passing forge test is NOT sufficient.
func buildInput(t *testing.T, fixture, contractKey string, class VulnClass) VerdictInput {
	t.Helper()
	exec, testAddr := execArenaFromFixture(t, fixture, contractKey)
	vault := setupVaultAddr(t, fixture, contractKey)
	return VerdictInput{
		Class:                class,
		ForgePassed:          true, // all four fixtures passed in forge
		HarnessIntact:        true,
		SuccessAssertion:     `assertGt(attacker.balance, preAttackerBalance, "no profit");`,
		ExecArena:            exec,
		TestContract:         testAddr,
		TargetAddress:        vault,
		TargetSignatures:     []string{"withdraw()", "deposit()"},
		AttackerEOA:          firstStartPrankArg(exec),
		ClaimsProfit:         true,
		ExpectedHarnessCalls: harnessExecCalls,
	}
}

func TestDecide_HonestReentrancyVerified(t *testing.T) {
	in := buildInput(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest", ClassReentrancy)
	v, ev := Decide(in)
	if v != Verified {
		t.Fatalf("honest reentrancy should be VERIFIED, got %s: %v", v, ev.Notes)
	}
	if !ev.Reentrancy.Occurred {
		t.Fatal("expected reentrancy evidence")
	}
	if ev.ValueFlow.NetWei == 0 {
		t.Fatal("expected positive value-flow corroboration")
	}
}

func TestDecide_InlineCheatRejected(t *testing.T) {
	in := buildInput(t, "cheat_inline.json", "test/CheatInline.t.sol:CheatInlineTest", ClassReentrancy)
	v, ev := Decide(in)
	if v != Rejected {
		t.Fatalf("inline cheat should be REJECTED, got %s", v)
	}
	if len(ev.CheatViolations) == 0 {
		t.Fatalf("expected cheat violations in evidence, notes: %v", ev.Notes)
	}
}

func TestDecide_ObfuscatedCheatRejected(t *testing.T) {
	// The headline case: forge PASSED, source scan sees nothing, yet the
	// verdict is REJECTED because the trace shows a cheatcode call from
	// model-deployed code.
	in := buildInput(t, "cheat_helper_obfuscated.json", "test/CheatHelper.t.sol:CheatHelperTest", ClassReentrancy)
	v, ev := Decide(in)
	if v != Rejected {
		t.Fatalf("obfuscated cheat should be REJECTED, got %s: %v", v, ev.Notes)
	}
	if len(ev.CheatViolations) == 0 {
		t.Fatal("expected cheat violations for obfuscated case")
	}
}

func TestDecide_VacuousExploitRejected(t *testing.T) {
	// forge PASSED, no cheatcodes at all, yet REJECTED because the target
	// function was never invoked (gaps #4/#5).
	in := buildInput(t, "vacuous_exploit.json", "test/VacuousExploit.t.sol:VacuousExploitTest", ClassReentrancy)
	v, ev := Decide(in)
	if v != Rejected {
		t.Fatalf("vacuous exploit should be REJECTED, got %s: %v", v, ev.Notes)
	}
	if ev.TargetInvocation.Invoked {
		t.Fatal("target should NOT have been invoked in vacuous case")
	}
	joined := strings.Join(ev.Notes, " ")
	if !strings.Contains(joined, "never invoked the claimed target") {
		t.Fatalf("expected target-invocation rejection note, got: %v", ev.Notes)
	}
}

func TestDecide_HonestButWrongClassRejected(t *testing.T) {
	// Sanity: the honest reentrancy trace, if a hypothesis CLAIMED it as
	// access-control, still verifies (target hit + assertion), but if we
	// demand reentrancy mechanism on the vacuous trace it fails. Here we
	// check that claiming reentrancy on something that never re-entered the
	// target is rejected even when nothing else is wrong — covered by the
	// vacuous case above; this adds the forge-failed path.
	in := buildInput(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest", ClassReentrancy)
	in.ForgePassed = false
	in.ForgeReason = "EvmError: Revert"
	v, _ := Decide(in)
	if v != Rejected {
		t.Fatalf("forge-failed exploit should be REJECTED, got %s", v)
	}
}

func TestDecide_ParseErrorInconclusive(t *testing.T) {
	in := buildInput(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest", ClassReentrancy)
	in.ParseError = errForTest("docker timed out")
	v, _ := Decide(in)
	if v != Inconclusive {
		t.Fatalf("parse/infra error should be INCONCLUSIVE, got %s", v)
	}
}

type errForTest string

func (e errForTest) Error() string { return string(e) }

func TestDecide_HollowPredicateRejected(t *testing.T) {
	// The honest reentrancy trace (a genuine exploit) must still be REJECTED
	// if the success invariant is hollow — a passing-but-meaningless assertion
	// is not proof. This is the class-independent gate.
	in := buildInput(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest", ClassReentrancy)
	in.SuccessAssertion = "assertTrue(true);"
	v, ev := Decide(in)
	if v != Rejected {
		t.Fatalf("hollow predicate should be REJECTED, got %s: %v", v, ev.Notes)
	}
	if ev.Predicate.OK {
		t.Fatal("predicate verdict should be not-OK")
	}
}

func TestDecide_VerifiesNonReentrancyClassOnPredicate(t *testing.T) {
	// Class-independence: the same honest trace, labelled access-control
	// (which has NO dedicated detector), still verifies because the gate is
	// the guarded predicate + value-flow, not the class. The reentrancy bonus
	// detector is simply not consulted.
	in := buildInput(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest", ClassAccessControl)
	v, ev := Decide(in)
	if v != Verified {
		t.Fatalf("access-control-labelled finding with a good predicate should VERIFY, got %s: %v", v, ev.Notes)
	}
}

func TestDecide_ProfitClaimWithoutValueFlowRejected(t *testing.T) {
	// A profit claim must be corroborated by independent value flow. The
	// vacuous fixture never moves value to the attacker, so even setting it up
	// to pass the earlier gates, a profit claim cannot stand. (Here the target
	// is also never invoked, so it rejects earlier; this asserts rejection.)
	in := buildInput(t, "vacuous_exploit.json", "test/VacuousExploit.t.sol:VacuousExploitTest", ClassGeneric)
	if v, _ := Decide(in); v != Rejected {
		t.Fatalf("expected REJECTED, got %s", v)
	}
}
