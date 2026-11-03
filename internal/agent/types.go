package agent

// Hypothesis is one suspected vulnerability from the hypothesize stage.
type Hypothesis struct {
	ID string `json:"id"`
	// Class is an advisory LABEL for the report (reentrancy, access-control,
	// …). Verification does NOT hinge on it: a finding is proven by breaking
	// the per-hypothesis SuccessAssertion invariant, not by matching a class.
	// A dedicated detector (e.g. reentrancy re-entry) may add bonus evidence
	// when the class has one, but never gates the verdict.
	Class    string `json:"class"`
	Contract string `json:"contract"`
	Function string `json:"function"` // the entry-point function name, e.g. "withdraw"
	// TargetSignature is the exact function signature in selector form, e.g.
	// "withdraw()" or "redeem(uint256)". The verify layer needs it to compute
	// the 4-byte selector; the model fills it from the source. Empty => the
	// loop falls back to Function+"()".
	TargetSignature string `json:"target_signature"`
	// SuccessAssertion is the heart of verification: a single Solidity
	// assertion statement (harness-owned, so the exploit author cannot weaken
	// it) encoding an invariant that holds on a safe contract but is BROKEN
	// once the exploit runs — e.g.
	//   assertGt(attacker.balance, preAttackerBalance, "no profit");
	//   assertEq(target.owner(), attacker, "no takeover");
	//   assertLt(address(target).balance, preTargetBalance, "not drained");
	// It may reference: attacker, preAttackerBalance, preTargetBalance,
	// target, START_BALANCE. The verify layer independently guards that this
	// predicate is meaningful (reads real state, not trivially true, no
	// cheatcodes) — see verify.CheckSuccessPredicate. Empty => the loop falls
	// back to the spec's default profit assertion.
	SuccessAssertion string `json:"success_assertion"`
	// ClaimsProfit is true when the success condition is attacker profit (ETH
	// in/out), enabling independent trace-based value-flow corroboration.
	ClaimsProfit  bool     `json:"claims_profit"`
	AttackSteps   []string `json:"attack_steps"`
	Preconditions []string `json:"preconditions"`
	SuccessMetric string   `json:"success_metric"`
	Confidence    float64  `json:"confidence"`
}

type HypothesisSet struct {
	Hypotheses []Hypothesis `json:"hypotheses"`
}
