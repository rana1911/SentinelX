// Package hypothesize is the front of the pipeline: it shows a contract's
// source to the model and asks for a structured list of suspected
// vulnerabilities (agent.Hypothesis), each of which the downstream loop then
// tries to PROVE with a real forge exploit. Nothing here decides whether a
// bug is real — that is the verify layer's job on executed traces. This
// stage only proposes leads, so it is deliberately generous (high recall);
// false positives cost a cheap exploit attempt that gets Rejected, while a
// missed hypothesis is a bug never found.
package hypothesize

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/rana1911/sentinelx/internal/agent"
)

// Completer is the subset of the model client this stage needs (satisfied by
// *agent.Client). Declared locally so the package doesn't depend on the
// orchestrator.
type Completer interface {
	Complete(ctx context.Context, msgs []agent.Message, temp float64, jsonMode bool) (string, error)
}

// knownClasses are the vulnerability classes the verify layer can reason
// about. Anything else from the model is coerced to "generic" (target
// invocation + assertion only) rather than dropped — the exploit still gets
// attempted.
var knownClasses = map[string]bool{
	"reentrancy":          true,
	"access-control":      true,
	"share-inflation":     true,
	"oracle-manipulation": true,
	"generic":             true,
}

// Hypothesizer proposes vulnerabilities for a contract.
type Hypothesizer struct {
	Spark Completer
	Max   int // cap on hypotheses returned (0 => DefaultMax)
}

const DefaultMax = 8

func New(spark Completer) *Hypothesizer { return &Hypothesizer{Spark: spark, Max: DefaultMax} }

// Propose returns suspected vulnerabilities for one contract, best-confidence
// first. contractName is the primary contract under audit; source is the
// Solidity the model should read (the contract plus any relevant imports).
func (h *Hypothesizer) Propose(ctx context.Context, contractName, source string) ([]agent.Hypothesis, error) {
	max := h.Max
	if max <= 0 {
		max = DefaultMax
	}
	msgs := []agent.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: buildUserPrompt(contractName, source, max)},
	}
	raw, err := h.Spark.Complete(ctx, msgs, 0.4, true)
	if err != nil {
		return nil, fmt.Errorf("hypothesize: model call failed: %w", err)
	}
	var set agent.HypothesisSet
	if err := agent.ExtractJSON(raw, &set); err != nil {
		return nil, fmt.Errorf("hypothesize: could not parse model output as JSON: %w", err)
	}
	return Sanitize(set.Hypotheses, contractName, max), nil
}

// Sanitize normalizes raw model output into trustworthy hypotheses: it drops
// entries with no target function, coerces unknown classes to "generic",
// clamps confidence, fills a default contract and stable IDs, de-duplicates
// on (class, function), sorts by confidence desc, and caps the count. It is
// exported and pure so it can be unit-tested without a model.
func Sanitize(in []agent.Hypothesis, contractName string, max int) []agent.Hypothesis {
	if max <= 0 {
		max = DefaultMax
	}
	seen := map[string]bool{}
	var out []agent.Hypothesis
	for _, hy := range in {
		hy.Function = strings.TrimSpace(hy.Function)
		if hy.Function == "" {
			continue // nothing for the exploit to target
		}
		hy.Class = strings.ToLower(strings.TrimSpace(hy.Class))
		if !knownClasses[hy.Class] {
			hy.Class = "generic"
		}
		if strings.TrimSpace(hy.Contract) == "" {
			hy.Contract = contractName
		}
		hy.TargetSignature = strings.TrimSpace(hy.TargetSignature)
		if hy.TargetSignature == "" {
			hy.TargetSignature = hy.Function + "()" // best-effort: assume no args
		}
		hy.SuccessAssertion = strings.TrimSpace(hy.SuccessAssertion)
		if hy.SuccessAssertion == "" {
			// Fall back to a profit invariant so the loop can still run; the
			// verify layer will guard whatever ends up here.
			hy.SuccessAssertion = `assertGt(attacker.balance, preAttackerBalance, "no profit");`
			hy.ClaimsProfit = true
		}
		switch {
		case hy.Confidence < 0:
			hy.Confidence = 0
		case hy.Confidence > 1:
			hy.Confidence = 1
		}
		key := hy.Class + "|" + hy.Contract + "." + hy.Function
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, hy)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Confidence > out[j].Confidence })
	if len(out) > max {
		out = out[:max]
	}
	for i := range out {
		if strings.TrimSpace(out[i].ID) == "" {
			out[i].ID = fmt.Sprintf("H%d", i+1)
		}
	}
	return out
}

const systemPrompt = `You are a smart-contract security auditor reviewing Solidity for an authorized audit. Given a contract's source, list the specific, plausible vulnerabilities worth proving with a proof-of-concept exploit. A later stage writes and RUNS an exploit for each, so only propose bugs an unprivileged on-chain attacker could actually trigger through the contract's public/external interface — not style issues, gas notes, or risks that need a malicious owner or compromised key.

For each hypothesis give:
- class: one of reentrancy, access-control, share-inflation, oracle-manipulation; or generic if it fits none of these.
- contract: the contract that holds the flaw.
- function: the external/public function name an attacker calls to trigger it (the single entry point), e.g. "withdraw".
- target_signature: that function's exact signature in selector form, e.g. "withdraw()" or "redeem(uint256)" — read the parameter types from the source.
- success_assertion: the CRUX. A single Solidity assertion statement expressing an invariant that holds on a safe contract but is BROKEN once the bug is exploited. This is the objective proof — the exploit must make this assertion pass. Write it to read real on-chain state, never a value the attacker controls, and never something trivially true. It may reference: attacker, preAttackerBalance (attacker's balance before the attack), preTargetBalance (target's balance before), target, START_BALANCE. Examples by bug:
    theft of funds: assertGt(attacker.balance, preAttackerBalance, "no profit");
    drained vault:   assertLt(address(target).balance, preTargetBalance, "not drained");
    ownership takeover: assertEq(target.owner(), attacker, "no takeover");
    broken accounting: assertGt(target.totalSupply(), <expected bound>, "supply inflated");
  Choose the assertion that most directly witnesses THIS bug. End it with a semicolon.
- claims_profit: true if success means the attacker gains ETH (enables an independent value-flow cross-check); false otherwise (e.g. ownership takeover).
- attack_steps: the concrete sequence an attacker performs, as short strings.
- preconditions: what must hold first (e.g. "pool holds other users' funds").
- success_metric: the observable proof of exploitation (e.g. "attacker ETH balance strictly increases").
- confidence: 0.0-1.0, your estimate that a working exploit exists.

Prefer specific, testable claims over vague ones. It is fine to return several; order does not matter. If the contract looks sound, return an empty list rather than inventing bugs.

Output ONLY a JSON object of this exact shape, no prose:
{"hypotheses":[{"class":"reentrancy","contract":"Vault","function":"withdraw","target_signature":"withdraw()","success_assertion":"assertGt(attacker.balance, preAttackerBalance, \"no profit\");","claims_profit":true,"attack_steps":["deposit","call withdraw","re-enter from receive before balance is zeroed"],"preconditions":["vault holds other deposits"],"success_metric":"attacker balance increases","confidence":0.8}]}`

func buildUserPrompt(contractName, source string, max int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Primary contract under audit: %s\n", contractName)
	fmt.Fprintf(&b, "Propose at most %d hypotheses.\n\nSource:\n```solidity\n", max)
	b.WriteString(source)
	b.WriteString("\n```\n")
	return b.String()
}
