package report

import (
	"strings"
	"testing"

	"github.com/rana1911/sentinelx/internal/agent"
	"github.com/rana1911/sentinelx/internal/orchestrator"
	"github.com/rana1911/sentinelx/internal/verify"
)

func sampleResults() []orchestrator.Result {
	return []orchestrator.Result{
		{
			Hypothesis: agent.Hypothesis{ID: "H2", Class: "access-control", Contract: "Vault", Function: "setOwner"},
			Verdict:    verify.Rejected,
			Reason:     "no verified exploit after 5 attempts",
		},
		{
			Hypothesis: agent.Hypothesis{ID: "H1", Class: "reentrancy", Contract: "Vault", Function: "withdraw", SuccessMetric: "attacker balance increases", Confidence: 0.85, AttackSteps: []string{"deposit", "re-enter"}},
			Verdict:    verify.Verified,
			Reason:     "exploit verified in 1 attempt(s)",
			Evidence:   verify.Evidence{Notes: []string{"confirmed re-entry: node #8 nested inside node #6", "attacker netted 6 ETH"}},
			Attempts:   []orchestrator.Attempt{{N: 1, Stage: "ok", Code: "function attack() internal { target.withdraw(); }"}},
		},
		{
			Hypothesis: agent.Hypothesis{ID: "H3", Class: "oracle-manipulation", Contract: "Vault", Function: "price"},
			Verdict:    verify.Inconclusive,
			Reason:     "could not parse forge output",
		},
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize("Vault", sampleResults())
	if s.Total != 3 || s.Verified != 1 || s.Rejected != 1 || s.Inconclusive != 1 {
		t.Fatalf("bad summary: %+v", s)
	}
}

func TestMarkdown_VerifiedLeadsWithProof(t *testing.T) {
	var b strings.Builder
	Markdown(&b, "Vault", sampleResults())
	out := b.String()

	if !strings.Contains(out, "**1 verified**, 1 rejected, 1 inconclusive out of 3") {
		t.Errorf("summary line missing:\n%s", out)
	}
	// Verified section must appear before the Not-confirmed section.
	vi := strings.Index(out, "## Verified vulnerabilities")
	ni := strings.Index(out, "## Not confirmed")
	if vi < 0 || ni < 0 || vi > ni {
		t.Errorf("section ordering wrong (verified=%d notconfirmed=%d)", vi, ni)
	}
	// The verified finding carries its PoC and trace evidence.
	if !strings.Contains(out, "target.withdraw()") {
		t.Error("verified PoC code missing")
	}
	if !strings.Contains(out, "confirmed re-entry") {
		t.Error("evidence note missing")
	}
	// Rejected + inconclusive both appear in the Not-confirmed table.
	if !strings.Contains(out, "setOwner") || !strings.Contains(out, "price") {
		t.Error("non-verified hypotheses missing from table")
	}
	if !strings.Contains(out, "Reentrancy in `Vault.withdraw`") {
		t.Errorf("class title not rendered:\n%s", out)
	}
}

func TestMarkdown_NoVerified(t *testing.T) {
	res := []orchestrator.Result{{
		Hypothesis: agent.Hypothesis{ID: "H1", Class: "reentrancy", Function: "f"},
		Verdict:    verify.Rejected, Reason: "nope",
	}}
	var b strings.Builder
	Markdown(&b, "C", res)
	if !strings.Contains(b.String(), "_None.") {
		t.Error("expected explicit 'None' when nothing verified")
	}
}

func TestMarkdown_TableEscaping(t *testing.T) {
	res := []orchestrator.Result{{
		Hypothesis: agent.Hypothesis{ID: "H1", Class: "generic", Function: "f"},
		Verdict:    verify.Rejected, Reason: "reverted with a|b\nsecond line",
	}}
	var b strings.Builder
	Markdown(&b, "C", res)
	out := b.String()
	if strings.Contains(out, "a|b") || strings.Contains(out, "second line\n|") {
		t.Errorf("table cell not escaped:\n%s", out)
	}
}
