package report

import (
	"encoding/json"
	"io"

	"github.com/rana1911/sentinelx/internal/orchestrator"
	"github.com/rana1911/sentinelx/internal/verify"
)

// JSONReport is the machine-readable audit result consumed by the web UI
// (and any other tooling). It is a flat, stable projection of the richer
// orchestrator.Result set — deliberately not the Go structs, so the frontend
// contract doesn't churn with internal refactors.
type JSONReport struct {
	Target   string        `json:"target"`
	Provider string        `json:"provider,omitempty"`
	Model    string        `json:"model,omitempty"`
	Summary  JSONSummary   `json:"summary"`
	Findings []JSONFinding `json:"findings"`
}

type JSONSummary struct {
	Total        int `json:"total"`
	Verified     int `json:"verified"`
	Rejected     int `json:"rejected"`
	Inconclusive int `json:"inconclusive"`
}

type JSONFinding struct {
	ID                  string   `json:"id"`
	Class               string   `json:"class"`
	Contract            string   `json:"contract"`
	Function            string   `json:"function"`
	Verdict             string   `json:"verdict"`
	Reason              string   `json:"reason"`
	Confidence          float64  `json:"confidence"`
	Impact              string   `json:"impact,omitempty"`
	SuccessAssertion    string   `json:"successAssertion,omitempty"`
	ClaimsProfit        bool     `json:"claimsProfit"`
	AttackSteps         []string `json:"attackSteps,omitempty"`
	EvidenceNotes       []string `json:"evidenceNotes,omitempty"`
	ValueFlowWei        uint64   `json:"valueFlowWei"`
	ReentrancyConfirmed bool     `json:"reentrancyConfirmed"`
	Attempts            int      `json:"attempts"`
	PoC                 string   `json:"poc,omitempty"` // attack region of the final exploit
}

// BuildJSON projects results into the UI-facing report.
func BuildJSON(target, provider, model string, results []orchestrator.Result) JSONReport {
	s := Summarize(target, results)
	out := JSONReport{
		Target:   target,
		Provider: provider,
		Model:    model,
		Summary:  JSONSummary{Total: s.Total, Verified: s.Verified, Rejected: s.Rejected, Inconclusive: s.Inconclusive},
		Findings: make([]JSONFinding, 0, len(results)),
	}
	for _, r := range results {
		h := r.Hypothesis
		f := JSONFinding{
			ID:                  h.ID,
			Class:               h.Class,
			Contract:            h.Contract,
			Function:            h.Function,
			Verdict:             string(r.Verdict),
			Reason:              r.Reason,
			Confidence:          h.Confidence,
			Impact:              h.SuccessMetric,
			SuccessAssertion:    h.SuccessAssertion,
			ClaimsProfit:        h.ClaimsProfit,
			AttackSteps:         h.AttackSteps,
			EvidenceNotes:       r.Evidence.Notes,
			ValueFlowWei:        r.Evidence.ValueFlow.NetWei,
			ReentrancyConfirmed: r.Evidence.Reentrancy.Occurred,
			Attempts:            len(r.Attempts),
		}
		if r.Verdict == verify.Verified && len(r.Attempts) > 0 {
			f.PoC = r.Attempts[len(r.Attempts)-1].Code
		}
		out.Findings = append(out.Findings, f)
	}
	return out
}

// WriteJSON renders the report as indented JSON.
func WriteJSON(w io.Writer, target, provider, model string, results []orchestrator.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(BuildJSON(target, provider, model, results))
}
