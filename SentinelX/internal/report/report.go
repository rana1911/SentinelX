// Package report renders the outcome of an audit — a set of per-hypothesis
// orchestrator.Results — into a human-readable Markdown report. Verified
// findings lead, each with its reproducible proof-of-concept and the
// trace-derived evidence; rejected and inconclusive hypotheses are listed
// after, so a reader can see what was tried and why it did not hold.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/rana1911/sentinelx/internal/orchestrator"
	"github.com/rana1911/sentinelx/internal/verify"
)

// Summary is the headline count across an audit.
type Summary struct {
	Target       string
	Total        int
	Verified     int
	Rejected     int
	Inconclusive int
}

// Summarize tallies results by verdict.
func Summarize(target string, results []orchestrator.Result) Summary {
	s := Summary{Target: target, Total: len(results)}
	for _, r := range results {
		switch r.Verdict {
		case verify.Verified:
			s.Verified++
		case verify.Inconclusive:
			s.Inconclusive++
		default:
			s.Rejected++
		}
	}
	return s
}

// Markdown writes the full report. results may be in any order; verified
// findings are promoted to the top regardless.
func Markdown(w io.Writer, target string, results []orchestrator.Result) {
	s := Summarize(target, results)
	fmt.Fprintf(w, "# SentinelX audit: %s\n\n", mdEsc(target))
	fmt.Fprintf(w, "**%d verified**, %d rejected, %d inconclusive out of %d hypotheses tested.\n\n",
		s.Verified, s.Rejected, s.Inconclusive, s.Total)
	fmt.Fprintln(w, "Every verified finding below was proven by an exploit that compiled and ran")
	fmt.Fprintln(w, "in Foundry; the proof uses only calls an unprivileged attacker could make, and")
	fmt.Fprintln(w, "the vulnerability was confirmed from the execution trace, not from a passing")
	fmt.Fprintln(w, "assertion alone.")
	fmt.Fprintln(w)

	verified, others := partition(results)

	if len(verified) > 0 {
		fmt.Fprintln(w, "## Verified vulnerabilities")
		fmt.Fprintln(w)
		for i, r := range verified {
			writeVerified(w, i+1, r)
		}
	} else {
		fmt.Fprintln(w, "## Verified vulnerabilities")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "_None. No hypothesis produced an exploit that survived verification._")
		fmt.Fprintln(w)
	}

	if len(others) > 0 {
		fmt.Fprintln(w, "## Not confirmed")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Hypothesis | Class | Function | Verdict | Why |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, r := range others {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
				mdCell(r.Hypothesis.ID), mdCell(r.Hypothesis.Class), mdCell(r.Hypothesis.Function),
				mdCell(string(r.Verdict)), mdCell(oneLine(r.Reason)))
		}
		fmt.Fprintln(w)
	}
}

func writeVerified(w io.Writer, n int, r orchestrator.Result) {
	h := r.Hypothesis
	fmt.Fprintf(w, "### %d. %s in `%s.%s`\n\n", n, title(h.Class), mdEsc(h.Contract), mdEsc(h.Function))
	if h.SuccessMetric != "" {
		fmt.Fprintf(w, "**Impact:** %s\n\n", mdEsc(h.SuccessMetric))
	}
	fmt.Fprintf(w, "**Confidence at hypothesis time:** %.2f  \n", h.Confidence)
	fmt.Fprintf(w, "**Proven in:** %s\n\n", mdEsc(r.Reason))

	if ev := r.Evidence; len(ev.Notes) > 0 {
		fmt.Fprintln(w, "**Evidence from execution trace:**")
		fmt.Fprintln(w)
		for _, note := range ev.Notes {
			fmt.Fprintf(w, "- %s\n", mdEsc(note))
		}
		fmt.Fprintln(w)
	}

	if len(h.AttackSteps) > 0 {
		fmt.Fprintln(w, "**Attack:**")
		fmt.Fprintln(w)
		for _, st := range h.AttackSteps {
			fmt.Fprintf(w, "1. %s\n", mdEsc(st))
		}
		fmt.Fprintln(w)
	}

	if code := lastCode(r); code != "" {
		fmt.Fprintln(w, "**Reproducible proof-of-concept** (the attack region of the Foundry test):")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "```solidity")
		fmt.Fprintln(w, strings.TrimRight(code, "\n"))
		fmt.Fprintln(w, "```")
		fmt.Fprintln(w)
	}
}

func partition(results []orchestrator.Result) (verified, others []orchestrator.Result) {
	for _, r := range results {
		if r.Verdict == verify.Verified {
			verified = append(verified, r)
		} else {
			others = append(others, r)
		}
	}
	return
}

func lastCode(r orchestrator.Result) string {
	if len(r.Attempts) == 0 {
		return ""
	}
	return r.Attempts[len(r.Attempts)-1].Code
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 140 {
		s = s[:137] + "..."
	}
	return s
}

func title(s string) string {
	if s == "" {
		return "Vulnerability"
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '_' })
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}

func mdEsc(s string) string {
	return strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(s)
}

// mdCell escapes a value for a Markdown table cell (pipes and newlines break
// table layout).
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return mdEsc(s)
}
