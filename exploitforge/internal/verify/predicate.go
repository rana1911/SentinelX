package verify

import (
	"regexp"
	"strings"
)

// The success predicate is what makes a finding class-independent: the model
// states an invariant that should hold on a safe contract, and the exploit
// is only "verified" if that invariant is BROKEN. But the predicate is
// supplied by the model, so it cannot be trusted blindly — a model trying to
// pass could write a trivially-true assertion, one over values it fully
// controls, or one that reads no contract state at all. CheckSuccessPredicate
// is the guard: a static check that the assertion is MEANINGFUL before we let
// a passing forge run count as proof. It does not (and cannot) re-execute the
// assertion; forge already did that. It guards the SHAPE of the claim.
//
// This is deliberately conservative and heuristic: it is far stronger than
// "an assertion passed", but it is not a theorem prover. Its job is to reject
// the obvious ways a predicate can be hollow, not to certify semantic
// correctness. Reported honestly as such.

var (
	assertCall = regexp.MustCompile(`\b(assertEq|assertNotEq|assertGt|assertLt|assertGe|assertLe|assertTrue|assertFalse|assertGtDecimal|assertLtDecimal)\s*\(`)
	bareAssert = regexp.MustCompile(`\b(assert|require)\s*\(`)
	// State sources that mean the predicate actually reads real contract /
	// chain state rather than only model-controlled locals or literals.
	stateSource = regexp.MustCompile(`\b(target|preTargetBalance|preAttackerBalance)\b|\.balance\b`)
	// Obviously-vacuous forms.
	trivialTrue  = regexp.MustCompile(`\bassert(True)?\s*\(\s*true\s*[),]`)
	trivialFalse = regexp.MustCompile(`\bassertFalse\s*\(\s*false\s*[),]`)
	numericLit   = regexp.MustCompile(`^(0x[0-9a-fA-F]+|\d+([.]\d+)?(\s*(ether|wei|gwei|days|hours|minutes|seconds))?|true|false)$`)
)

// PredicateVerdict is the guard's finding.
type PredicateVerdict struct {
	OK     bool
	Reason string // why it was rejected (empty when OK)
}

// CheckSuccessPredicate statically validates a harness success assertion.
func CheckSuccessPredicate(assertion string) PredicateVerdict {
	a := strings.TrimSpace(assertion)
	if a == "" {
		return PredicateVerdict{false, "no success assertion supplied"}
	}
	// Must not smuggle cheatcodes into the harness assertion line.
	if len(CheckSource(a)) > 0 {
		return PredicateVerdict{false, "success assertion references cheatcodes / test tooling"}
	}
	// Must actually be an assertion.
	if !assertCall.MatchString(a) && !bareAssert.MatchString(a) {
		return PredicateVerdict{false, "success assertion is not an assert*/require statement"}
	}
	// Reject the blatantly vacuous.
	if trivialTrue.MatchString(a) || trivialFalse.MatchString(a) {
		return PredicateVerdict{false, "success assertion is trivially true (assertTrue(true)/assertFalse(false))"}
	}
	// Must read some real state, not only literals and attacker-controlled
	// locals.
	if !stateSource.MatchString(a) {
		return PredicateVerdict{false, "success assertion reads no contract/attacker state (target, balances) — it cannot witness an exploit"}
	}
	// For a binary assertion, reject identical operands (assertEq(x, x)) and
	// literal-only comparisons (assertGt(2, 1)).
	if args, ok := binaryAssertArgs(a); ok {
		l, r := normExpr(args[0]), normExpr(args[1])
		if l == r {
			return PredicateVerdict{false, "success assertion compares an expression to itself (always holds)"}
		}
		if isLiteral(l) && isLiteral(r) {
			return PredicateVerdict{false, "success assertion compares two literals (independent of contract state)"}
		}
	}
	return PredicateVerdict{OK: true}
}

// binaryAssertArgs extracts the two arguments of a two-arg assertEq/NotEq/Gt/
// Lt/Ge/Le call (ignoring a trailing message arg), splitting on the top-level
// comma. ok is false if the assertion is not of that form.
func binaryAssertArgs(a string) ([2]string, bool) {
	m := regexp.MustCompile(`\b(assertEq|assertNotEq|assertGt|assertLt|assertGe|assertLe)\s*\(`).FindStringIndex(a)
	if m == nil {
		return [2]string{}, false
	}
	open := m[1] - 1
	inner, ok := balancedInner(a, open)
	if !ok {
		return [2]string{}, false
	}
	parts := splitTopComma(inner)
	if len(parts) < 2 {
		return [2]string{}, false
	}
	return [2]string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])}, true
}

// balancedInner returns the text between the '(' at index open and its
// matching ')'.
func balancedInner(s string, open int) (string, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], true
			}
		}
	}
	return "", false
}

// splitTopComma splits on commas not nested inside parens/brackets.
func splitTopComma(s string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func normExpr(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func isLiteral(s string) bool {
	return numericLit.MatchString(strings.TrimSpace(s))
}
