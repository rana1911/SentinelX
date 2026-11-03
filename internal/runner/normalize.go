package runner

import (
	"strings"
	"unicode"
)

// Normalized is model output converted to the shape the harness expects.
type Normalized struct {
	// Code is what gets inserted into the MODEL region. The harness supplies
	// the final "}" after MODEL_END, so Code is: ExploitTest members, then
	// (if there are helpers) a "}" closing ExploitTest, then the helper
	// contracts with the LAST closing brace removed.
	Code string
	// Members is the part of the model code that lives INSIDE ExploitTest
	// (attack() and any other functions/state). The shadowing guard scans
	// this: anything declared here can interact with forge-std's Test.
	Members string
	// Stripped lists top-level lines removed (pragma/import/SPDX) — they are
	// illegal inside a contract body and the harness already provides them.
	Stripped []string
}

// NormalizeModelCode accepts model output in either of two shapes:
//
//	(a) natural:  attack() + other members, followed by fully-closed
//	              top-level helper contracts/interfaces/libraries;
//	(b) harness:  members, then a "}" that closes ExploitTest, then helpers
//	              whose final "}" is supplied by the harness template.
//
// and returns shape (b). Models naturally write (a); without this step,
// their helper contracts end up nested inside ExploitTest (illegal Solidity)
// and every attempt fails to compile for a reason that isn't the model's.
func NormalizeModelCode(code string) Normalized {
	var stripped []string
	var kept []string
	for _, line := range strings.Split(code, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "pragma ") || strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "// SPDX-License-Identifier") {
			stripped = append(stripped, t)
			continue
		}
		kept = append(kept, line)
	}
	code = strings.Join(kept, "\n")

	closeIdx, declIdx := scanTopLevel(code)

	// Shape (b): the model already closed ExploitTest itself.
	if closeIdx >= 0 && (declIdx < 0 || closeIdx < declIdx) {
		return Normalized{Code: code, Members: code[:closeIdx], Stripped: stripped}
	}
	// Shape (a) with helpers: split at the first top-level declaration.
	if declIdx >= 0 {
		members := strings.TrimRight(code[:declIdx], " \t\n")
		helpers := strings.TrimSpace(code[declIdx:])
		if i := strings.LastIndex(helpers, "}"); i >= 0 {
			helpers = strings.TrimRight(helpers[:i], " \t\n")
		}
		return Normalized{
			Code:     members + "\n}\n\n" + helpers + "\n",
			Members:  members,
			Stripped: stripped,
		}
	}
	// Members only, no helpers.
	return Normalized{Code: code, Members: code, Stripped: stripped}
}

// scanTopLevel walks code as if it starts inside ExploitTest's body (brace
// depth 1), skipping comments and string literals. It returns the byte index
// of a "}" that would close ExploitTest (depth 1 -> 0), and the index of the
// first contract/interface/library/abstract keyword at depth 1. -1 = none.
func scanTopLevel(s string) (closeIdx, declIdx int) {
	closeIdx, declIdx = -1, -1
	depth := 1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return
			}
			i += 2 + end + 1
		case c == '"' || c == '\'':
			q := c
			for i++; i < len(s) && s[i] != q; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 && closeIdx < 0 {
				closeIdx = i
				return
			}
		case depth == 1 && declIdx < 0 && isWordStart(s, i):
			for _, kw := range []string{"abstract", "contract", "interface", "library"} {
				if hasWordAt(s, i, kw) {
					declIdx = i
					break
				}
			}
		}
	}
	return
}

func isIdent(b byte) bool {
	r := rune(b)
	return r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isWordStart(s string, i int) bool {
	return isIdent(s[i]) && (i == 0 || !isIdent(s[i-1]))
}

func hasWordAt(s string, i int, w string) bool {
	return strings.HasPrefix(s[i:], w) && (i+len(w) == len(s) || !isIdent(s[i+len(w)]))
}
