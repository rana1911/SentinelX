// Provenance-based checks operate on Foundry's structured call trace
// (internal/trace), not on the Solidity source text. They answer: "what
// actually executed," not "what did the source look like." This is what
// catches cheats a source-level scan structurally cannot — e.g. a cheatcode
// invoked via raw calldata bytes with no identifier naming it anywhere.
package verify

import (
	"fmt"
	"sort"

	"github.com/rana1911/exploitforge/internal/keccak"
	"github.com/rana1911/exploitforge/internal/trace"
)

// CheatcodeAddress is the fixed address Foundry's VM cheatcodes live at.
const CheatcodeAddress = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"

// ExpectedHarnessCall is one cheatcode call the FIXED harness itself makes
// (never the model), identified by its exact Solidity signature so the
// selector is computed, not guessed. Count caps how many times it may
// legitimately appear.
type ExpectedHarnessCall struct {
	Signature string // e.g. "startPrank(address)"
	Count     int
}

// CheatProvenanceViolation is one cheatcode call that cannot be attributed
// to the fixed harness.
type CheatProvenanceViolation struct {
	NodeIdx   int
	Caller    string
	Selector  string
	KnownName string // resolved name if the selector matches a known cheatcode, else ""
	Reason    string
}

func (v CheatProvenanceViolation) String() string {
	name := v.Selector
	if v.KnownName != "" {
		name = fmt.Sprintf("%s (%s)", v.KnownName, v.Selector)
	}
	return fmt.Sprintf("node #%d: cheatcode call %s from %s — %s", v.NodeIdx, name, v.Caller, v.Reason)
}

// knownCheatcodeSelectors is used only to produce readable violation
// messages ("deal(address,uint256)" instead of a bare selector); it is NOT
// an allowlist — any call to CheatcodeAddress not accounted for by
// expected is a violation regardless of whether we recognize its selector.
var knownCheatcodeSignatures = []string{
	"startPrank(address)", "startPrank(address,address)", "stopPrank()",
	"prank(address)", "prank(address,address)",
	"deal(address,uint256)", "etch(address,bytes)", "store(address,bytes32,bytes32)",
	"load(address,bytes32)", "mockCall(address,bytes,bytes)", "mockCallRevert(address,bytes,bytes)",
	"createSelectFork(string)", "createSelectFork(string,uint256)", "createFork(string)",
	"selectFork(uint256)", "rollFork(uint256)", "addr(uint256)", "label(address,string)",
	"warp(uint256)", "roll(uint256)", "fee(uint256)", "chainId(uint256)", "txGasPrice(uint256)",
	"coinbase(address)", "assume(bool)", "expectRevert()", "expectRevert(bytes)",
	"expectEmit(bool,bool,bool,bool)", "setNonce(address,uint64)", "ffi(string[])",
	"readFile(string)", "writeFile(string,string)", "broadcast()", "startBroadcast()",
	"stopBroadcast()", "deployCodeTo(string,address)",
}

var selectorToName = buildSelectorIndex()

func buildSelectorIndex() map[string]string {
	m := make(map[string]string, len(knownCheatcodeSignatures))
	for _, sig := range knownCheatcodeSignatures {
		m[keccak.SelectorHex(sig)] = sig
	}
	return m
}

// CheckCheatcodeProvenance walks the Execution arena (the actual call tree
// forge ran for test_exploit()) and flags every call to the cheatcode
// address that is not accounted for by `expected` AND made directly by the
// test contract itself. This catches two things a source scan cannot:
//
//  1. Any cheatcode call whose caller is NOT the test contract (i.e. came
//     from a model-deployed helper contract) — illegitimate regardless of
//     which cheatcode or how it was invoked (named interface, raw
//     calldata, whatever): the fixed harness never deploys helpers that
//     touch cheatcodes, so this is unconditional.
//  2. Any EXTRA cheatcode call from the test contract itself beyond what
//     the harness is declared to make (e.g. the model's attack() body
//     calling vm.deal directly, inline in the same contract).
//
// testContractAddr is the Execution arena's root call's `Address` (the
// contract test_exploit() runs on) — callers get this from arena[0].
func CheckCheatcodeProvenance(execArena []trace.Node, testContractAddr string, expected []ExpectedHarnessCall) []CheatProvenanceViolation {
	remaining := make(map[string]int, len(expected))
	for _, e := range expected {
		remaining[keccak.SelectorHex(e.Signature)] += e.Count
	}

	var violations []CheatProvenanceViolation
	for _, node := range execArena {
		c := node.Trace
		if !trace.SameAddress(c.Address, CheatcodeAddress) {
			continue
		}
		sel := c.Selector()
		known := selectorToName[sel]

		if !trace.SameAddress(c.Caller, testContractAddr) {
			violations = append(violations, CheatProvenanceViolation{
				NodeIdx: node.Idx, Caller: c.Caller, Selector: sel, KnownName: known,
				Reason: "called from a contract other than the test harness itself — the fixed harness never does this, so this can only be model-introduced code",
			})
			continue
		}
		if remaining[sel] > 0 {
			remaining[sel]--
			continue
		}
		violations = append(violations, CheatProvenanceViolation{
			NodeIdx: node.Idx, Caller: c.Caller, Selector: sel, KnownName: known,
			Reason: "cheatcode call from the test contract beyond what the fixed harness is declared to make — likely the model's attack() body calling a cheatcode directly",
		})
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].NodeIdx < violations[j].NodeIdx })
	return violations
}

// RootCallAddress returns the address the Execution arena's root call was
// made TO — i.e. the test contract itself — which CheckCheatcodeProvenance
// needs as testContractAddr. Returns "" if the arena is empty.
func RootCallAddress(execArena []trace.Node) string {
	for _, n := range execArena {
		if n.Parent == nil {
			return n.Trace.Address
		}
	}
	return ""
}
