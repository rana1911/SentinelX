// Package trace parses Foundry's structured `forge test --json -vvvv`
// output. Unlike scanning the pretty-printed -vvvv text (which is a
// rendering detail that can change between Foundry versions/verbosity
// levels), this reads the actual call-graph Foundry itself operates on:
// per-call depth, caller, callee address, calldata, output and success —
// which is what lets internal/verify do provenance-based checks ("who
// actually made this cheatcode call") instead of textual pattern matching.
package trace

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Call is one node of Foundry's call-trace arena.
type Call struct {
	Depth    int    `json:"depth"`
	Success  bool   `json:"success"`
	Caller   string `json:"caller"`
	Address  string `json:"address"`
	Kind     string `json:"kind"` // CALL | STATICCALL | DELEGATECALL | CREATE | ...
	Value    string `json:"value"`
	Data     string `json:"data"`
	Output   string `json:"output"`
	GasUsed  uint64 `json:"gas_used"`
	GasLimit uint64 `json:"gas_limit"`
	Status   string `json:"status"`
}

// Node is one arena entry: a Call plus tree linkage.
type Node struct {
	Parent   *int  `json:"parent"`
	Children []int `json:"children"`
	Idx      int   `json:"idx"`
	Trace    Call  `json:"trace"`
}

type arenaWrapper struct {
	Arena []Node `json:"arena"`
}

// namedArena is one ["Deployment"|"Setup"|"Execution", {arena:[...]}] entry.
// Foundry emits this as a raw 2-element JSON array (not an object), so it
// needs a custom unmarshaler.
type namedArena struct {
	Kind  string
	Nodes []Node
}

func (n *namedArena) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if len(raw) != 2 {
		return fmt.Errorf("trace: expected 2-element [kind, arena] pair, got %d", len(raw))
	}
	if err := json.Unmarshal(raw[0], &n.Kind); err != nil {
		return err
	}
	var w arenaWrapper
	if err := json.Unmarshal(raw[1], &w); err != nil {
		return err
	}
	n.Nodes = w.Arena
	return nil
}

type testResult struct {
	Status           string            `json:"status"`
	Reason           *string           `json:"reason"`
	Traces           []namedArena      `json:"traces"`
	LabeledAddresses map[string]string `json:"labeled_addresses"`
}

type contractResult struct {
	TestResults map[string]testResult `json:"test_results"`
}

// TestRun is the parsed, queryable result for one `contract:test` pair.
type TestRun struct {
	Status string
	Reason string
	arenas map[string][]Node // keyed by "Deployment" | "Setup" | "Execution"
}

// Arena returns the named call-trace arena ("Deployment", "Setup", or
// "Execution"), in execution order (index order == chronological order).
func (t *TestRun) Arena(kind string) []Node {
	return t.arenas[kind]
}

// Parse reads the raw output of `forge test --json -vvvv` and extracts the
// result for one contract (e.g. "test/Exploit.t.sol:ExploitTest") and test
// function (e.g. "test_exploit()").
func Parse(raw []byte, contractKey, testName string) (*TestRun, error) {
	var top map[string]contractResult
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("trace: not valid forge --json output: %w", err)
	}
	cr, ok := top[contractKey]
	if !ok {
		keys := make([]string, 0, len(top))
		for k := range top {
			keys = append(keys, k)
		}
		return nil, fmt.Errorf("trace: contract %q not found in output (have: %v)", contractKey, keys)
	}
	tr, ok := cr.TestResults[testName]
	if !ok {
		names := make([]string, 0, len(cr.TestResults))
		for k := range cr.TestResults {
			names = append(names, k)
		}
		return nil, fmt.Errorf("trace: test %q not found in %q (have: %v)", testName, contractKey, names)
	}
	reason := ""
	if tr.Reason != nil {
		reason = *tr.Reason
	}
	out := &TestRun{Status: tr.Status, Reason: reason, arenas: map[string][]Node{}}
	for _, na := range tr.Traces {
		out.arenas[na.Kind] = na.Nodes
	}
	return out, nil
}

// Selector returns the 4-byte function selector from a node's calldata
// ("0x" + 8+ hex chars), or "" if the calldata is too short to contain one
// (a bare value-transfer / receive() call has no selector).
func (c Call) Selector() string {
	d := strings.TrimPrefix(c.Data, "0x")
	if len(d) < 8 {
		return ""
	}
	return "0x" + strings.ToLower(d[:8])
}

// ValueWei parses the node's hex "value" field as a big-endian integer in
// wei. Malformed/empty values are treated as 0.
func (c Call) ValueWei() (weiLow64 uint64, overflowed bool) {
	d := strings.TrimPrefix(c.Value, "0x")
	if d == "" {
		return 0, false
	}
	raw, err := hex.DecodeString(padEven(d))
	if err != nil {
		return 0, false
	}
	// Only the low 8 bytes are meaningful for anything that fits in
	// uint64 (ETH amounts in test fixtures always do); report overflow so
	// callers can fall back to a big.Int path if they ever need one.
	if len(raw) > 8 {
		for _, b := range raw[:len(raw)-8] {
			if b != 0 {
				return 0, true
			}
		}
		raw = raw[len(raw)-8:]
	}
	var v uint64
	for _, b := range raw {
		v = (v << 8) | uint64(b)
	}
	return v, false
}

func padEven(s string) string {
	if len(s)%2 == 1 {
		return "0" + s
	}
	return s
}

// SameAddress does case-insensitive hex address comparison (Foundry's JSON
// emits lowercase addresses, but callers may pass checksummed ones).
func SameAddress(a, b string) bool {
	return strings.EqualFold(strings.TrimPrefix(a, "0x"), strings.TrimPrefix(b, "0x"))
}
