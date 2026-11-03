// Package ingest turns a Foundry project into the harness configuration the
// audit needs, so the user points at a repo instead of hand-writing an
// AuditSpec. It runs `forge build`, reads the compiled ABI for the target
// contract, and synthesizes a best-effort deploy/seed/assert setup.
//
// Structural facts (contract name, source, constructor inputs, function
// signatures, payability) are extracted reliably from the build artifact.
// Two things cannot always be inferred and are produced best-effort with an
// explicit note for the user to review: constructor argument VALUES, and
// whether/how to seed the target with victim funds. The generated spec is a
// correct starting point, not a guarantee.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rana1911/sentinelx/internal/runner"
)

// AbiArg is one input/output parameter.
type AbiArg struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Func is one ABI function entry.
type Func struct {
	Name            string   `json:"name"`
	Inputs          []AbiArg `json:"inputs"`
	StateMutability string   `json:"stateMutability"`
}

// Signature renders the selector form, e.g. "redeem(uint256)".
func (f Func) Signature() string {
	types := make([]string, len(f.Inputs))
	for i, a := range f.Inputs {
		types[i] = a.Type
	}
	return f.Name + "(" + strings.Join(types, ",") + ")"
}

func (f Func) Payable() bool  { return f.StateMutability == "payable" }
func (f Func) ReadOnly() bool { return f.StateMutability == "view" || f.StateMutability == "pure" }

type abiEntry struct {
	Type            string   `json:"type"` // function | constructor | receive | fallback | event | error
	Name            string   `json:"name"`
	Inputs          []AbiArg `json:"inputs"`
	StateMutability string   `json:"stateMutability"`
}

// Target is everything ingestion learned about the contract under audit.
type Target struct {
	Contract          string
	File              string // path relative to the project, e.g. "src/VulnerableVault.sol"
	Source            string
	ConstructorInputs []AbiArg
	Functions         []Func // external/public functions (view/pure included)
	HasReceive        bool
}

// AuditSpec is the generated harness configuration. Its JSON tags match the
// spec the audit command consumes, so an ingested spec can be printed,
// edited, and fed straight back in.
type AuditSpec struct {
	Mode             string `json:"mode"`
	Imports          string `json:"imports"`
	TargetDecl       string `json:"target_decl"`
	TargetSetup      string `json:"target_setup"`
	StartBalanceWei  string `json:"start_balance_wei"`
	SuccessAssertion string `json:"success_assertion"`
	ClaimsProfit     bool   `json:"claims_profit"`
	Contract         string `json:"contract"`
	ContractSrcFile  string `json:"contract_src_file"`

	// Notes are assumptions the user should review (never serialized into the
	// spec the audit reads; surfaced separately).
	Notes []string `json:"-"`
}

var contractDecl = regexp.MustCompile(`(?m)^\s*contract\s+([A-Za-z_]\w*)`)

// Inspect builds the project and extracts the target contract. If contract
// is empty and src/ defines exactly one concrete contract, that one is used;
// otherwise the caller must name it. solc is optional (passed to forge).
func Inspect(ctx context.Context, projectDir, contract, solc string, backend runner.Backend, timeout time.Duration) (*Target, error) {
	if backend == nil {
		backend = runner.LocalBackend{}
	}
	if timeout == 0 {
		timeout = 180 * time.Second
	}

	// Locate the source file for the requested (or only) concrete contract.
	file, name, src, err := findContract(projectDir, contract)
	if err != nil {
		return nil, err
	}

	// Build so the ABI artifact exists.
	args := []string{"build"}
	if solc != "" {
		args = append(args, "--use", solc)
	}
	if _, combined, err := backend.Exec(ctx, projectDir, timeout, "forge", args...); err != nil {
		return nil, fmt.Errorf("ingest: forge build failed: %v\n%s", err, combined)
	}

	abi, hasReceive, err := readABI(projectDir, file, name)
	if err != nil {
		return nil, err
	}

	t := &Target{Contract: name, File: file, Source: src, HasReceive: hasReceive}
	for _, e := range abi {
		switch e.Type {
		case "constructor":
			t.ConstructorInputs = e.Inputs
		case "function":
			t.Functions = append(t.Functions, Func{Name: e.Name, Inputs: e.Inputs, StateMutability: e.StateMutability})
		}
	}
	return t, nil
}

func findContract(projectDir, want string) (file, name, src string, err error) {
	srcDir := filepath.Join(projectDir, "src")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return "", "", "", fmt.Errorf("ingest: read src/: %w", err)
	}
	type hit struct{ file, name, src string }
	var hits []hit
	nameList := func() string {
		parts := make([]string, len(hits))
		for i, h := range hits {
			parts[i] = h.name
		}
		return strings.Join(parts, ", ")
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sol") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			continue
		}
		body := string(b)
		for _, m := range contractDecl.FindAllStringSubmatch(body, -1) {
			rel := filepath.ToSlash(filepath.Join("src", e.Name()))
			hits = append(hits, hit{rel, m[1], body})
		}
	}
	if len(hits) == 0 {
		return "", "", "", fmt.Errorf("ingest: no concrete contract found under %s", srcDir)
	}
	if want != "" {
		for _, h := range hits {
			if h.name == want {
				return h.file, h.name, h.src, nil
			}
		}
		return "", "", "", fmt.Errorf("ingest: contract %q not found in src/ (found: %s)", want, nameList())
	}
	if len(hits) == 1 {
		return hits[0].file, hits[0].name, hits[0].src, nil
	}
	return "", "", "", fmt.Errorf("ingest: src/ defines %d contracts (%s); pass -contract to choose one", len(hits), nameList())
}

// readABI loads out/<File>.sol/<Contract>.json produced by forge build.
func readABI(projectDir, file, contract string) ([]abiEntry, bool, error) {
	base := filepath.Base(file) // VulnerableVault.sol
	artifact := filepath.Join(projectDir, "out", base, contract+".json")
	b, err := os.ReadFile(artifact)
	if err != nil {
		return nil, false, fmt.Errorf("ingest: reading build artifact %s: %w (did forge build succeed?)", artifact, err)
	}
	var doc struct {
		ABI []abiEntry `json:"abi"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, false, fmt.Errorf("ingest: parse artifact ABI: %w", err)
	}
	hasReceive := false
	for _, e := range doc.ABI {
		if e.Type == "receive" || (e.Type == "fallback" && e.StateMutability == "payable") {
			hasReceive = true
		}
	}
	return doc.ABI, hasReceive, nil
}
