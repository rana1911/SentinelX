package ingest

import (
	"fmt"
	"strings"
)

// SynthOptions tunes spec generation.
type SynthOptions struct {
	StartBalanceWei string // default "1 ether"
	SeedWei         string // default "10 ether"
	// SeedFns are payable, zero-argument function names treated as a way to
	// pre-fund the target with a victim's deposit (e.g. "deposit", "mint").
	// A match is seeded best-effort. Default set used if nil.
	SeedFns []string
}

var defaultSeedFns = []string{"deposit", "mint", "stake", "supply", "fund", "donate"}

// Synthesize builds a best-effort AuditSpec from a Target. It always deploys
// the contract and sets a generic profit assertion; constructor arguments
// and target seeding are inferred where possible and flagged in Notes
// otherwise. The spec compiles for the common cases (no-arg constructor,
// a payable deposit-style seed); anything it had to guess is called out so
// the user can correct it before trusting the run.
func Synthesize(t *Target, opts SynthOptions) *AuditSpec {
	start := opts.StartBalanceWei
	if start == "" {
		start = "1 ether"
	}
	seedWei := opts.SeedWei
	if seedWei == "" {
		seedWei = "10 ether"
	}
	seedFns := opts.SeedFns
	if seedFns == nil {
		seedFns = defaultSeedFns
	}

	var notes []string
	ctorArgs, ctorNotes := constructorArgs(t.ConstructorInputs)
	notes = append(notes, ctorNotes...)

	var setup strings.Builder
	fmt.Fprintf(&setup, "target = new %s(%s);", t.Contract, ctorArgs)

	if fn, ok := seedFn(t, seedFns); ok {
		fmt.Fprintf(&setup, "\n        address seeder = address(0xBEEF);")
		fmt.Fprintf(&setup, "\n        vm.deal(seeder, %s);", seedWei)
		fmt.Fprintf(&setup, "\n        vm.prank(seeder);")
		fmt.Fprintf(&setup, "\n        target.%s{value: %s}();", fn, seedWei)
		notes = append(notes, fmt.Sprintf("seeded the target with %s via %s() (a payable entry point); adjust if that is not how value enters this contract", seedWei, fn))
	} else {
		notes = append(notes, "no payable deposit-style function found to seed the target — it starts with no victim funds, so profit-based findings may need a manual seed in target_setup")
	}

	spec := &AuditSpec{
		Mode:             "local-deploy",
		Imports:          fmt.Sprintf("import \"../%s\";", t.File),
		TargetDecl:       fmt.Sprintf("%s internal target;", t.Contract),
		TargetSetup:      setup.String(),
		StartBalanceWei:  start,
		SuccessAssertion: "assertGt(attacker.balance, preAttackerBalance, \"no profit\");",
		ClaimsProfit:     true,
		Contract:         t.Contract,
		ContractSrcFile:  t.File,
		Notes:            notes,
	}
	return spec
}

// constructorArgs renders default argument values for a constructor, with a
// note for any type it cannot safely default.
func constructorArgs(inputs []AbiArg) (string, []string) {
	if len(inputs) == 0 {
		return "", nil
	}
	var notes []string
	vals := make([]string, len(inputs))
	for i, in := range inputs {
		v, ok := zeroValue(in.Type)
		vals[i] = v
		if !ok {
			notes = append(notes, fmt.Sprintf("constructor arg #%d (%s %s) has no safe default — review target_setup before trusting results", i+1, in.Type, in.Name))
		}
	}
	notes = append([]string{fmt.Sprintf("constructor takes %d argument(s); generated default values — replace with realistic ones so the deployed state matches production", len(inputs))}, notes...)
	return strings.Join(vals, ", "), notes
}

// zeroValue returns a Solidity literal for a type's zero value and whether it
// is a safe/known default. Unknown types get a TODO placeholder (ok=false).
func zeroValue(t string) (string, bool) {
	switch {
	case strings.HasSuffix(t, "[]"):
		return fmt.Sprintf("new %s(0)", t), true
	case strings.HasPrefix(t, "uint") || strings.HasPrefix(t, "int"):
		return "0", true
	case t == "address":
		return "address(0)", true
	case t == "address payable":
		return "payable(address(0))", true
	case t == "bool":
		return "false", true
	case t == "string":
		return "\"\"", true
	case t == "bytes":
		return "\"\"", true
	case strings.HasPrefix(t, "bytes"): // bytes1..bytes32
		return t + "(0)", true
	default:
		return fmt.Sprintf("/* TODO: %s */", t), false
	}
}

// seedFn returns the first payable, zero-argument function whose name matches
// a seed candidate (case-insensitive).
func seedFn(t *Target, candidates []string) (string, bool) {
	for _, f := range t.Functions {
		if !f.Payable() || len(f.Inputs) != 0 {
			continue
		}
		for _, c := range candidates {
			if strings.EqualFold(f.Name, c) {
				return f.Name, true
			}
		}
	}
	return "", false
}
