package ingest

import (
	"strings"
	"testing"
)

func TestFuncSignature(t *testing.T) {
	f := Func{Name: "redeem", Inputs: []AbiArg{{Type: "uint256"}, {Type: "address"}}}
	if got := f.Signature(); got != "redeem(uint256,address)" {
		t.Fatalf("signature = %q", got)
	}
	if got := (Func{Name: "withdraw"}).Signature(); got != "withdraw()" {
		t.Fatalf("no-arg signature = %q", got)
	}
}

func TestSynthesize_VaultLike(t *testing.T) {
	tgt := &Target{
		Contract:   "VulnerableVault",
		File:       "src/VulnerableVault.sol",
		HasReceive: true,
		Functions: []Func{
			{Name: "deposit", StateMutability: "payable"},
			{Name: "withdraw", StateMutability: "nonpayable"},
			{Name: "balances", Inputs: []AbiArg{{Type: "address"}}, StateMutability: "view"},
		},
	}
	spec := Synthesize(tgt, SynthOptions{})
	if spec.Imports != `import "../src/VulnerableVault.sol";` {
		t.Errorf("imports = %q", spec.Imports)
	}
	if spec.TargetDecl != "VulnerableVault internal target;" {
		t.Errorf("decl = %q", spec.TargetDecl)
	}
	if !strings.Contains(spec.TargetSetup, "target = new VulnerableVault();") {
		t.Errorf("deploy line missing: %q", spec.TargetSetup)
	}
	// deposit() is payable + zero-arg => chosen as the seed path.
	if !strings.Contains(spec.TargetSetup, "target.deposit{value: 10 ether}();") {
		t.Errorf("expected deposit seed, got: %q", spec.TargetSetup)
	}
	if !spec.ClaimsProfit || spec.Contract != "VulnerableVault" {
		t.Errorf("spec basics wrong: %+v", spec)
	}
}

func TestSynthesize_NoSeedFunction(t *testing.T) {
	tgt := &Target{Contract: "C", File: "src/C.sol", Functions: []Func{{Name: "poke", StateMutability: "nonpayable"}}}
	spec := Synthesize(tgt, SynthOptions{})
	if strings.Contains(spec.TargetSetup, "seeder") {
		t.Error("should not seed when no payable deposit-style fn exists")
	}
	if !hasNote(spec.Notes, "no payable deposit-style function") {
		t.Errorf("expected a no-seed note, got %v", spec.Notes)
	}
}

func TestSynthesize_ConstructorArgsDefaultedAndNoted(t *testing.T) {
	tgt := &Target{
		Contract: "Token", File: "src/Token.sol",
		ConstructorInputs: []AbiArg{{Name: "supply", Type: "uint256"}, {Name: "owner", Type: "address"}, {Name: "cfg", Type: "Config"}},
	}
	spec := Synthesize(tgt, SynthOptions{})
	if !strings.Contains(spec.TargetSetup, "new Token(0, address(0), /* TODO: Config */);") {
		t.Errorf("constructor defaults wrong: %q", spec.TargetSetup)
	}
	if !hasNote(spec.Notes, "constructor takes 3 argument") {
		t.Errorf("missing constructor-count note: %v", spec.Notes)
	}
	if !hasNote(spec.Notes, "no safe default") {
		t.Errorf("missing unsafe-arg note for Config: %v", spec.Notes)
	}
}

func TestZeroValue(t *testing.T) {
	cases := map[string]string{
		"uint256": "0", "int8": "0", "address": "address(0)",
		"address payable": "payable(address(0))", "bool": "false",
		"string": `""`, "bytes32": "bytes32(0)", "uint256[]": "new uint256[](0)",
	}
	for typ, want := range cases {
		if got, ok := zeroValue(typ); !ok || got != want {
			t.Errorf("zeroValue(%q) = %q,%v want %q,true", typ, got, ok, want)
		}
	}
	if _, ok := zeroValue("SomeStruct"); ok {
		t.Error("unknown type should report ok=false")
	}
}

func hasNote(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}
