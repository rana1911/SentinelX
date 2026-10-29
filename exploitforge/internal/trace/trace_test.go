package trace

import (
	"os"
	"path/filepath"
	"testing"
)

// Parses a real fixture to confirm the schema decoding (custom
// [kind, arena] array unmarshaling, nested arena nodes) matches what forge
// 1.5.1 actually emits. The fixture lives in the verify package's testdata.
func fixturePath(name string) string {
	return filepath.Join("..", "verify", "testdata", name)
}

func TestParse_RealHonestFixture(t *testing.T) {
	raw, err := os.ReadFile(fixturePath("honest_exploit.json"))
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	tr, err := Parse(raw, "test/HonestExploit.t.sol:HonestExploitTest", "test_exploit()")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tr.Status != "Success" {
		t.Fatalf("expected Success, got %q", tr.Status)
	}
	exec := tr.Arena("Execution")
	if len(exec) == 0 {
		t.Fatal("empty Execution arena")
	}
	// Root node must have a nil parent.
	var roots int
	for _, n := range exec {
		if n.Parent == nil {
			roots++
		}
	}
	if roots != 1 {
		t.Fatalf("expected exactly 1 root in Execution arena, got %d", roots)
	}
}

func TestParse_WrongContractKey(t *testing.T) {
	raw, err := os.ReadFile(fixturePath("honest_exploit.json"))
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	if _, err := Parse(raw, "nonexistent:Contract", "test_exploit()"); err == nil {
		t.Fatal("expected error for missing contract key")
	}
}

func TestCall_Selector(t *testing.T) {
	cases := []struct {
		data, want string
	}{
		{"0x06447d56000000000000000000000000abcdef", "0x06447d56"},
		{"0x06447d56", "0x06447d56"},
		{"0x", ""},     // bare value transfer / receive()
		{"0x1234", ""}, // too short for a selector
		{"", ""},
	}
	for _, c := range cases {
		got := Call{Data: c.data}.Selector()
		if got != c.want {
			t.Errorf("Selector(%q) = %q, want %q", c.data, got, c.want)
		}
	}
}

func TestCall_ValueWei(t *testing.T) {
	cases := []struct {
		value string
		want  uint64
	}{
		{"0x0", 0},
		{"0x", 0},
		{"0xde0b6b3a7640000", 1000000000000000000}, // 1 ether
		{"0x1", 1},
	}
	for _, c := range cases {
		got, overflow := Call{Value: c.value}.ValueWei()
		if overflow {
			t.Errorf("ValueWei(%q) unexpectedly overflowed", c.value)
		}
		if got != c.want {
			t.Errorf("ValueWei(%q) = %d, want %d", c.value, got, c.want)
		}
	}
}

func TestSameAddress(t *testing.T) {
	if !SameAddress("0x7109709ECfa91a80626fF3989D68f67F5b1DD12D", "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d") {
		t.Fatal("checksummed and lowercase forms should match")
	}
	if !SameAddress("abc", "0xABC") {
		t.Fatal("prefix-insensitive match failed")
	}
	if SameAddress("0x1", "0x2") {
		t.Fatal("different addresses matched")
	}
}
