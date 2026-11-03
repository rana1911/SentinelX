package runner

import (
	"strings"
	"testing"
)

func TestNormalize_NaturalShapeWithHelpers(t *testing.T) {
	in := `pragma solidity ^0.8.19;
import "../src/VulnerableVault.sol";

function attack() internal {
    Drainer d = new Drainer(target); // a "}" in a comment
    d.run("}");
}

contract Drainer {
    VulnerableVault t;
    constructor(VulnerableVault _t) { t = _t; }
    function run(string memory) external { t.withdraw(); }
}

interface IFoo { function x() external; }`
	n := NormalizeModelCode(in)
	if len(n.Stripped) != 2 {
		t.Fatalf("expected pragma+import stripped, got %v", n.Stripped)
	}
	if strings.Contains(n.Members, "contract Drainer") {
		t.Fatal("helper leaked into members")
	}
	if !strings.Contains(n.Code, "}\n\ncontract Drainer") {
		t.Fatalf("expected ExploitTest closed before helpers:\n%s", n.Code)
	}
	if !strings.HasSuffix(strings.TrimSpace(n.Code), "function x() external;") {
		t.Fatalf("last helper's closing brace should be left for the harness:\n%s", n.Code)
	}
}

func TestNormalize_HarnessShapeUnchanged(t *testing.T) {
	in := "function attack() internal {}\n}\n\ncontract D {\n  function f() external {}"
	if n := NormalizeModelCode(in); n.Code != in {
		t.Fatalf("harness-shape code changed:\n%s", n.Code)
	}
}

func TestNormalize_MembersOnly(t *testing.T) {
	in := "function attack() internal { target.withdraw(); }"
	n := NormalizeModelCode(in)
	if n.Code != in || n.Members != in {
		t.Fatalf("unexpected: %+v", n)
	}
}
