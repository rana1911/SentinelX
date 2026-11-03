package verify

import (
	"strings"
	"testing"
)

const templateRendered = `pragma solidity ^0.8.19;
contract ExploitTest is Test {
    function setUp() public { vault = new Vault(); }
    function test_exploit() public {
        vm.startPrank(attacker);
        attack();
        vm.stopPrank();
        assertGt(attacker.balance, preAttackerBalance, "no profit");
    }
    // MODEL_BEGIN
    // MODEL_END
}`

func TestHarnessIntegrity_ModelRegionFilledIsOK(t *testing.T) {
	rendered := strings.Replace(templateRendered,
		"// MODEL_BEGIN\n    // MODEL_END",
		"// MODEL_BEGIN\n    function attack() internal { vault.withdraw(); }\n    // MODEL_END",
		1)
	if err := CheckHarnessIntegrity(rendered, templateRendered); err != nil {
		t.Fatalf("legitimate model fill rejected: %v", err)
	}
}

func TestHarnessIntegrity_TamperedAssertionCaught(t *testing.T) {
	// Model weakens the assertion (the suffix). Must be caught even though
	// the model region is also filled normally.
	rendered := strings.Replace(templateRendered,
		`assertGt(attacker.balance, preAttackerBalance, "no profit");`,
		`assertTrue(true);`, 1)
	rendered = strings.Replace(rendered,
		"// MODEL_BEGIN\n    // MODEL_END",
		"// MODEL_BEGIN\n    function attack() internal {}\n    // MODEL_END", 1)
	if err := CheckHarnessIntegrity(rendered, templateRendered); err == nil {
		t.Fatal("tampered assertion (suffix) was NOT caught")
	}
}

func TestHarnessIntegrity_TamperedSetupCaught(t *testing.T) {
	rendered := strings.Replace(templateRendered,
		"function setUp() public { vault = new Vault(); }",
		"function setUp() public { vault = new Vault(); vm.deal(attacker, 999 ether); }", 1)
	rendered = strings.Replace(rendered,
		"// MODEL_BEGIN\n    // MODEL_END",
		"// MODEL_BEGIN\n    function attack() internal {}\n    // MODEL_END", 1)
	if err := CheckHarnessIntegrity(rendered, templateRendered); err == nil {
		t.Fatal("tampered setUp (prefix) was NOT caught")
	}
}

func TestHarnessIntegrity_MissingMarkerRejected(t *testing.T) {
	if err := CheckHarnessIntegrity("no markers here", templateRendered); err == nil {
		t.Fatal("file with no markers should be rejected")
	}
}

func TestHarnessIntegrity_DuplicateMarkerRejected(t *testing.T) {
	dup := templateRendered + "\n// MODEL_BEGIN\n// MODEL_END"
	if err := CheckHarnessIntegrity(dup, templateRendered); err == nil {
		t.Fatal("file with duplicate markers should be rejected")
	}
}

func TestModelRegion_Extracts(t *testing.T) {
	rendered := strings.Replace(templateRendered,
		"// MODEL_BEGIN\n    // MODEL_END",
		"// MODEL_BEGIN\n    ATTACK_CODE_HERE\n    // MODEL_END", 1)
	region, err := ModelRegion(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(region, "ATTACK_CODE_HERE") {
		t.Fatalf("model region extraction wrong: %q", region)
	}
	if strings.Contains(region, "setUp") || strings.Contains(region, "assertGt") {
		t.Fatalf("model region leaked harness code: %q", region)
	}
}
