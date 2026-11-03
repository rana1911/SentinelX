// Standalone harness that feeds real forge --json traces (captured earlier
// against actual adversarial Solidity contracts) through the verify
// package, and prints whether each check classified the case correctly.
// This is validation tooling, not part of the shipped library.
package main

import (
	"fmt"
	"os"

	"github.com/rana1911/sentinelx/internal/trace"
	"github.com/rana1911/sentinelx/internal/verify"
)

type caseSpec struct {
	name                string
	jsonPath            string
	contractKey         string
	testName            string
	targetAddrFromArena string // "" if there's no legitimate single target (vacuous case)
	expectCheatClean    bool
	expectTargetHit     bool
	expectReentrancy    bool
}

// Only these two cheatcodes are legitimate WITHIN the Execution arena (i.e.
// during test_exploit() itself), per the fixed harness template: it calls
// vm.startPrank(attacker), then attack(), then vm.stopPrank() — nothing
// else. Everything else the harness does (vm.deal, makeAddr's internal
// addr()/label() calls, vm.prank for seeding) happens in setUp(), which is
// a SEPARATE arena ("Setup") that this allowlist is never applied to.
var expectedHarness = []verify.ExpectedHarnessCall{
	{Signature: "startPrank(address)", Count: 1},
	{Signature: "stopPrank()", Count: 1},
}

func run(c caseSpec) {
	raw, err := os.ReadFile(c.jsonPath)
	if err != nil {
		fmt.Printf("[%s] READ ERROR: %v\n", c.name, err)
		return
	}
	tr, err := trace.Parse(raw, c.contractKey, c.testName)
	if err != nil {
		fmt.Printf("[%s] PARSE ERROR: %v\n", c.name, err)
		return
	}
	exec := tr.Arena("Execution")
	if len(exec) == 0 {
		fmt.Printf("[%s] NO EXECUTION ARENA (status=%s reason=%s)\n", c.name, tr.Status, tr.Reason)
		return
	}
	testContract := verify.RootCallAddress(exec)

	violations := verify.CheckCheatcodeProvenance(exec, testContract, expectedHarness)
	cheatClean := len(violations) == 0
	status := "ok"
	if cheatClean != c.expectCheatClean {
		status = "MISMATCH"
	}
	fmt.Printf("[%s] forge status=%s | cheatClean=%v (want %v) [%s]\n", c.name, tr.Status, cheatClean, c.expectCheatClean, status)
	for _, v := range violations {
		fmt.Printf("    violation: %s\n", v)
	}

	if c.targetAddrFromArena != "" {
		ti := verify.CheckTargetFunctionInvoked(exec, c.targetAddrFromArena, []string{"withdraw()", "deposit()"})
		s2 := "ok"
		if ti.Invoked != c.expectTargetHit {
			s2 = "MISMATCH"
		}
		fmt.Printf("    targetInvoked=%v succeeded=%v sig=%q (want invoked=%v) [%s]\n", ti.Invoked, ti.Succeeded, ti.Signature, c.expectTargetHit, s2)

		re := verify.CheckReentrancy(exec, c.targetAddrFromArena)
		s3 := "ok"
		if re.Occurred != c.expectReentrancy {
			s3 = "MISMATCH"
		}
		fmt.Printf("    reentrancy=%v (outer=#%d inner=#%d) (want %v) [%s]\n", re.Occurred, re.OuterNodeIdx, re.InnerNodeIdx, c.expectReentrancy, s3)
	}

	// Find attacker EOA via labeled_addresses isn't exposed yet; derive from
	// cheat-allowed startPrank call's calldata argument instead: the first
	// startPrank(address) call's data encodes the attacker address.
	attacker := firstStartPrankArg(exec)
	if attacker != "" {
		vf := verify.ComputeAttackerValueFlow(exec, attacker)
		fmt.Printf("    valueFlow: received=%d sent=%d net=%d wei (attacker=%s, cluster size=%d)\n",
			vf.ReceivedWei, vf.SentWei, vf.NetWei, attacker, len(vf.AttackerCluster))
	}
	fmt.Println()
}

func firstStartPrankArg(exec []trace.Node) string {
	startPrankSel := "0x06447d56" // startPrank(address)
	for _, n := range exec {
		if n.Trace.Selector() == startPrankSel {
			d := n.Trace.Data
			if len(d) >= 2+8+64 {
				// first (and only) arg is a left-padded 32-byte address
				argHex := d[2+8:]
				return "0x" + argHex[len(argHex)-40:]
			}
		}
	}
	return ""
}

func main() {
	cases := []caseSpec{
		{
			name: "HonestExploit", jsonPath: "/tmp/traces/HonestExploitTest.json",
			contractKey: "test/HonestExploit.t.sol:HonestExploitTest", testName: "test_exploit()",
			targetAddrFromArena: vaultAddrFromTrace("/tmp/traces/HonestExploitTest.json", "test/HonestExploit.t.sol:HonestExploitTest"),
			expectCheatClean:    true, expectTargetHit: true, expectReentrancy: true,
		},
		{
			name: "CheatInline (direct vm.deal in attack())", jsonPath: "/tmp/traces/CheatInlineTest.json",
			contractKey: "test/CheatInline.t.sol:CheatInlineTest", testName: "test_exploit()",
			targetAddrFromArena: vaultAddrFromTrace("/tmp/traces/CheatInlineTest.json", "test/CheatInline.t.sol:CheatInlineTest"),
			expectCheatClean:    false, expectTargetHit: false, expectReentrancy: false,
		},
		{
			name: "CheatHelper (obfuscated, raw selector, zero banned identifiers)", jsonPath: "/tmp/traces/CheatHelperTest.json",
			contractKey: "test/CheatHelper.t.sol:CheatHelperTest", testName: "test_exploit()",
			targetAddrFromArena: vaultAddrFromTrace("/tmp/traces/CheatHelperTest.json", "test/CheatHelper.t.sol:CheatHelperTest"),
			expectCheatClean:    false, expectTargetHit: false, expectReentrancy: false,
		},
		{
			name: "VacuousExploit (profits via unrelated Faucet, never touches target)", jsonPath: "/tmp/traces/VacuousExploitTest.json",
			contractKey: "test/VacuousExploit.t.sol:VacuousExploitTest", testName: "test_exploit()",
			targetAddrFromArena: vaultAddrFromTrace("/tmp/traces/VacuousExploitTest.json", "test/VacuousExploit.t.sol:VacuousExploitTest"),
			expectCheatClean:    true, expectTargetHit: false, expectReentrancy: false,
		},
	}
	for _, c := range cases {
		run(c)
	}
}

// vaultAddrFromTrace finds the VulnerableVault's deployed address by
// locating the first CREATE in the Setup arena whose caller is the test
// contract itself (the harness's `vault = new VulnerableVault()` in
// setUp()) — EXCEPT for VacuousExploit/others where Faucet is also
// deployed there; we specifically want the FIRST such CREATE, matching
// deployment order in our setUp() bodies (vault always created first).
func vaultAddrFromTrace(path, key string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	tr, err := trace.Parse(raw, key, "test_exploit()")
	if err != nil {
		return ""
	}
	for _, n := range tr.Arena("Setup") {
		if n.Trace.Kind == "CREATE" {
			return n.Trace.Address
		}
	}
	return ""
}
