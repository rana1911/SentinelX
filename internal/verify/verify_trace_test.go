package verify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rana1911/sentinelx/internal/trace"
)

// These tests run against REAL `forge test --json -vvvv` output captured
// from actual adversarial Solidity contracts (see testdata/*.json). They
// need no forge/solc installed — the fixtures are checked in — so the
// anti-cheat logic is validated deterministically in CI.
//
// The four fixtures correspond to:
//   honest_exploit          — a real reentrancy drain (control: must pass all)
//   cheat_inline            — attack() calls vm.deal directly (same contract)
//   cheat_helper_obfuscated — cheatcode via raw calldata from a helper contract,
//                             with ZERO banned identifiers in the model's source
//   vacuous_exploit         — profits via an unrelated contract, never touching
//                             the claimed target (cheatcode-free but meaningless)

// execArenaFromFixture loads a fixture and returns its Execution arena plus
// the test-contract address.
func execArenaFromFixture(t *testing.T, name, contractKey string) ([]trace.Node, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	tr, err := trace.Parse(raw, contractKey, "test_exploit()")
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	exec := tr.Arena("Execution")
	if len(exec) == 0 {
		t.Fatalf("fixture %s has empty Execution arena", name)
	}
	return exec, RootCallAddress(exec)
}

// setupVaultAddr finds the VulnerableVault address (first CREATE in Setup).
func setupVaultAddr(t *testing.T, name, contractKey string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	tr, err := trace.Parse(raw, contractKey, "test_exploit()")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, n := range tr.Arena("Setup") {
		if n.Trace.Kind == "CREATE" {
			return n.Trace.Address
		}
	}
	t.Fatalf("no CREATE in Setup arena of %s", name)
	return ""
}

// harnessExecCalls: only startPrank/stopPrank are legitimate within the
// Execution arena per the fixed harness template.
var harnessExecCalls = []ExpectedHarnessCall{
	{Signature: "startPrank(address)", Count: 1},
	{Signature: "stopPrank()", Count: 1},
}

func TestProvenance_HonestExploitIsClean(t *testing.T) {
	exec, testAddr := execArenaFromFixture(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest")
	v := CheckCheatcodeProvenance(exec, testAddr, harnessExecCalls)
	if len(v) != 0 {
		t.Fatalf("honest exploit flagged as cheating: %v", v)
	}
}

func TestProvenance_InlineCheatCaught(t *testing.T) {
	exec, testAddr := execArenaFromFixture(t, "cheat_inline.json", "test/CheatInline.t.sol:CheatInlineTest")
	v := CheckCheatcodeProvenance(exec, testAddr, harnessExecCalls)
	if len(v) == 0 {
		t.Fatal("inline vm.deal in attack() was NOT caught")
	}
	// It should be flagged as an extra call from the test contract itself.
	found := false
	for _, viol := range v {
		if viol.KnownName == "deal(address,uint256)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a deal() violation, got: %v", v)
	}
}

func TestProvenance_ObfuscatedCheatCaught(t *testing.T) {
	// THE key case: the model's source has zero banned identifiers — a
	// regex scan is structurally blind to it — but the trace shows a
	// cheatcode call from a model-deployed helper contract.
	exec, testAddr := execArenaFromFixture(t, "cheat_helper_obfuscated.json", "test/CheatHelper.t.sol:CheatHelperTest")
	v := CheckCheatcodeProvenance(exec, testAddr, harnessExecCalls)
	if len(v) == 0 {
		t.Fatal("OBFUSCATED cheatcode call (raw calldata from helper) was NOT caught — this is the case source scanning cannot see")
	}
	// And confirm the source scan genuinely CANNOT see it, to prove the
	// trace check is doing load-bearing work: the model region here is the
	// SneakyHelper contract body with no vm/deal/cheat tokens.
	modelCode := `SneakyHelper h = new SneakyHelper();
h.pretendToBeNormal(attacker);
}
contract SneakyHelper {
    uint160 internal constant PART_A = 97433442488726861213578988847752201310395502865;
    uint160 internal constant PART_B = 548606830732011412036458774667846263564405620796;
    function pretendToBeNormal(address who) external {
        address target = address(PART_A ^ PART_B);
        bytes4 sig = bytes4(0xc88a5e6d);
        (bool ok, ) = target.call(abi.encodeWithSelector(sig, who, uint256(1000 ether)));
        require(ok, "call failed");
    }`
	if src := CheckSource(modelCode); len(src) != 0 {
		t.Fatalf("expected source scan to find NOTHING in obfuscated code (proving trace check is necessary), but it flagged: %v", src)
	}
}

func TestProvenance_VacuousExploitIsCheatClean(t *testing.T) {
	// Vacuous exploit uses no cheatcodes, so provenance is correctly clean.
	// It must be rejected by the TARGET-INVOCATION check instead.
	exec, testAddr := execArenaFromFixture(t, "vacuous_exploit.json", "test/VacuousExploit.t.sol:VacuousExploitTest")
	v := CheckCheatcodeProvenance(exec, testAddr, harnessExecCalls)
	if len(v) != 0 {
		t.Fatalf("vacuous exploit uses no cheatcodes but was flagged: %v", v)
	}
}

func TestTargetInvocation_HonestHitsTarget(t *testing.T) {
	exec, _ := execArenaFromFixture(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest")
	vault := setupVaultAddr(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest")
	ti := CheckTargetFunctionInvoked(exec, vault, []string{"withdraw()", "deposit()"})
	if !ti.Invoked {
		t.Fatal("honest exploit did not register as invoking the target")
	}
}

func TestTargetInvocation_VacuousMissesTarget(t *testing.T) {
	// THE case for gaps #4/#5: cheatcode-free, test passes, but the claimed
	// target function is never called. Must be caught here.
	exec, _ := execArenaFromFixture(t, "vacuous_exploit.json", "test/VacuousExploit.t.sol:VacuousExploitTest")
	vault := setupVaultAddr(t, "vacuous_exploit.json", "test/VacuousExploit.t.sol:VacuousExploitTest")
	ti := CheckTargetFunctionInvoked(exec, vault, []string{"withdraw()", "deposit()"})
	if ti.Invoked {
		t.Fatal("vacuous exploit falsely registered as invoking the target (it only touched an unrelated Faucet)")
	}
}

func TestReentrancy_OnlyHonestReentered(t *testing.T) {
	// Honest exploit genuinely re-enters withdraw(); vacuous does not.
	hExec, _ := execArenaFromFixture(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest")
	hVault := setupVaultAddr(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest")
	if re := CheckReentrancy(hExec, hVault); !re.Occurred {
		t.Fatal("honest reentrancy exploit did not register re-entry")
	}

	vExec, _ := execArenaFromFixture(t, "vacuous_exploit.json", "test/VacuousExploit.t.sol:VacuousExploitTest")
	vVault := setupVaultAddr(t, "vacuous_exploit.json", "test/VacuousExploit.t.sol:VacuousExploitTest")
	if re := CheckReentrancy(vExec, vVault); re.Occurred {
		t.Fatal("vacuous exploit falsely registered re-entry into the target")
	}
}

func TestValueFlow_HonestAttackerProfited(t *testing.T) {
	exec, _ := execArenaFromFixture(t, "honest_exploit.json", "test/HonestExploit.t.sol:HonestExploitTest")
	// attacker EOA is the arg to the single startPrank in Execution.
	attacker := firstStartPrankArg(exec)
	if attacker == "" {
		t.Fatal("could not locate attacker address from startPrank calldata")
	}
	vf := ComputeAttackerValueFlow(exec, attacker)
	if vf.NetWei == 0 {
		t.Fatalf("expected positive net value flow for honest exploit, got %+v", vf)
	}
}

func firstStartPrankArg(exec []trace.Node) string {
	const startPrankSel = "0x06447d56"
	for _, n := range exec {
		if n.Trace.Selector() == startPrankSel {
			d := n.Trace.Data
			if len(d) >= 2+8+64 {
				argHex := d[2+8:]
				return "0x" + argHex[len(argHex)-40:]
			}
		}
	}
	return ""
}
