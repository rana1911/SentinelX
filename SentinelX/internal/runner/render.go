// Package runner is the machine that actually executes an exploit: it
// renders the fixed harness around the model's attack code, runs
// `forge test --json -vvvv` (in a sandbox, in production), and returns the
// parsed structured result for the verdict engine. This is the step that
// was previously done by hand.
package runner

import (
	"fmt"
	"strings"
)

// Mode selects how the target contract is acquired in setUp().
type Mode int

const (
	// ModeFork pins a fork of a live chain and uses the target at its real
	// deployed address (the primary auditing mode). Requires RPC_URL in env.
	ModeFork Mode = iota
	// ModeLocalDeploy deploys the target from source inside the test (no RPC
	// needed) — used for self-contained testing and for contracts that are
	// not yet deployed.
	ModeLocalDeploy
)

// Config is everything the harness needs that is NOT the model's attack
// code. In production most of this comes from the ingestion stage; for
// testing it is supplied directly.
type Config struct {
	Mode Mode

	// Imports rendered verbatim after the forge-std import, e.g.
	// `import "../src/VulnerableVault.sol";` or an interface import.
	Imports string

	// TargetDecl is the state var declaration the rest of the harness/model
	// refers to, e.g. `VulnerableVault internal target;` (local-deploy) or
	// `address internal constant TARGET = 0xabc...;` (fork).
	TargetDecl string

	// TargetSetup is the body that acquires the target inside setUp(), e.g.
	// a `vm.createSelectFork(...)` (fork) or `target = new X(); <seed>;`
	// (local-deploy). It runs BEFORE the attacker is funded.
	TargetSetup string

	// StartBalanceWei is the attacker's starting ETH, as a Solidity literal
	// (e.g. "1 ether").
	StartBalanceWei string

	// SuccessAssertion is the single harness-owned assertion line — the
	// model never writes this. e.g.
	// `assertGt(attacker.balance, preAttackerBalance, "no profit");`
	SuccessAssertion string
}

// harnessTemplate is the fixed structure. Only {{ModelCode}} varies between
// a real render and the empty-region render used for integrity checking;
// every other field is identical across those two, so the integrity check
// (prefix/suffix byte-equality) holds regardless of Config.
const harnessTemplate = `// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
%s

contract ExploitTest is Test {
    address internal attacker;
    uint256 internal constant START_BALANCE = %s;
    uint256 internal preAttackerBalance;
    uint256 internal preTargetBalance;
    %s

    function setUp() public {
        %s
        preTargetBalance = address(target).balance;
        attacker = makeAddr("attacker");
        vm.deal(attacker, START_BALANCE);
        preAttackerBalance = attacker.balance;
    }

    function test_exploit() public {
        vm.startPrank(attacker);
        attack();
        vm.stopPrank();
        %s
    }

    // MODEL_BEGIN
%s
    // MODEL_END
}
`

// Render produces the full test file: the fixed harness with modelCode
// inserted into the MODEL region. Passing an empty modelCode yields the
// canonical "template render" that CheckHarnessIntegrity compares against.
func (c Config) Render(modelCode string) string {
	return fmt.Sprintf(harnessTemplate,
		c.Imports,
		c.StartBalanceWei,
		c.TargetDecl,
		c.TargetSetup,
		c.SuccessAssertion,
		modelCode,
	)
}

// TemplateRender is the empty-model-region render, for integrity comparison.
func (c Config) TemplateRender() string {
	return c.Render("")
}

// ContractKey is the key forge uses in its --json output for this test file,
// given the path the runner writes it to (e.g.
// "test/Exploit.t.sol:ExploitTest").
func ContractKey(testPath string) string {
	return testPath + ":ExploitTest"
}

// Validate catches obvious misconfiguration before we spend a forge run.
func (c Config) Validate() error {
	if strings.TrimSpace(c.StartBalanceWei) == "" {
		return fmt.Errorf("runner: Config.StartBalanceWei is required")
	}
	if strings.TrimSpace(c.SuccessAssertion) == "" {
		return fmt.Errorf("runner: Config.SuccessAssertion is required")
	}
	if strings.TrimSpace(c.TargetSetup) == "" {
		return fmt.Errorf("runner: Config.TargetSetup is required")
	}
	return nil
}
