package verify

import "testing"

func TestCheckSuccessPredicate(t *testing.T) {
	cases := []struct {
		name      string
		assertion string
		ok        bool
	}{
		{"profit", `assertGt(attacker.balance, preAttackerBalance, "no profit");`, true},
		{"drained", `assertLt(address(target).balance, preTargetBalance);`, true},
		{"takeover", `assertEq(target.owner(), attacker, "no takeover");`, true},
		{"empty", ``, false},
		{"trivial true", `assertTrue(true);`, false},
		{"trivial false", `assertFalse(false);`, false},
		{"not an assertion", `uint256 x = target.balanceOf(attacker);`, false},
		{"no state read", `assertGt(uint256(5), uint256(4));`, false},
		{"literals only", `assertEq(1, 1);`, false},
		{"self compare", `assertEq(target.owner(), target.owner());`, false},
		{"cheatcode smuggled", `assertEq(vm.load(address(target), 0), bytes32(uint256(uint160(attacker))));`, false},
		{"require form reading state", `require(attacker.balance > preAttackerBalance, "no profit");`, true},
	}
	for _, c := range cases {
		got := CheckSuccessPredicate(c.assertion)
		if got.OK != c.ok {
			t.Errorf("%s: CheckSuccessPredicate(%q).OK = %v (reason=%q), want %v", c.name, c.assertion, got.OK, got.Reason, c.ok)
		}
	}
}
