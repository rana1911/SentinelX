package verify

import "testing"

func TestCheckSource(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		dirty bool
	}{
		{"clean reentrancy", `function attack() internal { IVault(V).deposit{value: 1}(); IVault(V).withdraw(1); }`, false},
		{"vm.store", `function attack() internal { vm.store(V, 0, bytes32(0)); }`, true},
		{"bare deal via StdCheats", `function attack() internal { deal(attacker, 1000 ether); }`, true},
		{"vm.deal", `vm.deal(address(this), 1e30);`, true},
		{"raw cheatcode address", `address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D).call("");`, true},
		{"obfuscated hevm string", `address(uint160(uint256(keccak256("hevm cheat code"))))`, true},
		{"banned word only in comment", "// we do not use vm.store here\nfunction attack() internal {}", false},
		{"banned word only in string", `string memory s = "vm.deal"; `, false},
		{"inherits Test", `contract Helper is Test { }`, true},
		{"asm sstore", `assembly { sstore(0, 1) }`, true},
	}
	for _, c := range cases {
		got := CheckSource(c.src)
		if (len(got) > 0) != c.dirty {
			t.Errorf("%s: dirty=%v want %v (violations: %v)", c.name, len(got) > 0, c.dirty, got)
		}
	}
}

func TestCheckTrace(t *testing.T) {
	allowed := map[string]int{"createSelectFork": 1, "deal": 1, "startPrank": 1, "stopPrank": 1, "addr": 1, "label": 1}
	ok := "[0] VM::createSelectFork(...)\n[0] VM::deal(attacker, 1)\n[0] VM::startPrank(attacker)\n[0] VM::stopPrank()"
	if v := CheckTrace(ok, allowed); len(v) != 0 {
		t.Fatalf("expected clean, got %v", v)
	}
	bad := ok + "\n[0] VM::store(0xabc, 0x0, 0x1)"
	if v := CheckTrace(bad, allowed); len(v) != 1 {
		t.Fatalf("expected store flagged, got %v", v)
	}
	twice := ok + "\n[0] VM::deal(attacker, 1000000)"
	if v := CheckTrace(twice, allowed); len(v) != 1 {
		t.Fatalf("expected second deal flagged, got %v", v)
	}
}

func TestTrimOutput(t *testing.T) {
	s := ""
	for i := 0; i < 100; i++ {
		s += "line\n"
	}
	if out := TrimOutput(s, 10); len(out) >= len(s) {
		t.Fatal("not trimmed")
	}
}

func TestCheckMemberShadowing(t *testing.T) {
	bad := `function attack() internal { target.withdraw(); }
    function assertGt(uint256, uint256, string memory) internal pure override {}`
	if v := CheckMemberShadowing(bad); len(v) == 0 {
		t.Fatal("assertion override must be rejected")
	}
	if v := CheckMemberShadowing("function test_other() public {}"); len(v) == 0 {
		t.Fatal("extra test entry point must be rejected")
	}
	ok := `function attack() internal {
        // we do not override anything here
        Drainer d = new Drainer(target); d.run();
    }`
	if v := CheckMemberShadowing(ok); len(v) != 0 {
		t.Fatalf("honest members flagged: %v", v)
	}
}
