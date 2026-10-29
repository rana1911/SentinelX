package keccak

import (
	"encoding/hex"
	"testing"
)

func TestSum256_KnownVectors(t *testing.T) {
	cases := []struct{ input, wantHex string }{
		{"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
	}
	for _, c := range cases {
		got := Sum256([]byte(c.input))
		if gotHex := hex.EncodeToString(got[:]); gotHex != c.wantHex {
			t.Errorf("Sum256(%q) = %s, want %s", c.input, gotHex, c.wantHex)
		}
	}
}

func TestSelector_KnownSolidityFunctions(t *testing.T) {
	cases := []struct{ sig, want string }{
		{"transfer(address,uint256)", "0xa9059cbb"},
		{"approve(address,uint256)", "0x095ea7b3"},
		{"balanceOf(address)", "0x70a08231"},
		{"startPrank(address)", "0x06447d56"},
		{"stopPrank()", "0x90c5013b"},
		{"deal(address,uint256)", "0xc88a5e6d"},
		{"withdraw()", "0x3ccfd60b"},
		{"deposit()", "0xd0e30db0"},
	}
	for _, c := range cases {
		if got := SelectorHex(c.sig); got != c.want {
			t.Errorf("Selector(%q) = %s, want %s", c.sig, got, c.want)
		}
	}
}
