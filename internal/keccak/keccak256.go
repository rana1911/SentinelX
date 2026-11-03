// Package keccak is a small, self-contained, dependency-free implementation
// of Keccak-256 (the ORIGINAL Keccak padding, as used by Ethereum — NOT
// NIST SHA3-256, which uses different padding and would give wrong function
// selectors). It exists so internal/verify can compute 4-byte function
// selectors (keccak256(signature)[:4]) to decode cheatcode and target-contract
// calls from real forge trace calldata, without depending on
// golang.org/x/crypto (whose module proxy is unreachable in some sandboxed
// build environments — this package has zero external dependencies).
package keccak

const rounds = 24

var rc = [rounds]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rotc = [25]uint{
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
	41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
}

// pi lane permutation: tmp[piIdx[src]] = rotl(st[src], rotc[src]).
// For state position (x,y) (flattened x+5y), pi moves it to
// (x',y') = (y, (2x+3y) mod 5). Verified against known-answer test vectors
// and well-known Solidity function selectors (see keccak256_test.go) — an
// earlier draft of this table was wrong and silently produced incorrect
// hashes, so DO NOT edit this without re-running those tests.
var piIdx = [25]int{
	0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22,
	23, 8, 18, 3, 13, 14, 24, 9, 19, 4,
}

func rotl64(x uint64, n uint) uint64 {
	if n == 0 {
		return x
	}
	return (x << n) | (x >> (64 - n))
}

func keccakF1600(st *[25]uint64) {
	for r := 0; r < rounds; r++ {
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20]
		}
		var d [5]uint64
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
		}
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				st[x+5*y] ^= d[x]
			}
		}

		var tmp [25]uint64
		for i := 0; i < 25; i++ {
			tmp[piIdx[i]] = rotl64(st[i], rotc[i])
		}

		for y := 0; y < 5; y++ {
			var row [5]uint64
			for x := 0; x < 5; x++ {
				row[x] = tmp[x+5*y]
			}
			for x := 0; x < 5; x++ {
				st[x+5*y] = row[x] ^ ((^row[(x+1)%5]) & row[(x+2)%5])
			}
		}

		st[0] ^= rc[r]
	}
}

// Sum256 returns the Keccak-256 digest (Ethereum's variant: 0x01 padding).
func Sum256(data []byte) [32]byte {
	const rateBytes = 136
	var st [25]uint64

	for len(data) >= rateBytes {
		absorbBlock(&st, data[:rateBytes])
		data = data[rateBytes:]
		keccakF1600(&st)
	}
	var block [rateBytes]byte
	copy(block[:], data)
	block[len(data)] ^= 0x01
	block[rateBytes-1] ^= 0x80
	absorbBlock(&st, block[:])
	keccakF1600(&st)

	var out [32]byte
	for i := 0; i < 4; i++ {
		putLE64(out[i*8:], st[i])
	}
	return out
}

func absorbBlock(st *[25]uint64, block []byte) {
	for i := 0; i*8 < len(block); i++ {
		st[i] ^= getLE64(block[i*8:])
	}
}

func getLE64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

func putLE64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
}

// Selector returns the 4-byte Ethereum function selector for a Solidity
// function signature, e.g. Selector("startPrank(address)").
func Selector(signature string) [4]byte {
	h := Sum256([]byte(signature))
	var sel [4]byte
	copy(sel[:], h[:4])
	return sel
}

// SelectorHex is Selector formatted as "0xdeadbeef".
func SelectorHex(signature string) string {
	s := Selector(signature)
	const hexd = "0123456789abcdef"
	out := make([]byte, 10)
	out[0], out[1] = '0', 'x'
	for i, b := range s {
		out[2+i*2] = hexd[b>>4]
		out[3+i*2] = hexd[b&0xf]
	}
	return string(out)
}
