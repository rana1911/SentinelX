// Mechanism checks tie a passing test to the SPECIFIC claim a hypothesis
// makes, computed from the actual call trace — not merely "some assertion
// in Solidity returned true." This closes the gap that a cheatcode-free,
// passing exploit can still prove nothing about the claimed vulnerability
// (see VacuousExploit in the adversarial test suite): the exploit must be
// shown to have actually touched the target contract's claimed function,
// and, for reentrancy specifically, to have actually re-entered it.
package verify

import (
	"fmt"

	"github.com/rana1911/exploitforge/internal/keccak"
	"github.com/rana1911/exploitforge/internal/trace"
)

// TargetInvocation is evidence that the exploit actually called the
// contract/function the hypothesis claims is vulnerable.
type TargetInvocation struct {
	Invoked   bool
	Succeeded bool
	NodeIdx   int
	Signature string // which candidate signature matched
}

// CheckTargetFunctionInvoked requires that somewhere in the Execution
// arena, a CALL was made to targetAddr whose selector matches one of
// candidateSignatures (the hypothesis's claimed function, in every
// overload/signature form the ingestion stage knows about for it — e.g.
// ["withdraw()"] or ["transferFrom(address,address,uint256)"]). Without
// this, "the assertion passed" could mean the exploit profited through any
// unrelated path (see internal_test.go's VacuousExploit case) and the
// verdict would be wrongly attributed to this hypothesis's target function.
func CheckTargetFunctionInvoked(execArena []trace.Node, targetAddr string, candidateSignatures []string) TargetInvocation {
	wanted := make(map[string]string, len(candidateSignatures))
	for _, sig := range candidateSignatures {
		wanted[keccak.SelectorHex(sig)] = sig
	}
	for _, node := range execArena {
		c := node.Trace
		if !trace.SameAddress(c.Address, targetAddr) {
			continue
		}
		if c.Kind != "CALL" && c.Kind != "STATICCALL" {
			continue
		}
		if sig, ok := wanted[c.Selector()]; ok {
			return TargetInvocation{Invoked: true, Succeeded: c.Success, NodeIdx: node.Idx, Signature: sig}
		}
	}
	return TargetInvocation{Invoked: false}
}

// ReentrancyEvidence is proof (or disproof) that the target contract was
// actually re-entered — i.e. called again while an earlier, still-open
// call into it had not yet returned — as opposed to merely being called
// twice in sequence, which is not reentrancy.
type ReentrancyEvidence struct {
	Occurred     bool
	OuterNodeIdx int
	InnerNodeIdx int
}

// CheckReentrancy walks the Execution call TREE (using each node's Parent
// link, not just its position in the flat list) looking for a call into
// targetAddr that has an ANCESTOR which is also a call into targetAddr.
// That parent/child nesting relationship — not merely "target appears
// twice" — is what reentrancy actually is, and it's exactly what a
// positional/textual trace scan cannot reliably distinguish from two
// separate top-level calls.
func CheckReentrancy(execArena []trace.Node, targetAddr string) ReentrancyEvidence {
	byIdx := make(map[int]trace.Node, len(execArena))
	for _, n := range execArena {
		byIdx[n.Idx] = n
	}
	for _, n := range execArena {
		if !trace.SameAddress(n.Trace.Address, targetAddr) {
			continue
		}
		// Walk up the parent chain looking for another call into target.
		cur := n.Parent
		for cur != nil {
			anc, ok := byIdx[*cur]
			if !ok {
				break
			}
			if trace.SameAddress(anc.Trace.Address, targetAddr) {
				return ReentrancyEvidence{Occurred: true, OuterNodeIdx: anc.Idx, InnerNodeIdx: n.Idx}
			}
			cur = anc.Parent
		}
	}
	return ReentrancyEvidence{Occurred: false}
}

// ValueFlow is a trace-only (not Solidity-assertion-dependent) measurement
// of net ETH the attacker-controlled address cluster gained during
// test_exploit(). It is deliberately computed independently of whatever
// the harness's own `assertGt(...)` checks, as a second opinion: if the
// Solidity assertion were itself buggy or gameable, this still only counts
// ETH that actually moved via CALL value during execution.
type ValueFlow struct {
	NetWei          uint64
	ReceivedWei     uint64
	SentWei         uint64
	AttackerCluster []string // attacker EOA plus every contract it (transitively) deployed
}

// ComputeAttackerValueFlow expands attackerEOA into its full "cluster" (any
// address CREATEd, directly or transitively, by an address already in the
// cluster — i.e. attacker-deployed helper contracts), then nets every CALL
// value sent to vs. from cluster addresses during Execution.
func ComputeAttackerValueFlow(execArena []trace.Node, attackerEOA string) ValueFlow {
	cluster := map[string]bool{normalizeAddr(attackerEOA): true}
	// CREATEs can appear before their deployer is known to be in the
	// cluster if ordering is adversarial in some edge case, so fixed-point
	// over a few passes rather than assuming single-pass order suffices.
	for pass := 0; pass < 4; pass++ {
		changed := false
		for _, n := range execArena {
			if n.Trace.Kind != "CREATE" && n.Trace.Kind != "CREATE2" {
				continue
			}
			if cluster[normalizeAddr(n.Trace.Caller)] && !cluster[normalizeAddr(n.Trace.Address)] {
				cluster[normalizeAddr(n.Trace.Address)] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	var received, sent uint64
	for _, n := range execArena {
		v, overflowed := n.Trace.ValueWei()
		if overflowed || v == 0 {
			continue
		}
		if cluster[normalizeAddr(n.Trace.Address)] {
			received += v
		}
		if cluster[normalizeAddr(n.Trace.Caller)] {
			sent += v
		}
	}

	addrs := make([]string, 0, len(cluster))
	for a := range cluster {
		addrs = append(addrs, a)
	}
	var net uint64
	if received > sent {
		net = received - sent
	}
	return ValueFlow{NetWei: net, ReceivedWei: received, SentWei: sent, AttackerCluster: addrs}
}

func normalizeAddr(a string) string {
	return fmt.Sprintf("%040s", trimPrefixLower(a))
}

func trimPrefixLower(a string) string {
	if len(a) >= 2 && a[0:2] == "0x" {
		a = a[2:]
	}
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		b := a[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		out[i] = b
	}
	return string(out)
}
