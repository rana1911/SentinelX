package hypothesize

import (
	"context"
	"errors"
	"testing"

	"github.com/rana1911/sentinelx/internal/agent"
)

type fakeCompleter struct {
	reply       string
	err         error
	gotJSONMode bool
}

func (f *fakeCompleter) Complete(_ context.Context, _ []agent.Message, _ float64, jsonMode bool) (string, error) {
	f.gotJSONMode = jsonMode
	return f.reply, f.err
}

func TestPropose_ParsesAndSanitizes(t *testing.T) {
	reply := "```json\n" + `{"hypotheses":[
      {"class":"Reentrancy","function":"withdraw","confidence":0.9},
      {"class":"made-up-class","contract":"Vault","function":"skim","confidence":1.7},
      {"class":"reentrancy","function":"withdraw","confidence":0.5},
      {"class":"access-control","function":"  ","confidence":0.8}
    ]}` + "\n```"
	h := New(&fakeCompleter{reply: reply})
	got, err := h.Propose(context.Background(), "Vault", "contract Vault {}")
	if err != nil {
		t.Fatal(err)
	}
	// 4 in -> drop empty-function, dedup the two reentrancy/withdraw -> 2 out.
	if len(got) != 2 {
		t.Fatalf("expected 2 hypotheses, got %d: %+v", len(got), got)
	}
	// Highest confidence first; unknown class coerced to generic; conf clamped.
	if got[0].Function != "skim" || got[0].Class != "generic" || got[0].Confidence != 1 {
		t.Errorf("first hypothesis wrong: %+v", got[0])
	}
	if got[1].Class != "reentrancy" || got[1].Contract != "Vault" {
		t.Errorf("second hypothesis wrong (class lowercased, contract defaulted): %+v", got[1])
	}
	if got[0].ID == "" || got[1].ID == "" {
		t.Error("IDs must be assigned")
	}
}

func TestPropose_RequestsJSONMode(t *testing.T) {
	f := &fakeCompleter{reply: `{"hypotheses":[]}`}
	New(f).Propose(context.Background(), "C", "contract C{}")
	if !f.gotJSONMode {
		t.Error("hypothesize should request JSON mode")
	}
}

func TestPropose_PropagatesModelError(t *testing.T) {
	h := New(&fakeCompleter{err: errors.New("api down")})
	if _, err := h.Propose(context.Background(), "C", "src"); err == nil {
		t.Fatal("expected error from model failure")
	}
}

func TestPropose_BadJSONIsError(t *testing.T) {
	h := New(&fakeCompleter{reply: "I think the withdraw function is reentrant."})
	if _, err := h.Propose(context.Background(), "C", "src"); err == nil {
		t.Fatal("expected parse error on non-JSON reply")
	}
}

func TestSanitize_CapsAndOrders(t *testing.T) {
	var in []agent.Hypothesis
	for i := 0; i < 20; i++ {
		in = append(in, agent.Hypothesis{Class: "reentrancy", Function: string(rune('a' + i)), Confidence: float64(i) / 20})
	}
	out := Sanitize(in, "C", 3)
	if len(out) != 3 {
		t.Fatalf("cap not applied: %d", len(out))
	}
	if !(out[0].Confidence >= out[1].Confidence && out[1].Confidence >= out[2].Confidence) {
		t.Error("not sorted by confidence desc")
	}
}

func TestSanitize_EmptyInput(t *testing.T) {
	if out := Sanitize(nil, "C", 5); len(out) != 0 {
		t.Errorf("expected empty, got %v", out)
	}
}
