package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rana1911/exploitforge/internal/agent"
	"github.com/rana1911/exploitforge/internal/runner"
)

// fakeSpark returns canned completions in order, then repeats the last one.
type fakeSpark struct {
	replies []string
	err     error
	calls   int
}

func (f *fakeSpark) Complete(ctx context.Context, msgs []agent.Message, temp float64, jsonMode bool) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	i := f.calls - 1
	if i >= len(f.replies) {
		i = len(f.replies) - 1
	}
	return f.replies[i], nil
}

// fakeRunner returns canned RunResults in order, then repeats the last.
type fakeRunner struct {
	results []runner.RunResult
	calls   int
}

func (f *fakeRunner) Run(ctx context.Context, modelCode string) runner.RunResult {
	f.calls++
	i := f.calls - 1
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	return f.results[i]
}

func minimalTask() ExploitTask {
	return ExploitTask{
		Hypothesis:     agent.Hypothesis{ID: "H1", Class: "reentrancy", Contract: "Vault", Function: "withdraw"},
		ContractSrc:    "contract Vault {}",
		Class:          "reentrancy",
		TemplateRender: "// MODEL_BEGIN\n// MODEL_END",
	}
}

func TestLoop_SparkErrorIsInconclusive(t *testing.T) {
	l := New(&fakeSpark{err: errors.New("api down")}, &fakeRunner{results: []runner.RunResult{{}}})
	res := l.Execute(context.Background(), minimalTask())
	if res.Verdict != Inconclusive {
		t.Fatalf("expected Inconclusive, got %s", res.Verdict)
	}
}

func TestLoop_InfraErrorIsInconclusive(t *testing.T) {
	l := New(
		&fakeSpark{replies: []string{"function attack() internal {}"}},
		&fakeRunner{results: []runner.RunResult{{InfraErr: errors.New("docker exploded")}}},
	)
	res := l.Execute(context.Background(), minimalTask())
	if res.Verdict != Inconclusive {
		t.Fatalf("expected Inconclusive on infra error, got %s (%s)", res.Verdict, res.Reason)
	}
}

func TestLoop_SourceCheatRejectedThenExhausts(t *testing.T) {
	// Spark keeps returning cheating code; the source pre-filter keeps
	// rejecting it, and after MaxAttempts the verdict is Rejected. The
	// runner should never be called, since source rejection happens first.
	fr := &fakeRunner{results: []runner.RunResult{{}}}
	l := New(&fakeSpark{replies: []string{"function attack() internal { vm.deal(attacker, 1 ether); }"}}, fr)
	l.MaxAttempts = 3
	res := l.Execute(context.Background(), minimalTask())
	if res.Verdict != Rejected {
		t.Fatalf("expected Rejected, got %s", res.Verdict)
	}
	if fr.calls != 0 {
		t.Fatalf("runner should not run source-rejected code, but ran %d times", fr.calls)
	}
	if len(res.Attempts) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(res.Attempts))
	}
	for _, a := range res.Attempts {
		if a.Stage != "source-cheat" {
			t.Fatalf("expected every attempt to be source-cheat, got %q", a.Stage)
		}
	}
}

func TestLoop_CompileFailureRetries(t *testing.T) {
	fr := &fakeRunner{results: []runner.RunResult{
		{Compiled: false, CompileErr: "Error (1234): undeclared"},
	}}
	l := New(&fakeSpark{replies: []string{"function attack() internal { brokenCode }"}}, fr)
	l.MaxAttempts = 2
	res := l.Execute(context.Background(), minimalTask())
	if res.Verdict != Rejected {
		t.Fatalf("expected Rejected after repeated compile failures, got %s", res.Verdict)
	}
	if fr.calls != 2 {
		t.Fatalf("expected runner called twice (once per attempt), got %d", fr.calls)
	}
	for _, a := range res.Attempts {
		if a.Stage != "compile" {
			t.Fatalf("expected compile stage, got %q", a.Stage)
		}
	}
}

func TestLoop_HarnessTamperRejected(t *testing.T) {
	// Rendered file whose fixed prefix differs from the template render ->
	// integrity check fails -> retry.
	fr := &fakeRunner{results: []runner.RunResult{
		{Compiled: true, Rendered: "TAMPERED PREFIX\n// MODEL_BEGIN\nx\n// MODEL_END"},
	}}
	l := New(&fakeSpark{replies: []string{"function attack() internal {}"}}, fr)
	l.MaxAttempts = 2
	task := minimalTask()
	task.TemplateRender = "CLEAN PREFIX\n// MODEL_BEGIN\n// MODEL_END"
	res := l.Execute(context.Background(), task)
	if res.Verdict != Rejected {
		t.Fatalf("expected Rejected on harness tamper, got %s", res.Verdict)
	}
	if len(res.Attempts) == 0 || res.Attempts[0].Stage != "rejected" {
		t.Fatalf("expected first attempt stage 'rejected', got %+v", res.Attempts)
	}
}

func TestCheatRetryPrompt_MentionsViolations(t *testing.T) {
	p := cheatRetryPrompt([]string{`banned identifier "vm"`})
	if !strings.Contains(p, "vm") {
		t.Fatal("expected violation echoed back into retry prompt")
	}
}

func TestBuildExploitUserPrompt_IncludesHypothesisFields(t *testing.T) {
	h := agent.Hypothesis{Class: "reentrancy", Contract: "Vault", Function: "withdraw", SuccessMetric: "balance increases"}
	p := buildExploitUserPrompt(h, "contract Vault {}")
	for _, want := range []string{"reentrancy", "Vault", "withdraw", "balance increases"} {
		if !strings.Contains(p, want) {
			t.Fatalf("prompt missing %q:\n%s", want, p)
		}
	}
}
