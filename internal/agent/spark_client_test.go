package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestComplete_RetriesOn500ThenSucceeds(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":{"message":"overloaded"}}`))
			return
		}
		writeChat(w, "```solidity\nfunction attack() internal {}\n```")
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, APIKey: "k", Model: "muse-spark", HTTP: srv.Client(), MaxRetries: 4}
	// speed up the test: real backoff starts at 1s; shrink by overriding via
	// a tiny context deadline check only — backoff itself isn't parameterized,
	// so we just allow enough wall time here.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := c.Complete(ctx, []Message{{Role: "user", Content: "hi"}}, 0.2, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls (2 failures + 1 success), got %d", calls)
	}
	if ExtractCode(out) != "function attack() internal {}" {
		t.Fatalf("unexpected extracted code: %q", ExtractCode(out))
	}
}

func TestComplete_NonRetryableFailsFast(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"bad key"}}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, APIKey: "bad", Model: "m", HTTP: srv.Client(), MaxRetries: 4}
	_, err := c.Complete(context.Background(), []Message{{Role: "user", Content: "hi"}}, 0, false)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call for non-retryable status, got %d", calls)
	}
}

func TestExtractJSON_TolerantOfChatterAndFences(t *testing.T) {
	raw := "Sure, here you go:\n```json\n{\"hypotheses\":[{\"id\":\"H1\",\"class\":\"reentrancy\",\"confidence\":0.8}]}\n```\nLet me know if you need more."
	var hs HypothesisSet
	if err := ExtractJSON(raw, &hs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hs.Hypotheses) != 1 || hs.Hypotheses[0].ID != "H1" {
		t.Fatalf("bad parse: %+v", hs)
	}
}

// writeChat writes a minimal OpenAI-style chat completion response.
func writeChat(w http.ResponseWriter, content string) {
	var resp chatResponse
	resp.Choices = make([]struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	}, 1)
	resp.Choices[0].Message = Message{Role: "assistant", Content: content}
	resp.Choices[0].FinishReason = "stop"
	json.NewEncoder(w).Encode(resp)
}

// Claude's OpenAI-compat layer rejects temperature < 1 on current models and
// ignores response_format, so the claude client must omit both and send
// max_tokens + Bearer auth to /chat/completions.
func TestClaudeRequestShape(t *testing.T) {
	var got map[string]any
	var path, auth, ws string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth, ws = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("anthropic-workspace-id")
		json.NewDecoder(r.Body).Decode(&got)
		writeChat(w, "ok")
	}))
	defer srv.Close()

	t.Setenv("SENTINELX_PROVIDER", "claude")
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("CLAUDE_API_BASE", srv.URL+"/v1/")
	t.Setenv("CLAUDE_MODEL", "")
	t.Setenv("ANTHROPIC_WORKSPACE_ID", "ws-1")
	c, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(context.Background(), []Message{{Role: "user", Content: "hi"}}, 0.2, true); err != nil {
		t.Fatal(err)
	}
	if path != "/v1/chat/completions" {
		t.Errorf("path = %q", path)
	}
	if auth != "Bearer sk-test" || ws != "ws-1" {
		t.Errorf("auth=%q ws=%q", auth, ws)
	}
	if got["model"] != DefaultClaudeModel {
		t.Errorf("model = %v", got["model"])
	}
	if _, ok := got["temperature"]; ok {
		t.Errorf("temperature must be omitted for claude, got %v", got["temperature"])
	}
	if _, ok := got["response_format"]; ok {
		t.Errorf("response_format must be omitted for claude")
	}
	if got["max_tokens"] != float64(16000) {
		t.Errorf("max_tokens = %v", got["max_tokens"])
	}
}

func TestMetaRequestStillSendsTemperature(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeChat(w, "ok")
	}))
	defer srv.Close()
	t.Setenv("SENTINELX_PROVIDER", "meta")
	t.Setenv("META_API_BASE", srv.URL)
	t.Setenv("META_API_KEY", "k")
	t.Setenv("META_MODEL", "muse-spark")
	c, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	c.Complete(context.Background(), []Message{{Role: "user", Content: "hi"}}, 0.2, true)
	if got["temperature"] != 0.2 || got["response_format"] == nil {
		t.Errorf("meta request lost temperature/json mode: %v", got)
	}
}

func TestProviderAutoDetectAndErrors(t *testing.T) {
	t.Setenv("SENTINELX_PROVIDER", "")
	t.Setenv("ANTHROPIC_API_KEY", "sk")
	c, err := NewFromEnv()
	if err != nil || c.Provider != ProviderClaude {
		t.Fatalf("expected claude auto-detect, got %v %v", c, err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("META_API_BASE", "")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("expected error with no credentials")
	}
	t.Setenv("SENTINELX_PROVIDER", "gpt")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestEmptyContentIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeChat(w, "   ")
	}))
	defer srv.Close()
	c := &Client{Provider: ProviderClaude, BaseURL: srv.URL, APIKey: "k", Model: "m", HTTP: srv.Client()}
	if _, err := c.Complete(context.Background(), nil, 0, false); err == nil {
		t.Fatal("expected error on empty content")
	}
}
