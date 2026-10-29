// Package agent wraps the LLM that hypothesizes and writes exploits.
//
// The client speaks the OpenAI-style /chat/completions protocol, which both
// providers we care about expose:
//
//   - Claude (current dev stand-in): Anthropic's OpenAI-compatibility layer
//     at https://api.anthropic.com/v1. Quirks handled here: current Claude
//     models reject temperature < 1 (so we omit it), response_format is
//     ignored (ExtractJSON copes), and max_tokens should be set explicitly.
//   - Meta Muse Spark (hackathon target): ASSUMED OpenAI-compatible. Check
//     the Meta Model API docs for the real path, auth header and JSON-mode
//     flag, then adjust newMeta() / once(). Everything else is shared.
//
// Pick the provider with EXPLOITFORGE_PROVIDER=claude|meta (see NewFromEnv).
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Message struct {
	Role    string `json:"role"` // system | user | assistant
	Content string `json:"content"`
}

// Provider names a model backend.
type Provider string

const (
	ProviderClaude Provider = "claude"
	ProviderMeta   Provider = "meta"
)

const (
	DefaultClaudeBase  = "https://api.anthropic.com/v1"
	DefaultClaudeModel = "claude-sonnet-5-5"
)

// Client is an OpenAI-style chat client. The zero value of the quirk flags
// gives plain OpenAI behaviour (temperature + response_format are sent).
type Client struct {
	Provider   Provider
	BaseURL    string // e.g. https://api.anthropic.com/v1
	APIKey     string
	Model      string // e.g. claude-sonnet-5-5 or muse-spark
	HTTP       *http.Client
	MaxRetries int

	// Provider quirks.
	OmitTemperature bool              // Claude 4.7+/5.x reject temperature < 1
	NoJSONMode      bool              // provider ignores/doesn't support response_format
	MaxTokens       int               // 0 = don't send
	ExtraHeaders    map[string]string // e.g. anthropic-workspace-id
}

// NewFromEnv builds a client for the provider in EXPLOITFORGE_PROVIDER
// ("claude" or "meta"). If unset, it picks claude when ANTHROPIC_API_KEY is
// set, otherwise meta.
//
// claude: ANTHROPIC_API_KEY (required), CLAUDE_MODEL (default
//
//	claude-sonnet-5-5), CLAUDE_API_BASE (default api.anthropic.com/v1),
//	ANTHROPIC_WORKSPACE_ID (only for keys not scoped to a workspace).
//
// meta:   META_API_BASE, META_API_KEY, META_MODEL (all required).
func NewFromEnv() (*Client, error) {
	p := Provider(strings.ToLower(strings.TrimSpace(os.Getenv("EXPLOITFORGE_PROVIDER"))))
	if p == "" {
		if os.Getenv("ANTHROPIC_API_KEY") != "" {
			p = ProviderClaude
		} else {
			p = ProviderMeta
		}
	}
	switch p {
	case ProviderClaude:
		return newClaude()
	case ProviderMeta:
		return newMeta()
	default:
		return nil, fmt.Errorf("unknown EXPLOITFORGE_PROVIDER %q (want claude or meta)", p)
	}
}

func newClaude() (*Client, error) {
	c := &Client{
		Provider:   ProviderClaude,
		BaseURL:    strings.TrimRight(envOr("CLAUDE_API_BASE", DefaultClaudeBase), "/"),
		APIKey:     os.Getenv("ANTHROPIC_API_KEY"),
		Model:      envOr("CLAUDE_MODEL", DefaultClaudeModel),
		HTTP:       &http.Client{Timeout: 300 * time.Second}, // thinking is on by default; allow long replies
		MaxRetries: 4,

		OmitTemperature: true,
		NoJSONMode:      true,
		MaxTokens:       16000,
	}
	if ws := os.Getenv("ANTHROPIC_WORKSPACE_ID"); ws != "" {
		c.ExtraHeaders = map[string]string{"anthropic-workspace-id": ws}
	}
	if c.APIKey == "" {
		return nil, errors.New("claude provider: set ANTHROPIC_API_KEY (from platform.claude.com)")
	}
	return c, nil
}

func newMeta() (*Client, error) {
	c := &Client{
		Provider:   ProviderMeta,
		BaseURL:    strings.TrimRight(os.Getenv("META_API_BASE"), "/"),
		APIKey:     os.Getenv("META_API_KEY"),
		Model:      os.Getenv("META_MODEL"),
		HTTP:       &http.Client{Timeout: 120 * time.Second},
		MaxRetries: 4,
	}
	if c.BaseURL == "" || c.APIKey == "" || c.Model == "" {
		return nil, errors.New("meta provider: set META_API_BASE, META_API_KEY and META_MODEL")
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

type chatRequest struct {
	Model          string            `json:"model"`
	Messages       []Message         `json:"messages"`
	Temperature    *float64          `json:"temperature,omitempty"`
	MaxTokens      int               `json:"max_tokens,omitempty"`
	ResponseFormat map[string]string `json:"response_format,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete sends a chat request. jsonMode asks for JSON-only output (remove
// the field if Spark lacks it; ExtractJSON still copes with fenced output).
// Retries 429/5xx and network errors with exponential backoff plus jitter.
func (c *Client) Complete(ctx context.Context, msgs []Message, temp float64, jsonMode bool) (string, error) {
	req := chatRequest{Model: c.Model, Messages: msgs, MaxTokens: c.MaxTokens}
	if !c.OmitTemperature {
		req.Temperature = &temp
	}
	if jsonMode && !c.NoJSONMode {
		req.ResponseFormat = map[string]string{"type": "json_object"}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1))*time.Second + time.Duration(rand.Intn(500))*time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		out, retryable, err := c.once(ctx, body)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !retryable {
			return "", err
		}
	}
	return "", fmt.Errorf("%s: giving up after %d retries: %w", c.name(), c.MaxRetries, lastErr)
}

func (c *Client) once(ctx context.Context, body []byte) (string, bool, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	for k, v := range c.ExtraHeaders {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", ctx.Err() == nil, err // network error: retry unless ctx is done
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return "", true, fmt.Errorf("%s: HTTP %d: %s", c.name(), resp.StatusCode, truncate(string(raw), 300))
	}
	if resp.StatusCode != 200 {
		return "", false, fmt.Errorf("%s: HTTP %d: %s", c.name(), resp.StatusCode, truncate(string(raw), 300))
	}
	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", false, fmt.Errorf("%s: bad response JSON: %w", c.name(), err)
	}
	if cr.Error != nil {
		return "", false, fmt.Errorf("%s: %s", c.name(), cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", false, fmt.Errorf("%s: empty choices", c.name())
	}
	ch := cr.Choices[0]
	if strings.TrimSpace(ch.Message.Content) == "" {
		// e.g. a refusal or a reply cut off at max_tokens with no text.
		return "", false, fmt.Errorf("%s: model returned no text (finish_reason=%q)", c.name(), ch.FinishReason)
	}
	return ch.Message.Content, false, nil
}

func (c *Client) name() string {
	if c.Provider == "" {
		return "llm"
	}
	return string(c.Provider)
}

var codeFence = regexp.MustCompile("(?s)```(?:solidity|sol|json)?\\s*\n(.*?)```")

// ExtractCode returns the first fenced block, or the whole text if unfenced.
func ExtractCode(s string) string {
	if m := codeFence.FindStringSubmatch(s); m != nil {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimSpace(s)
}

// ExtractJSON unmarshals model output into v, tolerating fences and chatter
// around the JSON object.
func ExtractJSON(s string, v any) error {
	s = ExtractCode(s)
	if i, j := strings.Index(s, "{"), strings.LastIndex(s, "}"); i >= 0 && j > i {
		s = s[i : j+1]
	}
	return json.Unmarshal([]byte(s), v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
