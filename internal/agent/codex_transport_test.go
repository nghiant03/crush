package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCodexResponsesRoundTripRetriesBeforeHeaders(t *testing.T) {
	t.Parallel()

	calls := 0
	rt := codexInstructionsRoundTripper{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.JSONEq(t, `{
				"input":[{"role":"user","content":"Hello"}],
				"parallel_tool_calls":true,
				"store":false
			}`, string(body))
			if calls < codexResponseMaxAttempts {
				return nil, errors.New("timeout waiting for response headers")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}
	req, err := http.NewRequest(
		http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses",
		strings.NewReader(`{"input":[{"role":"user","content":"Hello"}]}`),
	)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, codexResponseMaxAttempts, calls)
}

func TestCodexResponsesRoundTripKeepsStreamContextAlive(t *testing.T) {
	t.Parallel()

	rt := codexInstructionsRoundTripper{
		next: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}
	req, err := http.NewRequest(
		http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses",
		strings.NewReader(`{"input":[{"role":"user","content":"Hello"}]}`),
	)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	select {
	case <-resp.Request.Context().Done():
		t.Fatal("stream context was canceled before the body was read")
	default:
	}

	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.ErrorIs(t, resp.Request.Context().Err(), context.Canceled)
}

func TestPromoteCodexInstructions(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"model": "gpt-5.1-codex-max",
		"input": [
			{"role": "developer", "content": "Be concise."},
			{"role": "user", "content": [{"type": "input_text", "text": "Hello"}]}
		]
	}`)

	updated, ok := normalizeCodexResponsesBody(body)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(updated, &payload))
	require.Equal(t, "Be concise.", payload["instructions"])
	require.Equal(t, true, payload["parallel_tool_calls"])
	require.Equal(t, false, payload["store"])

	input := payload["input"].([]any)
	require.Len(t, input, 1)
	require.Equal(t, "user", input[0].(map[string]any)["role"])
}

func TestPromoteCodexInstructionsKeepsExistingInstructions(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"instructions": "Already set.",
		"parallel_tool_calls": false,
		"store": true,
		"input": [{"role": "developer", "content": "Ignored."}]
	}`)

	updated, ok := normalizeCodexResponsesBody(body)
	require.False(t, ok)
	require.Equal(t, string(body), string(updated))
}

func TestPromoteCodexInstructionsFromContentParts(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"input": [
			{"role": "system", "content": [
				{"type": "input_text", "text": "One."},
				{"type": "input_text", "text": "Two."}
			]},
			{"role": "user", "content": "Hello"}
		]
	}`)

	updated, ok := normalizeCodexResponsesBody(body)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(updated, &payload))
	require.Equal(t, "One.\nTwo.", payload["instructions"])
}

func TestNormalizeCodexResponsesBodyAddsRequestOptions(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"input": [
			{"role": "user", "content": "Hello"}
		]
	}`)

	updated, ok := normalizeCodexResponsesBody(body)
	require.True(t, ok)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(updated, &payload))
	require.Equal(t, true, payload["parallel_tool_calls"])
	require.Equal(t, false, payload["store"])
}

func TestNormalizeCodexResponsesBodyLeavesTokenFieldsToSDKOptions(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"max_output_tokens": 4096,
		"max_tokens": 4096,
		"parallel_tool_calls": false,
		"store": true,
		"input": [
			{"role": "user", "content": "Hello"}
		]
	}`)

	updated, ok := normalizeCodexResponsesBody(body)
	require.False(t, ok)
	require.Equal(t, string(body), string(updated))
}
