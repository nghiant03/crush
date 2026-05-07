package agent

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

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

	input := payload["input"].([]any)
	require.Len(t, input, 1)
	require.Equal(t, "user", input[0].(map[string]any)["role"])
}

func TestPromoteCodexInstructionsKeepsExistingInstructions(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"instructions": "Already set.",
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

func TestNormalizeCodexResponsesBodyLeavesTokenFieldsToSDKOptions(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"max_output_tokens": 4096,
		"max_tokens": 4096,
		"input": [
			{"role": "user", "content": "Hello"}
		]
	}`)

	updated, ok := normalizeCodexResponsesBody(body)
	require.False(t, ok)
	require.Equal(t, string(body), string(updated))
}
