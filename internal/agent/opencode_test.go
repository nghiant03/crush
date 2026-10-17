package agent

import (
	"strings"
	"testing"

	"charm.land/fantasy"
	"github.com/stretchr/testify/require"
)

func TestOpencodeSessionID(t *testing.T) {
	t.Parallel()
	seen := map[string]struct{}{}
	for range 100 {
		id := opencodeSessionID()
		require.True(t, strings.HasPrefix(id, "ses_"), id)
		require.Len(t, id, len("ses_")+12+14, id)
		for _, c := range id[len("ses_")+12:] {
			require.Contains(t, opencodeIDAlphabet, string(c), id)
		}
		_, dup := seen[id]
		require.False(t, dup, "duplicate session id %s", id)
		seen[id] = struct{}{}
	}
}

func TestIsOpenCodeFreeTierProvider(t *testing.T) {
	t.Parallel()
	require.True(t, isOpenCodeFreeTierProvider("opencode-zen", ""))
	require.True(t, isOpenCodeFreeTierProvider("opencode-zen", "public"))
	require.False(t, isOpenCodeFreeTierProvider("opencode-zen", "oc_sk_real"))
	require.False(t, isOpenCodeFreeTierProvider("opencode-go", ""))
	require.False(t, isOpenCodeFreeTierProvider("anthropic", ""))
}

func TestStampFreeTierTools(t *testing.T) {
	t.Parallel()
	fn := func(name string) fantasy.FunctionTool {
		return fantasy.FunctionTool{Name: name, Description: name + " tool"}
	}

	t.Run("renames view to read", func(t *testing.T) {
		t.Parallel()
		tools, renamed := stampFreeTierTools([]fantasy.Tool{fn("bash"), fn("view"), fn("edit")})
		require.True(t, renamed)
		require.Len(t, tools, 3)
		require.Equal(t, "bash", tools[0].GetName())
		require.Equal(t, "read", tools[1].GetName())
		require.Equal(t, "edit", tools[2].GetName())
	})

	t.Run("existing read is left alone", func(t *testing.T) {
		t.Parallel()
		in := []fantasy.Tool{fn("read"), fn("view")}
		tools, renamed := stampFreeTierTools(in)
		require.False(t, renamed)
		require.Equal(t, "read", tools[0].GetName())
		require.Equal(t, "view", tools[1].GetName())
	})

	t.Run("appends marker when no view", func(t *testing.T) {
		t.Parallel()
		tools, renamed := stampFreeTierTools([]fantasy.Tool{fn("bash")})
		require.False(t, renamed)
		require.Len(t, tools, 2)
		require.Equal(t, "bash", tools[0].GetName())
		require.Equal(t, "read", tools[1].GetName())
	})
}

func TestOpenCodeFreeTierStamp(t *testing.T) {
	t.Parallel()
	m := opencodeFreeTierModel{sessionID: "ses_test"}

	textOf := func(msg fantasy.Message) string {
		var sb strings.Builder
		for _, part := range msg.Content {
			if tp, ok := part.(fantasy.TextPart); ok {
				sb.WriteString(tp.Text)
			}
		}
		return sb.String()
	}

	t.Run("tool-less call uses title prompt identity", func(t *testing.T) {
		t.Parallel()
		call := fantasy.Call{Prompt: fantasy.Prompt{fantasy.NewUserMessage("hi")}}
		renamed := m.stamp(&call)
		require.False(t, renamed)
		require.Equal(t, opencodeUserAgent, call.UserAgent)
		require.Equal(t, "ses_test", call.Headers["x-session-id"])
		require.Len(t, call.Prompt, 2)
		require.Equal(t, fantasy.MessageRoleSystem, call.Prompt[0].Role)
		require.Contains(t, textOf(call.Prompt[0]), "You are a title generator.")
	})

	t.Run("call with tools uses agent prompt identity", func(t *testing.T) {
		t.Parallel()
		call := fantasy.Call{
			Prompt: fantasy.Prompt{fantasy.NewUserMessage("hi")},
			Tools:  []fantasy.Tool{fantasy.FunctionTool{Name: "view"}},
		}
		renamed := m.stamp(&call)
		require.True(t, renamed)
		require.Equal(t, "read", call.Tools[0].GetName())
		require.Len(t, call.Prompt, 2)
		sys := textOf(call.Prompt[0])
		require.Contains(t, sys, "You are an AI agent running in OpenCode")
	})
}

func TestOpenCodeFreeTierPromptContents(t *testing.T) {
	t.Parallel()
	// The gateway substring-matches roughly the first 1000 bytes of
	// each known OpenCode prompt, so both blocks must carry at least
	// that much verbatim text.
	require.Contains(t, opencodeFreeTierPromptPrefix, "You are a title generator.")
	require.Greater(t, strings.Index(opencodeFreeTierPromptPrefix, "<<<END-VERIFICATION-TOKEN>>>"), 1000)
	require.Contains(t, opencodeFreeTierAgentPromptPrefix, "You are an AI agent running in OpenCode")
	require.Greater(t, strings.Index(opencodeFreeTierAgentPromptPrefix, "<<<END-VERIFICATION-TOKEN>>>"), 1000)
}
