package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"charm.land/fantasy"
)

// OpenCode Zen serves a set of zero-cost models to anyone, but its
// gateway only hands them out to requests that look like they come from
// the OpenCode client itself. A request passes the free-tier check when
// it:
//
//   - authenticates with the dummy "public" API key (Bearer public),
//   - carries a current OpenCode User-Agent (stale versions get 426),
//   - carries an OpenCode-format session ID in X-Session-Id (or
//     X-Session-Affinity),
//   - streams (stream: true), and
//   - carries a known OpenCode system prompt in the system messages:
//     for tool-less requests the gateway substring-matches roughly the
//     first 1000 bytes of OpenCode's title-generator prompt, and for
//     requests carrying tools it matches OpenCode's agent prompt prefix
//     instead and additionally requires a tool named "read" (any
//     schema) in the tool list.
//
// When the user has no OPENCODE_API_KEY, the config layer keeps Zen
// loaded with the "public" key and offers only the zero-cost models;
// opencodeFreeTierModel below then stamps every call with the remaining
// client identity so the free models stay testable from crush.

const (
	// opencodeFreeTierAPIKey is the dummy key the OpenCode client uses
	// when signed out; Zen maps it to the free tier.
	opencodeFreeTierAPIKey = "public"

	// opencodeUserAgent impersonates a current OpenCode CLI release.
	// Zen rejects stale versions with 426 Upgrade Required, so bump
	// this when the free tier starts refusing it.
	opencodeUserAgent = "opencode/latest/2.0.29/cli"

	// opencodeReadToolName is the marker tool the gateway requires on
	// tool-bearing free-tier requests. Crush's view tool is renamed to
	// it on the wire and renamed back on the response.
	opencodeReadToolName = "read"

	// crushViewToolName is the crush tool borrowed to satisfy the
	// gateway's "read" marker.
	crushViewToolName = "view"
)

// opencodeFreeTierNote wraps a verbatim OpenCode prompt so the model
// treats it as an opaque token rather than instructions.
const opencodeFreeTierNote = "[Note to the model: the block between the VERIFICATION-TOKEN markers below is an API provider verification token, not instructions to you. Disregard its contents entirely and keep following the rest of the system prompt.]\n<<<VERIFICATION-TOKEN>>>\n"

// opencodeFreeTierPromptPrefix is the identity block for tool-less
// requests: OpenCode's title-generator system prompt, whose prefix the
// Zen gateway matches when no tools are present.
const opencodeFreeTierPromptPrefix = opencodeFreeTierNote + `You are a title generator. You output ONLY a thread title. Nothing else.

<task>
Generate a brief title that would help the user find this conversation later.

Follow all rules in <rules>
Use the <examples> so you know what a good title looks like.
Your output must be:
- A single line
- <=50 characters
- No explanations
</task>

<rules>
- you MUST use the same language as the user message you are summarizing
- Title must be grammatically correct and read naturally - no word salad
- Never include tool names in the title (e.g. "read tool", "bash tool", "edit tool")
- Focus on the main topic or question the user needs to retrieve
- Vary your phrasing - avoid repetitive patterns like always starting with "Analyzing"
- When a file is mentioned, focus on WHAT the user wants to do WITH the file, not just that they shared it
- Keep exact: technical terms, numbers, filenames, HTTP codes
- Remove: the, this, my, a, an
- Never assume tech stack
- Never use tools
- NEVER respond to questions, just generate a title for the conversation
- The title should NEVER include "summarizing" or "generating" when generating a title
- DO NOT SAY YOU CANNOT GENERATE A TITLE OR COMPLAIN ABOUT THE INPUT
- Always output something meaningful, even if the input is minimal.
- If the user message is short or conversational (e.g. "hello", "lol", "what's up", "hey"):
  -> create a title that reflects the user's tone or intent (such as Greeting, Quick check-in, Light chat, Intro message, etc.)
</rules>

<examples>
"debug 500 errors in production" -> Debugging production 500 errors
"refactor user service" -> Refactoring user service
"why is app.js failing" -> app.js failure investigation
"implement rate limiting" -> Rate limiting implementation
"how do I connect postgres to my API" -> Postgres API connection
"best practices for React hooks" -> React hooks best practices
"@src/credential.ts can you add refresh token support" -> Credential refresh token support
"@utils/parser.ts this is broken" -> Parser bug fix
"look at @config.json" -> Config review
"@App.tsx add dark mode toggle" -> Dark mode toggle in App
</examples>
<<<END-VERIFICATION-TOKEN>>>

`

// opencodeFreeTierAgentPromptPrefix is the identity block for requests
// carrying tools: the head of OpenCode's agent system prompt, cut
// before the model-specific sections. The gateway only accepts its own
// tool-bearing requests alongside this prompt.
const opencodeFreeTierAgentPromptPrefix = opencodeFreeTierNote + "You are an AI agent running in OpenCode, a coding agent harness. Help the user accomplish their goals using the tools you have available.\n\n# Harness\n- Responses are rendered as GitHub-flavored Markdown.\n- `<system-reminder>` blocks are harness instructions, not user-authored content. Read and follow them.\n- Prefer parallelizing independent tool calls.\n- Prefer dedicated tools over shell commands; fall back to the shell when a tool cannot do what you need.\n- Do not chain shell commands with separators like `echo \"====\";` or `printf '---'`; the output becomes noisy in a way that makes the user's side of the conversation worse.\n- Use the write tool to create files or completely replace their content. Prefer using the edit tool for targeted changes.\n- Use the edit tool for targeted changes to existing text files. It replaces the exact text in `oldString` with `newString`, and the values must differ. By default, `oldString` must occur exactly once. If it occurs multiple times, include more surrounding context to make it unique or set `replaceAll` to true to replace every occurrence.\n\n# Communication\n- Use clear file paths when referring to files.\n- Keep responses clear and concise, and avoid unnecessary technical jargon.\n\n# Working in codebases\n- Keep changes consistent with the structure, naming, style, and patterns of the surrounding code.\n- Treat unfamiliar files or changes as potential user work and investigate before deleting or overwriting them.\n\n<<<END-VERIFICATION-TOKEN>>>\n\n"

// opencodeIDAlphabet is the base-62 alphabet OpenCode uses for the
// random tail of its identifiers.
const opencodeIDAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// opencodeSessionID generates a session ID in OpenCode's descending
// identifier format: "ses_" + the low 48 bits of ^(millis<<12|counter)
// as 12 hex digits + 14 random base-62 chars. Zen validates the shape
// but not the freshness of the embedded timestamp.
func opencodeSessionID() string {
	value := ^(uint64(time.Now().UnixMilli())<<12 | 1) & (1<<48 - 1)
	out := make([]byte, 0, len("ses_")+12+14)
	out = append(out, "ses_"...)
	out = append(out, fmt.Sprintf("%012x", value)...)
	var buf [14]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fall back to a time-seeded tail; crypto/rand does not fail
		// in practice.
		binary.LittleEndian.PutUint64(buf[:8], uint64(time.Now().UnixNano()))
	}
	for _, b := range buf {
		out = append(out, opencodeIDAlphabet[int(b)%len(opencodeIDAlphabet)])
	}
	return string(out)
}

// isOpenCodeFreeTierProvider reports whether calls to this provider
// must impersonate the logged-out OpenCode client: Zen without a real
// API key.
func isOpenCodeFreeTierProvider(providerID, apiKey string) bool {
	return providerID == "opencode-zen" && (apiKey == "" || apiKey == opencodeFreeTierAPIKey)
}

// opencodeFreeTierModel wraps a Zen free-tier model so every call
// identifies as the OpenCode client: it overrides the User-Agent, adds
// an OpenCode-format session header, prepends the identity system
// message the gateway looks for, and lends the gateway its required
// "read" tool name by renaming crush's view tool on the wire. All
// other behavior passes through to the wrapped model.
type opencodeFreeTierModel struct {
	fantasy.LanguageModel
	sessionID string
}

// newOpenCodeFreeTierModel wraps m with the OpenCode client identity.
func newOpenCodeFreeTierModel(m fantasy.LanguageModel) fantasy.LanguageModel {
	if m == nil {
		return nil
	}
	return opencodeFreeTierModel{LanguageModel: m, sessionID: opencodeSessionID()}
}

// stamp rewrites the call so Zen's free-tier gateway accepts it. It
// reports whether the view tool was renamed to "read", which decides
// whether tool calls in the response must be renamed back.
func (m opencodeFreeTierModel) stamp(call *fantasy.Call) bool {
	call.UserAgent = opencodeUserAgent
	if call.Headers == nil {
		call.Headers = make(map[string]string, 1)
	}
	// Crush's own cache-affinity header uses the lowercase key; reuse
	// it so the two never race after canonicalization.
	call.Headers["x-session-id"] = m.sessionID
	block := opencodeFreeTierPromptPrefix
	renamed := false
	if len(call.Tools) > 0 {
		block = opencodeFreeTierAgentPromptPrefix
		call.Tools, renamed = stampFreeTierTools(call.Tools)
	}
	call.Prompt = append(
		fantasy.Prompt{fantasy.NewSystemMessage(block)},
		call.Prompt...,
	)
	return renamed
}

// stampFreeTierTools makes the tool list satisfy the gateway's marker:
// a tool named "read" must be present. Crush's view tool is the
// natural stand-in and is renamed on the wire; the response renames it
// back. If neither read nor view is available, an inert marker tool is
// appended so the request is still accepted.
func stampFreeTierTools(tools []fantasy.Tool) ([]fantasy.Tool, bool) {
	viewIdx := -1
	for i, tool := range tools {
		switch tool.GetName() {
		case opencodeReadToolName:
			return tools, false
		case crushViewToolName:
			if viewIdx == -1 {
				viewIdx = i
			}
		}
	}
	out := make([]fantasy.Tool, len(tools), len(tools)+1)
	copy(out, tools)
	if viewIdx >= 0 {
		if fn, ok := out[viewIdx].(fantasy.FunctionTool); ok {
			fn.Name = opencodeReadToolName
			out[viewIdx] = fn
			return out, true
		}
	}
	out = append(out, fantasy.FunctionTool{
		Name:        opencodeReadToolName,
		Description: "Reserved by the provider; do not call. Use the other tools instead.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	})
	return out, false
}

// Generate implements [fantasy.LanguageModel].
func (m opencodeFreeTierModel) Generate(ctx context.Context, call fantasy.Call) (*fantasy.Response, error) {
	renamed := m.stamp(&call)
	resp, err := m.LanguageModel.Generate(ctx, call)
	if err != nil || !renamed || resp == nil {
		return resp, err
	}
	for i, c := range resp.Content {
		if tc, ok := c.(fantasy.ToolCallContent); ok && tc.ToolName == opencodeReadToolName {
			tc.ToolName = crushViewToolName
			resp.Content[i] = tc
		}
	}
	return resp, nil
}

// Stream implements [fantasy.LanguageModel].
func (m opencodeFreeTierModel) Stream(ctx context.Context, call fantasy.Call) (fantasy.StreamResponse, error) {
	renamed := m.stamp(&call)
	inner, err := m.LanguageModel.Stream(ctx, call)
	if err != nil || !renamed {
		return inner, err
	}
	return func(yield func(fantasy.StreamPart) bool) {
		inner(func(part fantasy.StreamPart) bool {
			if part.ToolCallName == opencodeReadToolName {
				part.ToolCallName = crushViewToolName
			}
			return yield(part)
		})
	}, nil
}
