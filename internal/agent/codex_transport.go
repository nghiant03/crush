package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/charmbracelet/crush/internal/log"
)

type codexInstructionsRoundTripper struct {
	next http.RoundTripper
}

func newCodexResponsesHTTPClient(debug bool) *http.Client {
	next := http.DefaultTransport
	if debug {
		next = log.NewHTTPClient().Transport
	}
	return &http.Client{
		Transport: codexInstructionsRoundTripper{next: next},
	}
}

func (rt codexInstructionsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	next := rt.next
	if next == nil {
		next = http.DefaultTransport
	}
	if req.Body == nil || req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/responses") {
		return next.RoundTrip(req)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()

	if normalized, ok := normalizeCodexResponsesBody(body); ok {
		body = normalized
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	return next.RoundTrip(req)
}

func normalizeCodexResponsesBody(body []byte) ([]byte, bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body, false
	}
	if !promoteCodexInstructions(payload) {
		return body, false
	}

	updated, err := json.Marshal(payload)
	if err != nil {
		return body, false
	}
	return updated, true
}

func promoteCodexInstructions(payload map[string]any) bool {
	if instructions, ok := payload["instructions"].(string); ok && strings.TrimSpace(instructions) != "" {
		return false
	}

	input, ok := payload["input"].([]any)
	if !ok {
		return false
	}

	filtered := make([]any, 0, len(input))
	var instructions string
	for _, item := range input {
		msg, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		role, _ := msg["role"].(string)
		if instructions == "" && (role == "system" || role == "developer") {
			instructions = codexInstructionContent(msg["content"])
			if strings.TrimSpace(instructions) != "" {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	if strings.TrimSpace(instructions) == "" {
		return false
	}

	payload["instructions"] = instructions
	payload["input"] = filtered

	return true
}

func codexInstructionContent(content any) string {
	switch c := content.(type) {
	case string:
		return c
	case []any:
		var parts []string
		for _, item := range c {
			part, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := part["text"].(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}
