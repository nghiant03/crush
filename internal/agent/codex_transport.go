package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	codexResponseHeaderTimeout = 60 * time.Second
	codexResponseMaxAttempts   = 3
	codexResponseRetryDelay    = 250 * time.Millisecond
	codexStreamIdleTimeout     = 60 * time.Second
)

type codexInstructionsRoundTripper struct {
	next http.RoundTripper
}

type codexIdleTimeoutReadCloser struct {
	body    io.ReadCloser
	cancel  context.CancelCauseFunc
	started time.Time
	status  int
	url     string
}

func newCodexResponsesHTTPClient(_ bool) *http.Client {
	return &http.Client{
		Transport: codexInstructionsRoundTripper{
			next: newCodexTransport(),
		},
	}
}

func newCodexTransport() http.RoundTripper {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.ResponseHeaderTimeout = codexResponseHeaderTimeout
		return clone
	}
	return http.DefaultTransport
}

func (rt codexInstructionsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	next := rt.next
	if next == nil {
		next = http.DefaultTransport
	}
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/responses") {
		return next.RoundTrip(req)
	}

	started := time.Now()
	bodySize := int64(0)
	bodyChanged := false
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()

		bodySize = int64(len(body))
		if normalized, ok := normalizeCodexResponsesBody(body); ok {
			body = normalized
			bodyChanged = true
			bodySize = int64(len(body))
		}
	}

	slog.Debug(
		"Codex responses request started",
		"method", req.Method,
		"url", req.URL.Redacted(),
		"content_length", bodySize,
		"body_normalized", bodyChanged,
	)

	var lastErr error
	for attempt := 1; attempt <= codexResponseMaxAttempts; attempt++ {
		attemptStarted := time.Now()
		attemptReq := req.Clone(req.Context())
		if req.Body != nil {
			attemptReq.Body = io.NopCloser(bytes.NewReader(body))
			attemptReq.ContentLength = bodySize
			attemptReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(body)), nil
			}
		}

		resp, err := next.RoundTrip(attemptReq)
		if err != nil {
			if req.Context().Err() != nil {
				return nil, err
			}
			lastErr = fmt.Errorf("codex responses headers not received within %s: %w", codexResponseHeaderTimeout, err)
			slog.Warn(
				"Codex responses request failed before headers",
				"url", req.URL.Redacted(),
				"attempt", attempt,
				"max_attempts", codexResponseMaxAttempts,
				"duration", time.Since(attemptStarted),
				"total_duration", time.Since(started),
				"header_timeout", codexResponseHeaderTimeout,
				"error", lastErr,
			)
			if attempt == codexResponseMaxAttempts {
				break
			}
			if err := sleepBeforeCodexRetry(req.Context(), attempt); err != nil {
				return nil, err
			}
			continue
		}

		if resp.Body == nil {
			slog.Debug(
				"Codex responses request completed without body",
				"url", req.URL.Redacted(),
				"status", resp.StatusCode,
				"attempt", attempt,
				"duration", time.Since(started),
			)
			return resp, nil
		}
		slog.Debug(
			"Codex responses headers received",
			"url", req.URL.Redacted(),
			"status", resp.StatusCode,
			"attempt", attempt,
			"duration", time.Since(started),
			"request_id", resp.Header.Get("x-request-id"),
			"cf_ray", resp.Header.Get("cf-ray"),
		)
		ctx, cancel := context.WithCancelCause(req.Context())
		resp.Body = codexIdleTimeoutReadCloser{
			body:    resp.Body,
			cancel:  cancel,
			started: started,
			status:  resp.StatusCode,
			url:     req.URL.Redacted(),
		}
		if resp.Request == nil {
			resp.Request = req.WithContext(ctx)
		} else {
			resp.Request = resp.Request.WithContext(ctx)
		}
		return resp, nil
	}

	return nil, lastErr
}

func sleepBeforeCodexRetry(ctx context.Context, attempt int) error {
	delay := codexResponseRetryDelay * time.Duration(1<<(attempt-1))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (rc codexIdleTimeoutReadCloser) Read(p []byte) (int, error) {
	idleErr := fmt.Errorf("codex responses stream idle for %s", codexStreamIdleTimeout)
	timer := time.AfterFunc(codexStreamIdleTimeout, func() {
		rc.cancel(idleErr)
		_ = rc.body.Close()
		slog.Warn(
			"Codex responses stream idle timeout",
			"url", rc.url,
			"status", rc.status,
			"duration", time.Since(rc.started),
			"idle_timeout", codexStreamIdleTimeout,
		)
	})
	n, err := rc.body.Read(p)
	if !timer.Stop() && err == nil {
		err = idleErr
	}
	if err != nil {
		rc.cancel(err)
		slog.Debug(
			"Codex responses stream read finished",
			"url", rc.url,
			"status", rc.status,
			"duration", time.Since(rc.started),
			"bytes", n,
			"error", err,
		)
	}
	return n, err
}

func (rc codexIdleTimeoutReadCloser) Close() error {
	rc.cancel(nil)
	err := rc.body.Close()
	slog.Debug(
		"Codex responses stream closed",
		"url", rc.url,
		"status", rc.status,
		"duration", time.Since(rc.started),
		"error", err,
	)
	return err
}

func normalizeCodexResponsesBody(body []byte) ([]byte, bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body, false
	}

	changed := promoteCodexInstructions(payload)
	changed = normalizeCodexRequestOptions(payload) || changed
	if !changed {
		return body, false
	}

	updated, err := json.Marshal(payload)
	if err != nil {
		return body, false
	}
	return updated, true
}

func normalizeCodexRequestOptions(payload map[string]any) bool {
	changed := false
	if _, ok := payload["parallel_tool_calls"]; !ok {
		payload["parallel_tool_calls"] = true
		changed = true
	}
	if _, ok := payload["store"]; !ok {
		payload["store"] = false
		changed = true
	}
	return changed
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
