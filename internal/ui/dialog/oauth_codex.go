package dialog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/codex"
	"github.com/charmbracelet/crush/internal/ui/common"
	"github.com/pkg/browser"
)

func NewOAuthCodex(
	com *common.Common,
	isOnboarding bool,
	provider catwalk.Provider,
	model config.SelectedModel,
	modelType config.SelectedModelType,
) (*OAuth, tea.Cmd) {
	return newOAuth(com, isOnboarding, provider, model, modelType, &OAuthCodex{})
}

type OAuthCodex struct {
	deviceCode      *codex.DeviceCode
	verificationURL string
	verifier        string
	csrfState       string
	cancelFunc      func()
}

var _ OAuthProvider = (*OAuthCodex)(nil)

func (m *OAuthCodex) name() string {
	return "OpenAI Codex"
}

func (m *OAuthCodex) initiateAuth() tea.Msg {
	authURL, verifier, csrfState := codex.AuthURL()

	m.verificationURL = authURL
	m.verifier = verifier
	m.csrfState = csrfState

	return ActionInitiateOAuth{
		DeviceCode:      "",
		UserCode:        "",
		VerificationURL: authURL,
		ExpiresIn:       600,
	}
}

func (m *OAuthCodex) startPolling(deviceCode string, expiresIn int) tea.Cmd {
	return func() tea.Msg {
		if m.deviceCode != nil {
			return m.pollDeviceCode()
		}
		return m.pollCallback(expiresIn)
	}
}

func (m *OAuthCodex) pollDeviceCode() tea.Msg {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelFunc = cancel

	token, err := codex.PollForDeviceCode(ctx, m.deviceCode)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return ActionOAuthErrored{Error: err}
	}
	return completeCodexOAuth(ctx, token)
}

func (m *OAuthCodex) pollCallback(expiresIn int) tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(expiresIn)*time.Second)
	m.cancelFunc = cancel
	defer cancel()

	code, err := m.waitForCallback(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		deviceCode, deviceErr := m.initiateDeviceCode(ctx)
		if deviceErr != nil {
			return ActionOAuthErrored{Error: err}
		}
		m.deviceCode = deviceCode
		return ActionInitiateOAuth{
			DeviceCode:      deviceCode.DeviceAuthID,
			UserCode:        deviceCode.UserCode,
			VerificationURL: deviceCode.VerificationURL,
			ExpiresIn:       deviceCode.ExpiresIn,
			Interval:        deviceCode.Interval,
		}
	}

	token, err := codex.ExchangeCode(ctx, code, m.verifier)
	if err != nil {
		return ActionOAuthErrored{Error: fmt.Errorf("token exchange failed: %w", err)}
	}
	return completeCodexOAuth(ctx, token)
}

func (m *OAuthCodex) initiateDeviceCode(ctx context.Context) (*codex.DeviceCode, error) {
	deviceCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return codex.RequestDeviceCode(deviceCtx)
}

func completeCodexOAuth(ctx context.Context, token *oauth.Token) tea.Msg {
	if token.AccountID == "" {
		accountID, err := codex.FetchAccountID(ctx, token.AccessToken)
		if err != nil {
			return ActionOAuthErrored{Error: fmt.Errorf("fetch account ID failed: %w", err)}
		}
		token.AccountID = accountID
	}
	if token.AccountID == "" {
		return ActionOAuthErrored{Error: fmt.Errorf("OpenAI Codex account ID not found")}
	}

	return ActionCompleteOAuth{Token: token}
}

func (m *OAuthCodex) stopPolling() tea.Msg {
	if m.cancelFunc != nil {
		m.cancelFunc()
	}
	return nil
}

func (m *OAuthCodex) waitForCallback(ctx context.Context) (string, error) {
	type callbackResult struct {
		code string
		err  error
	}

	results := make(chan callbackResult, 1)
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		code, state, err := codex.ParseRedirectURL(r.URL.String())
		if err == nil && state != m.csrfState {
			err = fmt.Errorf("CSRF state mismatch")
		}
		if err != nil {
			http.Error(w, "Authentication failed. You can return to Crush.", http.StatusBadRequest)
			results <- callbackResult{err: err}
			return
		}

		fmt.Fprintln(w, "Authentication complete. You can return to Crush.")
		results <- callbackResult{code: code}
	})
	server.Handler = mux

	listener, err := net.Listen("tcp", "localhost:1455")
	if err != nil {
		return "", fmt.Errorf("start callback server: %w", err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	errs := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errs <- err
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := openBrowserSilent(m.verificationURL); err != nil {
		return "", fmt.Errorf("open browser: %w", err)
	}

	select {
	case result := <-results:
		return result.code, result.err
	case err := <-errs:
		return "", fmt.Errorf("start callback server: %w", err)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func openBrowserSilent(url string) error {
	stdout := browser.Stdout
	stderr := browser.Stderr
	browser.Stdout = io.Discard
	browser.Stderr = io.Discard
	defer func() {
		browser.Stdout = stdout
		browser.Stderr = stderr
	}()
	return browser.OpenURL(url)
}
