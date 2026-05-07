package dialog

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
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

	// PKCE flow requires a browser redirect to localhost:1455.
	// Display the URL for the user to open.
	return ActionInitiateOAuth{
		DeviceCode:      "",
		UserCode:        "",
		VerificationURL: authURL,
		ExpiresIn:       600,
	}
}

func (m *OAuthCodex) startPolling(deviceCode string, expiresIn int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(expiresIn)*time.Second)
		m.cancelFunc = cancel
		defer cancel()

		code, err := m.waitForCallback(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return ActionOAuthErrored{Error: err}
		}

		token, err := codex.ExchangeCode(ctx, code, m.verifier)
		if err != nil {
			return ActionOAuthErrored{Error: fmt.Errorf("token exchange failed: %w", err)}
		}
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

	// The dialog shows the URL, so users can still open it manually.
	_ = browser.OpenURL(m.verificationURL)

	select {
	case result := <-results:
		return result.code, result.err
	case err := <-errs:
		return "", fmt.Errorf("start callback server: %w", err)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
