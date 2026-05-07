// Package codex provides OpenAI Codex OAuth authentication.
//
// Codex uses the PKCE Authorization Code flow (RFC 7636). Unlike Copilot's
// device code flow, this requires a localhost callback server to capture the
// authorization code.
//
// References:
//   - https://auth.openai.com/.well-known/openid-configuration
package codex

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/crush/internal/oauth"
)

const (
	clientID = "app_EMoamEEZ73f0CkXaXp7hrann"

	authorizeURL = "https://auth.openai.com/oauth/authorize"
	tokenURL     = "https://auth.openai.com/oauth/token"
	redirectURI  = "http://localhost:1455/auth/callback"
	baseURL      = "https://chatgpt.com/backend-api/codex"
	accountURL   = "https://api.openai.com/auth/v1/account"
	tokenInfoURL = "https://api.openai.com/auth/v1/token-info"
	originator   = "Codex Crush"
)

// AuthURL builds the authorization URL with PKCE challenge.
// Returns the URL the user must open, the code verifier (needed later for
// token exchange), and the CSRF state.
func AuthURL() (string, string, string) {
	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)
	state := generateState()

	u, _ := url.Parse(authorizeURL)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email offline_access api.connectors.read api.connectors.invoke")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("id_token_add_organizations", "true")
	q.Set("codex_cli_simplified_flow", "true")
	q.Set("state", state)
	q.Set("originator", originator)
	u.RawQuery = q.Encode()

	return u.String(), verifier, state
}

// ExchangeCode exchanges the authorization code for tokens.
func ExchangeCode(ctx context.Context, code, verifier string) (*oauth.Token, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	setHeaders(req.Header)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: status %d body %q", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	token := &oauth.Token{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
		ExpiresIn:    result.ExpiresIn,
	}
	token.AccountID = cmpOr(ExtractAccountID(token.AccessToken), ExtractAccountID(token.IDToken))
	token.SetExpiresAt()
	return token, nil
}

// RefreshToken refreshes the access token using the refresh token.
func RefreshToken(ctx context.Context, refreshToken string) (*oauth.Token, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", clientID)
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	setHeaders(req.Header)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed: status %d body %q", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	token := &oauth.Token{
		AccessToken:  result.AccessToken,
		RefreshToken: cmpOr(result.RefreshToken, refreshToken),
		IDToken:      result.IDToken,
		ExpiresIn:    result.ExpiresIn,
	}
	token.AccountID = cmpOr(ExtractAccountID(token.AccessToken), ExtractAccountID(token.IDToken))
	token.SetExpiresAt()
	return token, nil
}

// BaseURL returns the ChatGPT Codex backend used by ChatGPT OAuth tokens.
func BaseURL() string {
	return baseURL
}

// ExtractAccountID returns the ChatGPT account ID from an OAuth JWT.
func ExtractAccountID(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	authClaim, ok := claims["https://api.openai.com/auth"].(map[string]any)
	if !ok {
		return ""
	}
	accountID, _ := authClaim["chatgpt_account_id"].(string)
	return accountID
}

// FetchAccountID retrieves the Codex account ID using the access token.
func FetchAccountID(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", accountURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	setHeaders(req.Header)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("account request failed: status %d body %q", resp.StatusCode, string(body))
	}

	var result struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	return result.ChatGPTAccountID, nil
}

// ValidateToken checks if the token is still valid.
func ValidateToken(ctx context.Context, accessToken string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", tokenInfoURL, nil)
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	setHeaders(req.Header)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// Headers returns the extra HTTP headers for Codex API requests.
func Headers() map[string]string {
	return map[string]string{
		"originator": originator,
		"User-Agent": originator,
	}
}

// HeadersForToken returns Codex request headers derived from token metadata.
func HeadersForToken(token *oauth.Token) map[string]string {
	headers := Headers()
	if token != nil {
		accountID := cmpOr(token.AccountID, cmpOr(ExtractAccountID(token.AccessToken), ExtractAccountID(token.IDToken)))
		if accountID != "" {
			headers["ChatGPT-Account-ID"] = accountID
		}
	}
	return headers
}

func setHeaders(header http.Header) {
	for key, value := range Headers() {
		header.Set(key, value)
	}
}

// generateCodeVerifier generates a cryptographically random PKCE code verifier.
func generateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge generates a SHA256 PKCE code challenge from the verifier.
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateState generates a random CSRF state parameter.
func generateState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ParseRedirectURL extracts the authorization code and state from a redirect URL.
func ParseRedirectURL(redirectURL string) (code, state string, err error) {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return "", "", fmt.Errorf("parse URL: %w", err)
	}
	code = u.Query().Get("code")
	state = u.Query().Get("state")
	if errCode := u.Query().Get("error"); errCode != "" {
		if description := u.Query().Get("error_description"); description != "" {
			return "", "", fmt.Errorf("OAuth callback error %s: %s", errCode, description)
		}
		return "", "", fmt.Errorf("OAuth callback error: %s", errCode)
	}
	if code == "" {
		return "", "", fmt.Errorf("no authorization code in URL")
	}
	return code, state, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
