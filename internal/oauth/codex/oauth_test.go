package codex

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthURLIncludesCodexParameters(t *testing.T) {
	t.Parallel()

	authURL, verifier, state := AuthURL()
	require.NotEmpty(t, verifier)
	require.NotEmpty(t, state)

	u, err := url.Parse(authURL)
	require.NoError(t, err)

	q := u.Query()
	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "auth.openai.com", u.Host)
	require.Equal(t, "/oauth/authorize", u.Path)
	require.Equal(t, clientID, q.Get("client_id"))
	require.Equal(t, redirectURI, q.Get("redirect_uri"))
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, "true", q.Get("id_token_add_organizations"))
	require.Equal(t, "true", q.Get("codex_cli_simplified_flow"))
	require.Equal(t, originator, q.Get("originator"))
	require.Contains(t, q.Get("scope"), "api.connectors.read")
	require.Contains(t, q.Get("scope"), "api.connectors.invoke")
	require.Equal(t, state, q.Get("state"))
	require.NotEmpty(t, q.Get("code_challenge"))
}

func TestParseRedirectURLReturnsOAuthCallbackError(t *testing.T) {
	t.Parallel()

	code, state, err := ParseRedirectURL("http://localhost:1455/auth/callback?error=access_denied&error_description=missing_codex_entitlement&state=abc")
	require.Empty(t, code)
	require.Empty(t, state)
	require.Error(t, err)
	require.Contains(t, err.Error(), "access_denied")
	require.Contains(t, err.Error(), "missing_codex_entitlement")
}

func TestDeviceCodeConstantsMatchOfficialCodexEndpoints(t *testing.T) {
	t.Parallel()

	require.Equal(t, "https://auth.openai.com/api/accounts/deviceauth/usercode", deviceUserCodeURL)
	require.Equal(t, "https://auth.openai.com/api/accounts/deviceauth/token", deviceTokenURL)
	require.Equal(t, "https://auth.openai.com/codex/device", deviceVerificationURL)
	require.Equal(t, "https://auth.openai.com/deviceauth/callback", deviceRedirectURI)
}

func TestExtractAccountID(t *testing.T) {
	t.Parallel()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc_123"}}`))

	require.Equal(t, "acc_123", ExtractAccountID(header+"."+payload+"."))
	require.Empty(t, ExtractAccountID("not-a-jwt"))
}
