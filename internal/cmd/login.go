package cmd

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"charm.land/catwalk/pkg/catwalk"
	"charm.land/lipgloss/v2"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/crush/internal/client"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/codex"
	"github.com/charmbracelet/crush/internal/oauth/copilot"
	"github.com/charmbracelet/crush/internal/oauth/hyper"
	"github.com/charmbracelet/x/ansi"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Aliases: []string{"auth"},
	Use:     "login [platform]",
	Short:   "Login Crush to a platform",
	Long: `Login Crush to a specified platform.
The platform should be provided as an argument.
Available platforms are: hyper, copilot, codex.`,
	Example: `
# Authenticate with Charm Hyper
crush login

# Authenticate with GitHub Copilot
crush login copilot

# Authenticate with OpenAI Codex
crush login codex
  `,
	ValidArgs: []cobra.Completion{
		"hyper",
		"copilot",
		"github",
		"github-copilot",
		"codex",
		"openai-codex",
	},
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, ws, cleanup, err := connectToServer(cmd)
		if err != nil {
			return err
		}
		defer cleanup()

		progressEnabled := ws.Config.Options.Progress == nil || *ws.Config.Options.Progress
		if progressEnabled && supportsProgressBar() {
			_, _ = fmt.Fprintf(os.Stderr, ansi.SetIndeterminateProgressBar)
			defer func() { _, _ = fmt.Fprintf(os.Stderr, ansi.ResetProgressBar) }()
		}

		provider := "hyper"
		if len(args) > 0 {
			provider = args[0]
		}
		switch provider {
		case "hyper":
			return loginHyper(c, ws.ID)
		case "copilot", "github", "github-copilot":
			return loginCopilot(cmd.Context(), c, ws.ID)
		case "codex", "openai-codex":
			return loginCodex(cmd.Context(), c, ws.ID)
		default:
			return fmt.Errorf("unknown platform: %s", args[0])
		}
	},
}

func loginHyper(c *client.Client, wsID string) error {
	ctx := getLoginContext()

	resp, err := hyper.InitiateDeviceAuth(ctx)
	if err != nil {
		return err
	}

	if clipboard.WriteAll(resp.UserCode) == nil {
		fmt.Println("The following code should be on clipboard already:")
	} else {
		fmt.Println("Copy the following code:")
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Render(resp.UserCode))
	fmt.Println()
	fmt.Println("Press enter to open this URL, and then paste it there:")
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Hyperlink(resp.VerificationURL, "id=hyper").Render(resp.VerificationURL))
	fmt.Println()
	waitEnter()
	if err := browser.OpenURL(resp.VerificationURL); err != nil {
		fmt.Println("Could not open the URL. You'll need to manually open the URL in your browser.")
	}

	fmt.Println("Exchanging authorization code...")
	refreshToken, err := hyper.PollForToken(ctx, resp.DeviceCode, resp.ExpiresIn)
	if err != nil {
		return err
	}

	fmt.Println("Exchanging refresh token for access token...")
	token, err := hyper.ExchangeToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	fmt.Println("Verifying access token...")
	introspect, err := hyper.IntrospectToken(ctx, token.AccessToken)
	if err != nil {
		return fmt.Errorf("token introspection failed: %w", err)
	}
	if !introspect.Active {
		return fmt.Errorf("access token is not active")
	}

	if err := cmp.Or(
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.hyper.api_key", token.AccessToken),
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.hyper.oauth", token),
	); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with Hyper!")
	return nil
}

func loginCopilot(ctx context.Context, c *client.Client, wsID string) error {
	loginCtx := getLoginContext()

	cfg, err := c.GetConfig(ctx, wsID)
	if err == nil && cfg != nil {
		if pc, ok := cfg.Providers.Get("copilot"); ok && pc.OAuthToken != nil {
			fmt.Println("You are already logged in to GitHub Copilot.")
			return nil
		}
	}

	diskToken, hasDiskToken := copilot.RefreshTokenFromDisk()
	var token *oauth.Token

	switch {
	case hasDiskToken:
		fmt.Println("Found existing GitHub Copilot token on disk. Using it to authenticate...")

		t, err := copilot.RefreshToken(loginCtx, diskToken)
		if err != nil {
			return fmt.Errorf("unable to refresh token from disk: %w", err)
		}
		token = t
	default:
		fmt.Println("Requesting device code from GitHub...")
		dc, err := copilot.RequestDeviceCode(loginCtx)
		if err != nil {
			return err
		}

		fmt.Println()
		fmt.Println("Open the following URL and follow the instructions to authenticate with GitHub Copilot:")
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Hyperlink(dc.VerificationURI, "id=copilot").Render(dc.VerificationURI))
		fmt.Println()
		fmt.Println("Code:", lipgloss.NewStyle().Bold(true).Render(dc.UserCode))
		fmt.Println()
		fmt.Println("Waiting for authorization...")

		t, err := copilot.PollForToken(loginCtx, dc)
		if err == copilot.ErrNotAvailable {
			fmt.Println()
			fmt.Println("GitHub Copilot is unavailable for this account. To signup, go to the following page:")
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Hyperlink(copilot.SignupURL, "id=copilot-signup").Render(copilot.SignupURL))
			fmt.Println()
			fmt.Println("You may be able to request free access if eligible. For more information, see:")
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Hyperlink(copilot.FreeURL, "id=copilot-free").Render(copilot.FreeURL))
		}
		if err != nil {
			return err
		}
		token = t
	}

	if err := cmp.Or(
		c.SetConfigField(loginCtx, wsID, config.ScopeGlobal, "providers.copilot.api_key", token.AccessToken),
		c.SetConfigField(loginCtx, wsID, config.ScopeGlobal, "providers.copilot.oauth", token),
	); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with GitHub Copilot!")
	return nil
}

func loginCodex(ctx context.Context, c *client.Client, wsID string) error {
	loginCtx := getLoginContext()

	cfg, err := c.GetConfig(ctx, wsID)
	if err == nil && cfg != nil {
		if pc, ok := cfg.Providers.Get(string(catwalk.InferenceProviderOpenAI)); ok && pc.OAuthToken != nil {
			fmt.Println("You are already logged in to OpenAI Codex.")
			return nil
		}
	}

	authURL, verifier, csrfState := codex.AuthURL()

	fmt.Println()
	fmt.Println("Open the following URL and follow the instructions to authenticate with OpenAI Codex:")
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Hyperlink(authURL).Render(authURL))
	fmt.Println()
	fmt.Println("Authentication uses a local callback server on port 1455.")
	fmt.Println("The browser will redirect there after you log in.")
	fmt.Println()

	if err := browser.OpenURL(authURL); err != nil {
		fmt.Println("Could not open the browser. Falling back to device code login.")
		token, err := loginCodexDevice(loginCtx)
		if err != nil {
			return err
		}
		if err := saveCodexToken(loginCtx, c, wsID, token); err != nil {
			return err
		}
		fmt.Println()
		fmt.Println("You're now authenticated with OpenAI Codex!")
		return nil
	}
	fmt.Println("After logging in, paste the full redirect URL here:")
	fmt.Print("> ")

	var redirectURL string
	if _, err := fmt.Scanln(&redirectURL); err != nil {
		return fmt.Errorf("failed to read redirect URL: %w", err)
	}

	code, state, err := codex.ParseRedirectURL(redirectURL)
	if err != nil {
		return fmt.Errorf("failed to parse redirect URL: %w", err)
	}
	if state != csrfState {
		return fmt.Errorf("CSRF state mismatch")
	}

	fmt.Println("Exchanging authorization code...")
	token, err := codex.ExchangeCode(loginCtx, code, verifier)
	if err != nil {
		return err
	}

	if err := saveCodexToken(loginCtx, c, wsID, token); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with OpenAI Codex!")
	return nil
}

func loginCodexDevice(ctx context.Context) (*oauth.Token, error) {
	fmt.Println("Requesting device code from OpenAI...")
	dc, err := codex.RequestDeviceCode(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Println()
	fmt.Println("Open the following URL and follow the instructions to authenticate with OpenAI Codex:")
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Hyperlink(dc.VerificationURL, "id=codex-device").Render(dc.VerificationURL))
	fmt.Println()
	fmt.Println("Code:", lipgloss.NewStyle().Bold(true).Render(dc.UserCode))
	fmt.Println()
	fmt.Println("Waiting for authorization...")

	return codex.PollForDeviceCode(ctx, dc)
}

func saveCodexToken(ctx context.Context, c *client.Client, wsID string, token *oauth.Token) error {
	accountID, err := codex.FetchAccountID(ctx, token.AccessToken)
	if err != nil {
		slog.Warn("Could not fetch account ID", "error", err)
	} else {
		token.AccountID = accountID
		slog.Info("Codex account ID", "account_id", accountID)
	}
	if token.AccountID == "" {
		token.AccountID = cmp.Or(codex.ExtractAccountID(token.AccessToken), codex.ExtractAccountID(token.IDToken))
	}

	if err := cmp.Or(
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.openai.api_key", token.AccessToken),
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.openai.oauth", token),
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.openai.base_url", codex.BaseURL()),
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.openai.type", string(catwalk.TypeOpenAI)),
	); err != nil {
		return err
	}
	return nil
}

func getLoginContext() context.Context {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	go func() {
		<-ctx.Done()
		cancel()
		os.Exit(1)
	}()
	return ctx
}

func waitEnter() {
	_, _ = fmt.Scanln()
}
