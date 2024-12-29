package eveauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// HttpClient is a minimal interface for making HTTP requests.
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// AuthClient is the interface that provides EVE SSO OAuth methods.
type AuthClient interface {
	// GenerateAuthURL builds a state string (with the given mode/appID) and
	// returns a full auth URL. If you want to control the "state" directly,
	// you could provide a separate method or skip this one entirely.
	GenerateAuthURL(mode, appID string) (string, error)

	// ParseState parses the "state" param from the EVE callback into AuthState.
	ParseState(stateStr string) (*AuthState, error)

	// ExchangeCode exchanges the authorization code for an access token.
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)

	// RefreshToken refreshes the OAuth token using the refresh token.
	RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)
}

// authClient is a concrete implementation of AuthClient.
type authClient struct {
	oauthConfig *oauth2.Config
	httpClient  HttpClient
}

// NewAuthClient constructs an AuthClient for EVE SSO with the given credentials,
// callback URL, and custom scopes. The caller must provide their own HttpClient,
// e.g., an *http.Client or mock for testing.
func NewAuthClient(
	clientID, clientSecret, callbackURL string,
	scopes []string,
	httpClient HttpClient,
) AuthClient {
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  callbackURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.eveonline.com/v2/oauth/authorize",
			TokenURL: "https://login.eveonline.com/v2/oauth/token",
		},
	}

	return &authClient{
		oauthConfig: config,
		httpClient:  httpClient,
	}
}

// GenerateAuthURL builds a new AuthState from the given mode/appID,
// encodes it, and returns the OAuth2 "auth code" URL including the state param.
func (c *authClient) GenerateAuthURL(mode, appID string) (string, error) {
	stateStruct := NewAuthState(mode, appID)
	stateStr, err := EncodeState(stateStruct)
	if err != nil {
		return "", fmt.Errorf("GenerateAuthURL: failed to encode state: %w", err)
	}
	return c.oauthConfig.AuthCodeURL(stateStr), nil
}

// ParseState decodes the "state" param back into an AuthState struct.
func (c *authClient) ParseState(stateStr string) (*AuthState, error) {
	authState, err := DecodeState(stateStr)
	if err != nil {
		return nil, fmt.Errorf("ParseState: %w", err)
	}
	return authState, nil
}

// ExchangeCode exchanges the authorization code for an access token.
// The caller can pass any context, e.g. with timeouts or cancellation.
func (c *authClient) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	tok, err := c.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("ExchangeCode: failed to exchange token: %w", err)
	}
	return tok, nil
}

// RefreshToken refreshes the OAuth token using the refresh token.
// The caller can pass any context, e.g. with timeouts or cancellation.
func (c *authClient) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauthConfig.Endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("RefreshToken: failed to create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Encode clientID:clientSecret in Base64
	encodedCreds := base64.StdEncoding.EncodeToString(
		[]byte(c.oauthConfig.ClientID + ":" + c.oauthConfig.ClientSecret),
	)
	req.Header.Add("Authorization", "Basic "+encodedCreds)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RefreshToken: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("RefreshToken: non-200 status %d. Body: %s", resp.StatusCode, string(bodyBytes))
	}

	var token oauth2.Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("RefreshToken: failed to decode JSON: %w", err)
	}

	return &token, nil
}
