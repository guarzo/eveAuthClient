package eveauth_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guarzo/eveauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHttpClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHttpClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func TestGenerateAuthURL(t *testing.T) {
	hc := &mockHttpClient{}
	scopes := []string{"publicData"}
	client := eveauth.NewAuthClient("testID", "testSecret", "http://callback", scopes, hc)

	// We can just check that it encodes the scope, client_id, state, etc.
	url, err := client.GenerateAuthURL("main", "myApp")
	require.NoError(t, err)
	assert.Contains(t, url, "scope=publicData")
	assert.Contains(t, url, "client_id=testID")
	assert.Contains(t, url, "state=")
}

// Example test for RefreshToken success
func TestRefreshToken_Success(t *testing.T) {
	hc := &mockHttpClient{}
	hc.DoFunc = func(req *http.Request) (*http.Response, error) {
		// check that request has refresh_token param
		bodyBytes, _ := io.ReadAll(req.Body)
		bodyStr := string(bodyBytes)
		assert.Contains(t, bodyStr, "grant_type=refresh_token")
		assert.Contains(t, bodyStr, "refresh_token=old-refresh")

		responseBody := `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer"}`
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(responseBody)),
		}, nil
	}

	client := eveauth.NewAuthClient(
		"clientID", "clientSecret", "http://callback",
		[]string{"publicData"}, hc,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := client.RefreshToken(ctx, "old-refresh")
	require.NoError(t, err)
	assert.Equal(t, "new-access", token.AccessToken)
	assert.Equal(t, "new-refresh", token.RefreshToken)
}
