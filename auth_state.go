package eveauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// AuthState is an example structure capturing typical data you might
// store in the OAuth "state" parameter.
type AuthState struct {
	// Mode might be "main", "add", or any custom value
	Mode string `json:"mode"`

	// AppID is whichever application context or ID you want to store
	AppID string `json:"app_id"`

	// Timestamp can store a Unix time for expiration checks
	Timestamp int64 `json:"timestamp"`
}

// EncodeState converts the AuthState struct to a URL-safe string (JSON + Base64).
func EncodeState(s AuthState) (string, error) {
	j, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(j), nil
}

// DecodeState does the reverse: parses a string (JSON in base64) into AuthState.
func DecodeState(stateStr string) (*AuthState, error) {
	decoded, err := base64.URLEncoding.DecodeString(stateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}
	var s AuthState
	if err := json.Unmarshal(decoded, &s); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON auth state: %w", err)
	}
	return &s, nil
}

// Helper to build a new AuthState with the current timestamp.
func NewAuthState(mode, appID string) AuthState {
	return AuthState{
		Mode:      mode,
		AppID:     appID,
		Timestamp: time.Now().UnixNano(),
	}
}
