package eveauth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guarzo/eveauth"
)

func TestAuthState_EncodeDecode(t *testing.T) {
	// Create a sample AuthState
	now := time.Now().UnixNano()
	original := eveauth.AuthState{
		Mode:      "main",
		AppID:     "testApp",
		Timestamp: now,
	}

	// Encode the AuthState
	encoded, err := eveauth.EncodeState(original)
	require.NoError(t, err, "EncodeState should not return an error")
	assert.NotEmpty(t, encoded, "Encoded string should not be empty")

	// Decode the AuthState
	decoded, err := eveauth.DecodeState(encoded)
	require.NoError(t, err, "DecodeState should not return an error")
	assert.Equal(t, original.Mode, decoded.Mode, "Mode should match")
	assert.Equal(t, original.AppID, decoded.AppID, "AppID should match")
	assert.Equal(t, original.Timestamp, decoded.Timestamp, "Timestamp should match")
}

func TestAuthState_NewAuthState(t *testing.T) {
	as := eveauth.NewAuthState("add", "myCustomAppID")
	assert.Equal(t, "add", as.Mode)
	assert.Equal(t, "myCustomAppID", as.AppID)
	assert.NotZero(t, as.Timestamp, "Timestamp should be set to the current time")
}
