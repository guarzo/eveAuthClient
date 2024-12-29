# eveauth — A Go Client for EVE Online OAuth (SSO) Flows
[![Build & Test CI](https://github.com/guarzo/eveauth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/guarzo/eveauth/actions/workflows/ci.yml)
[![Release Workflow](https://github.com/guarzo/eveauth/actions/workflows/release.yml/badge.svg)](https://github.com/guarzo/eveauth/actions/workflows/release.yml)



`eveauth` is a lightweight Go library that simplifies integration with EVE Online’s Single Sign-On (SSO) for OAuth2. It handles:

- Generating state parameters (mode, appID, timestamps) and encoding/decoding them.
- Building an EVE Online authorization URL with custom scopes.
- Exchanging authorization codes for access tokens.
- Refreshing tokens via the EVE Online OAuth endpoint.
- Returning clear, descriptive errors (no internal logging).

---

## Features

- **Configurable scopes**: specify whichever EVE SSO scopes your application needs.
- **Injectable `http.Client`**: you control timeouts, retries, or mocking in tests.
- **State helpers**: easily encode/decode `AuthState` in base64 to pass through OAuth “state”.
- **Descriptive errors**: no logger needed; you decide how to handle or log errors.

---

## Installation

```bash
go get github.com/guarzo/eveauth
```

Replace `github.com/guarzo/eveauth` with your actual module path.

---

## Usage

Below is a minimal example of how to use `eveauth` in your application:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/guarzo/eveauth"
)

// myHttpClient wraps a standard http.Client so it implements eveauth.HttpClient.
type myHttpClient struct {
    client *http.Client
}
func (m *myHttpClient) Do(req *http.Request) (*http.Response, error) {
    return m.client.Do(req)
}

func main() {
    // 1) Construct the EVE auth client with your details.
    hc := &myHttpClient{client: &http.Client{Timeout: 10 * time.Second}}
    scopes := []string{"publicData", "esi-search.search_structures.v1"}
    client := eveauth.NewAuthClient(
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
        "https://yourdomain.com/callback", // or "http://localhost:8080/callback"
        scopes,
        hc,
    )

    // 2) Create a login handler that redirects users to EVE's auth page.
    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        // Use "main" as mode, "myApp" as appID (customize these as needed)
        authURL, err := client.GenerateAuthURL("main", "myApp")
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to build auth URL: %v", err), http.StatusInternalServerError)
            return
        }
        http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
    })

    // 3) Handle the EVE callback: parse the state, exchange the code, etc.
    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        code := r.URL.Query().Get("code")
        stateStr := r.URL.Query().Get("state")

        // Parse state
        authState, err := client.ParseState(stateStr)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to parse state: %v", err), http.StatusBadRequest)
            return
        }
        log.Printf("AuthState: %+v\n", authState)

        // Exchange the code for a token
        ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
        defer cancel()

        token, err := client.ExchangeCode(ctx, code)
        if err != nil {
            http.Error(w, fmt.Sprintf("Failed to exchange code: %v", err), http.StatusUnauthorized)
            return
        }

        // ... store token, retrieve character data, etc.
        fmt.Fprintf(w, "Success! AccessToken: %s\n", token.AccessToken)
    })

    log.Println("Starting server on :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## Auth State Helpers

`eveauth` offers a simple `AuthState` struct plus functions to encode/decode state:

- `NewAuthState(mode, appID string) AuthState`
- `EncodeState(as AuthState) (string, error)`
- `DecodeState(encoded string) (*AuthState, error)`

Use them if you want to embed additional info in the OAuth state parameter.

---

## Refreshing Tokens

To refresh an existing token:

```go
ctx := context.Background()
newToken, err := client.RefreshToken(ctx, oldRefreshToken)
if err != nil {
    // handle error
}
// use newToken.AccessToken, etc.
```

---

## Testing

We include a basic test suite using [Testify](https://github.com/stretchr/testify) in:

- `authclient_test.go`
- `auth_state_test.go`

Customize or expand these for your needs.

```bash
go test ./...
```

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with your changes.


---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

**Author**: [@guarzo](https://github.com/guarzo)
**Project Link**: [github.com/guarzo/eveauth](https://github.com/guarzo/eveauth)