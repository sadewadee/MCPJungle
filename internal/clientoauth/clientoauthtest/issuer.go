// Package clientoauthtest provides a fake OAuth authorization server for tests of
// OAuth sign-in for MCP clients.
package clientoauthtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Issuer serves OpenID discovery metadata and a JWKS, and signs access tokens.
type Issuer struct {
	// URL is the issuer identifier, which is also the server's base URL.
	URL string

	key jose.JSONWebKey
}

// NewIssuer starts a fake authorization server that is stopped when the test ends.
func NewIssuer(t *testing.T) *Issuer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	iss := &Issuer{key: jose.JSONWebKey{Key: priv, KeyID: "test-key", Algorithm: string(jose.RS256)}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss.URL, "jwks_uri": iss.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{iss.key.Public()}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	iss.URL = server.URL
	return iss
}

// Token returns an access token for subject, issued for audience and valid for an hour.
func (iss *Issuer) Token(t *testing.T, subject, audience string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: iss.key}, nil)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	now := time.Now()
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   iss.URL,
		Subject:  subject,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}).Serialize()
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}
