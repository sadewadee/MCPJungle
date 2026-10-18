package clientoauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPublicURL = "https://mcp.example.test"

// testIssuer is a minimal authorization server: OpenID discovery plus a JWKS endpoint.
type testIssuer struct {
	server *httptest.Server

	mu         sync.Mutex
	keys       []jose.JSONWebKey
	jwksHits   int
	jwksDown   bool
	oidcExists bool
}

func newTestIssuer(t *testing.T, oidcExists bool) *testIssuer {
	t.Helper()
	iss := &testIssuer{oidcExists: oidcExists}
	metadata := func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   iss.server.URL,
			"jwks_uri": iss.server.URL + "/jwks",
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if !iss.oidcExists {
			http.NotFound(w, r)
			return
		}
		metadata(w, r)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", metadata)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		iss.mu.Lock()
		defer iss.mu.Unlock()
		iss.jwksHits++
		if iss.jwksDown {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: iss.keys})
	})
	iss.server = httptest.NewServer(mux)
	t.Cleanup(iss.server.Close)
	return iss
}

// addKey publishes a new RSA signing key and returns its private half.
func (iss *testIssuer) addKey(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.keys = append(iss.keys, jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"})
	return jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.RS256)}
}

func sign(t *testing.T, key jose.JSONWebKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key}, nil)
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func validClaims(iss *testIssuer) map[string]any {
	return map[string]any{
		"iss": iss.server.URL,
		"aud": testPublicURL + "/mcp",
		"sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

func newTestVerifier(t *testing.T, iss *testIssuer, cfg Config) *Verifier {
	t.Helper()
	cfg.Issuer = iss.server.URL
	cfg.PublicURL = testPublicURL
	v, err := NewVerifier(cfg, nil)
	require.NoError(t, err)
	return v
}

func TestNewVerifier_RequiresIssuerAndAbsolutePublicURL(t *testing.T) {
	_, err := NewVerifier(Config{PublicURL: testPublicURL}, nil)
	assert.Error(t, err)

	_, err = NewVerifier(Config{Issuer: "https://idp.example.test"}, nil)
	assert.Error(t, err)

	_, err = NewVerifier(Config{Issuer: "https://idp.example.test", PublicURL: "mcp.example.test"}, nil)
	assert.Error(t, err)

	v, err := NewVerifier(Config{Issuer: "https://idp.example.test", PublicURL: testPublicURL + "/"}, nil)
	require.NoError(t, err)
	assert.Equal(t, testPublicURL+"/mcp", v.Config().Audience)
	assert.Equal(t, DefaultUsernameClaim, v.Config().UsernameClaim)
}

func TestVerify(t *testing.T) {
	iss := newTestIssuer(t, true)
	key := iss.addKey(t, "key-1")
	v := newTestVerifier(t, iss, Config{})

	hmacSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	require.NoError(t, err)
	hmacToken, err := jwt.Signed(hmacSigner).Claims(validClaims(iss)).Serialize()
	require.NoError(t, err)

	tests := []struct {
		name    string
		token   func() string
		wantErr string
	}{
		{
			name:  "valid token",
			token: func() string { return sign(t, key, validClaims(iss)) },
		},
		{
			name: "audience among several",
			token: func() string {
				c := validClaims(iss)
				c["aud"] = []string{"other-api", testPublicURL + "/mcp"}
				return sign(t, key, c)
			},
		},
		{
			name: "wrong audience",
			token: func() string {
				c := validClaims(iss)
				c["aud"] = "other-api"
				return sign(t, key, c)
			},
			wantErr: "audience",
		},
		{
			name: "wrong issuer",
			token: func() string {
				c := validClaims(iss)
				c["iss"] = "https://evil.example.test"
				return sign(t, key, c)
			},
			wantErr: "issuer",
		},
		{
			name: "expired",
			token: func() string {
				c := validClaims(iss)
				c["exp"] = time.Now().Add(-time.Hour).Unix()
				return sign(t, key, c)
			},
			wantErr: "expired",
		},
		{
			name: "no expiry",
			token: func() string {
				c := validClaims(iss)
				delete(c, "exp")
				return sign(t, key, c)
			},
			wantErr: "no expiry",
		},
		{
			name: "no username claim",
			token: func() string {
				c := validClaims(iss)
				delete(c, "sub")
				return sign(t, key, c)
			},
			wantErr: `no "sub" claim`,
		},
		{
			name:    "symmetric algorithm",
			token:   func() string { return hmacToken },
			wantErr: "malformed",
		},
		{
			name:    "not a JWT",
			token:   func() string { return "static-mcp-client-token" },
			wantErr: "malformed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, err := v.Verify(context.Background(), tt.token())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "alice", username)
		})
	}
}

func TestVerify_UsesConfiguredAudienceAndUsernameClaim(t *testing.T) {
	iss := newTestIssuer(t, true)
	key := iss.addKey(t, "key-1")
	v := newTestVerifier(t, iss, Config{Audience: "mcpjungle-api", UsernameClaim: "email"})

	c := validClaims(iss)
	c["aud"] = "mcpjungle-api"
	c["email"] = "alice@example.test"
	username, err := v.Verify(context.Background(), sign(t, key, c))
	require.NoError(t, err)
	assert.Equal(t, "alice@example.test", username)
}

func TestVerify_FallsBackToRFC8414Metadata(t *testing.T) {
	iss := newTestIssuer(t, false)
	key := iss.addKey(t, "key-1")
	v := newTestVerifier(t, iss, Config{})

	username, err := v.Verify(context.Background(), sign(t, key, validClaims(iss)))
	require.NoError(t, err)
	assert.Equal(t, "alice", username)
}

func TestVerify_RefetchesKeysAfterRotation(t *testing.T) {
	iss := newTestIssuer(t, true)
	oldKey := iss.addKey(t, "key-1")
	v := newTestVerifier(t, iss, Config{})

	_, err := v.Verify(context.Background(), sign(t, oldKey, validClaims(iss)))
	require.NoError(t, err)

	newKey := iss.addKey(t, "key-2")
	token := sign(t, newKey, validClaims(iss))

	// right after a fetch, an unknown key ID does not trigger another fetch
	_, err = v.Verify(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key")

	v.mu.Lock()
	v.attemptedAt = time.Now().Add(-2 * unknownKeyRefetchInterval)
	v.mu.Unlock()

	username, err := v.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "alice", username)

	iss.mu.Lock()
	defer iss.mu.Unlock()
	assert.Equal(t, 2, iss.jwksHits)
}

func TestVerify_KeepsKeysWhileIssuerIsUnreachable(t *testing.T) {
	iss := newTestIssuer(t, true)
	key := iss.addKey(t, "key-1")
	v := newTestVerifier(t, iss, Config{})
	token := sign(t, key, validClaims(iss))

	_, err := v.Verify(context.Background(), token)
	require.NoError(t, err)

	// the keys are due for a refresh, but the issuer is down
	iss.mu.Lock()
	iss.jwksDown = true
	iss.mu.Unlock()
	v.mu.Lock()
	v.fetchedAt = time.Now().Add(-2 * keysMaxAge)
	v.attemptedAt = time.Now().Add(-2 * unknownKeyRefetchInterval)
	v.mu.Unlock()

	for i := 0; i < 3; i++ {
		username, err := v.Verify(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, "alice", username)
	}

	// only one refresh attempt is made per refetch interval
	iss.mu.Lock()
	defer iss.mu.Unlock()
	assert.Equal(t, 2, iss.jwksHits)
}

func TestVerify_FailsFastWhenKeysWereNeverFetched(t *testing.T) {
	iss := newTestIssuer(t, true)
	key := iss.addKey(t, "key-1")
	iss.jwksDown = true
	v := newTestVerifier(t, iss, Config{})
	token := sign(t, key, validClaims(iss))

	for i := 0; i < 3; i++ {
		_, err := v.Verify(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unavailable")
	}

	iss.mu.Lock()
	defer iss.mu.Unlock()
	assert.Equal(t, 1, iss.jwksHits)
}

func TestVerify_RejectsMetadataForAnotherIssuer(t *testing.T) {
	iss := newTestIssuer(t, true)
	key := iss.addKey(t, "key-1")
	v, err := NewVerifier(Config{Issuer: iss.server.URL + "/realms/other", PublicURL: testPublicURL}, nil)
	require.NoError(t, err)

	c := validClaims(iss)
	c["iss"] = iss.server.URL + "/realms/other"
	_, err = v.Verify(context.Background(), sign(t, key, c))
	require.Error(t, err)
}

func TestResourceMetadata(t *testing.T) {
	v, err := NewVerifier(Config{Issuer: "https://idp.example.test", PublicURL: testPublicURL}, nil)
	require.NoError(t, err)

	md := v.ResourceMetadataFor("/v0/groups/eng/mcp")
	assert.Equal(t, testPublicURL+"/v0/groups/eng/mcp", md.Resource)
	assert.Equal(t, []string{"https://idp.example.test"}, md.AuthorizationServers)
	assert.Equal(t,
		testPublicURL+"/.well-known/oauth-protected-resource/mcp",
		v.ResourceMetadataURL("/mcp"),
	)
}
