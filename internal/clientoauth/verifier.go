// Package clientoauth verifies OAuth access tokens that MCP clients present to the
// MCPJungle gateway. MCPJungle acts as an OAuth 2.1 resource server here: an external
// authorization server (Keycloak, Auth0, Okta, Entra ID, ...) issues JWT access tokens,
// and MCPJungle checks their signature against the issuer's published keys (JWKS) and
// their issuer, audience and expiry claims.
package clientoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// keysMaxAge is how long fetched signing keys are trusted before they are fetched again.
	keysMaxAge = time.Hour
	// unknownKeyRefetchInterval limits how often a token signed with an unknown key ID
	// can trigger a JWKS refetch, so that bogus tokens cannot be used to hammer the issuer.
	unknownKeyRefetchInterval = time.Minute
	// clockLeeway tolerates small clock differences between MCPJungle and the issuer.
	clockLeeway = time.Minute
	// DefaultUsernameClaim is the token claim mapped to an MCPJungle username by default.
	DefaultUsernameClaim = "sub"
)

// allowedAlgorithms lists the asymmetric signature algorithms accepted for access tokens.
// Symmetric (HS*) algorithms are deliberately excluded.
var allowedAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Config configures OAuth access token verification for MCP clients.
type Config struct {
	// Issuer is the issuer identifier of the authorization server. Tokens must carry it in "iss".
	Issuer string
	// Audience is the value tokens must carry in "aud".
	Audience string
	// PublicURL is the externally reachable base URL of MCPJungle, eg- https://mcp.example.com
	// It is used to build the protected resource identifiers and metadata URLs advertised to clients.
	PublicURL string
	// UsernameClaim is the token claim whose value is the MCPJungle username of the caller.
	UsernameClaim string
}

// Verifier verifies JWT access tokens issued by the configured authorization server.
type Verifier struct {
	cfg        Config
	httpClient *http.Client

	mu          sync.Mutex
	jwksURI     string
	keys        *jose.JSONWebKeySet
	fetchedAt   time.Time // last successful key fetch
	attemptedAt time.Time // last key fetch attempt
	fetchErr    error     // error of the last key fetch attempt
}

// NewVerifier validates the config and returns a Verifier.
// It does not contact the authorization server; keys are fetched on first use.
func NewVerifier(cfg Config, httpClient *http.Client) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("OAuth issuer is required")
	}
	if cfg.PublicURL == "" {
		return nil, errors.New("public URL of mcpjungle is required when OAuth is enabled for MCP clients")
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid public URL %q: must be an absolute URL like https://mcp.example.com", cfg.PublicURL)
	}
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if cfg.Audience == "" {
		cfg.Audience = cfg.PublicURL + "/mcp"
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = DefaultUsernameClaim
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{cfg: cfg, httpClient: httpClient}, nil
}

// Config returns the effective configuration, with defaults applied.
func (v *Verifier) Config() Config {
	return v.cfg
}

// Verify checks the access token and returns the caller's username, taken from the configured claim.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (string, error) {
	tok, err := jwt.ParseSigned(rawToken, allowedAlgorithms)
	if err != nil {
		return "", fmt.Errorf("malformed access token: %w", err)
	}
	if len(tok.Headers) != 1 {
		return "", errors.New("access token must have exactly one signature")
	}
	header := tok.Headers[0]

	key, err := v.signingKey(ctx, header.KeyID)
	if err != nil {
		return "", err
	}
	if key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return "", fmt.Errorf("access token algorithm %s does not match signing key algorithm %s", header.Algorithm, key.Algorithm)
	}

	var std jwt.Claims
	var all map[string]any
	if err := tok.Claims(key.Key, &std, &all); err != nil {
		return "", fmt.Errorf("invalid access token signature: %w", err)
	}
	if std.Expiry == nil {
		return "", errors.New("access token has no expiry")
	}
	expected := jwt.Expected{Issuer: v.cfg.Issuer, AnyAudience: jwt.Audience{v.cfg.Audience}}
	if err := std.ValidateWithLeeway(expected, clockLeeway); err != nil {
		return "", fmt.Errorf("access token rejected: %w", err)
	}

	username, _ := all[v.cfg.UsernameClaim].(string)
	if username == "" {
		return "", fmt.Errorf("access token has no %q claim", v.cfg.UsernameClaim)
	}
	return username, nil
}

// signingKey returns the issuer's public key with the given key ID, fetching the
// issuer's keys when they are missing, stale, or do not contain that key ID.
func (v *Verifier) signingKey(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	refreshed := false
	if v.keys == nil || time.Since(v.fetchedAt) > keysMaxAge {
		v.refreshKeysLocked(ctx)
		refreshed = true
	}
	if v.keys == nil {
		return nil, fmt.Errorf("signing keys of the authorization server are unavailable: %w", v.fetchErr)
	}
	if key := findKey(v.keys, kid); key != nil {
		return key, nil
	}
	// the issuer may have rotated its keys since we last fetched them
	if !refreshed {
		v.refreshKeysLocked(ctx)
		if key := findKey(v.keys, kid); key != nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("access token is signed with unknown key %q", kid)
}

// refreshKeysLocked fetches the issuer's keys, at most once per unknownKeyRefetchInterval.
// If the fetch fails, the keys fetched earlier stay in use, so that an unreachable
// authorization server does not lock out users whose tokens are still valid.
func (v *Verifier) refreshKeysLocked(ctx context.Context) {
	if time.Since(v.attemptedAt) < unknownKeyRefetchInterval {
		return
	}
	v.attemptedAt = time.Now()
	v.fetchErr = v.fetchKeysLocked(ctx)
	if v.fetchErr != nil {
		log.Printf("[WARN] failed to fetch signing keys of OAuth issuer %s: %v", v.cfg.Issuer, v.fetchErr)
	}
}

// findKey picks the public signing key for kid. A token without a key ID is
// accepted only when the issuer publishes exactly one signing key.
func findKey(keys *jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	var candidates []jose.JSONWebKey
	if kid != "" {
		candidates = keys.Key(kid)
	} else {
		candidates = keys.Keys
	}
	var found []jose.JSONWebKey
	for _, k := range candidates {
		if k.IsPublic() && (k.Use == "" || k.Use == "sig") {
			found = append(found, k)
		}
	}
	if len(found) != 1 {
		return nil
	}
	return &found[0]
}

func (v *Verifier) fetchKeysLocked(ctx context.Context) error {
	if v.jwksURI == "" {
		uri, err := v.discoverJWKSURI(ctx)
		if err != nil {
			return err
		}
		v.jwksURI = uri
	}
	var keys jose.JSONWebKeySet
	if err := v.getJSON(ctx, v.jwksURI, &keys); err != nil {
		return fmt.Errorf("failed to fetch signing keys from %s: %w", v.jwksURI, err)
	}
	v.keys = &keys
	v.fetchedAt = time.Now()
	return nil
}

// discoverJWKSURI reads the issuer's metadata, trying OpenID Connect discovery first
// and then OAuth 2.0 authorization server metadata (RFC 8414).
func (v *Verifier) discoverJWKSURI(ctx context.Context) (string, error) {
	issuer := strings.TrimRight(v.cfg.Issuer, "/")
	candidates := []string{issuer + "/.well-known/openid-configuration"}
	if u, err := url.Parse(issuer); err == nil {
		candidates = append(candidates, u.Scheme+"://"+u.Host+"/.well-known/oauth-authorization-server"+u.Path)
	}

	var errs []error
	for _, metadataURL := range candidates {
		var metadata struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.getJSON(ctx, metadataURL, &metadata); err != nil {
			errs = append(errs, err)
			continue
		}
		if metadata.Issuer != v.cfg.Issuer {
			return "", fmt.Errorf("authorization server metadata at %s names issuer %q, expected %q", metadataURL, metadata.Issuer, v.cfg.Issuer)
		}
		if metadata.JWKSURI == "" {
			return "", fmt.Errorf("authorization server metadata at %s has no jwks_uri", metadataURL)
		}
		return metadata.JWKSURI, nil
	}
	return "", fmt.Errorf("failed to discover authorization server metadata for issuer %s: %w", v.cfg.Issuer, errors.Join(errs...))
}

func (v *Verifier) getJSON(ctx context.Context, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned status %d", rawURL, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ResourceMetadata is the OAuth protected resource metadata document (RFC 9728)
// that tells MCP clients which authorization server issues tokens for a resource.
type ResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// ResourceMetadataFor returns the metadata for the resource served at path, eg- /mcp
func (v *Verifier) ResourceMetadataFor(path string) ResourceMetadata {
	return ResourceMetadata{
		Resource:               v.cfg.PublicURL + path,
		AuthorizationServers:   []string{v.cfg.Issuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "MCPJungle",
	}
}

// ResourceMetadataURL returns where the metadata for the resource served at path is published.
// It follows RFC 9728: the resource path is appended to the well-known path.
func (v *Verifier) ResourceMetadataURL(path string) string {
	return v.cfg.PublicURL + WellKnownPath + path
}

// WellKnownPath is the well-known path for OAuth protected resource metadata.
const WellKnownPath = "/.well-known/oauth-protected-resource"
