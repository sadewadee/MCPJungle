package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/clientoauth"
	"github.com/mcpjungle/mcpjungle/internal/clientoauth/clientoauthtest"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/service/mcpclient"
	"github.com/mcpjungle/mcpjungle/internal/service/user"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPublicURL = "https://mcp.example.test"

func TestCheckAuthForMcpProxyAccess_OAuthUsers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setup := testhelpers.SetupTestDB(t)
	defer setup.Cleanup()

	mcpClientService := mcpclient.NewMCPClientService(setup.DB)
	userService := user.NewUserService(setup.DB)
	_, err := userService.CreateUser(&model.User{Username: "alice", AllowList: []byte(`["srva"]`)})
	require.NoError(t, err)
	_, err = userService.CreateAdminUser()
	require.NoError(t, err)
	_, err = mcpClientService.CreateClient(model.McpClient{
		Name: "cursor", AccessToken: "static-client-token", AllowList: []byte(`["srvb"]`),
	})
	require.NoError(t, err)

	issuer := clientoauthtest.NewIssuer(t)
	verifier, err := clientoauth.NewVerifier(clientoauth.Config{Issuer: issuer.URL, PublicURL: testPublicURL}, nil)
	require.NoError(t, err)
	audience := testPublicURL + "/mcp"

	server := &Server{mcpClientService: mcpClientService, userService: userService, clientOAuth: verifier}
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("mode", model.ModeEnterprise) })
	router.Use(server.checkAuthForMcpProxyAccess())
	router.GET("/mcp", func(c *gin.Context) {
		client := c.Request.Context().Value("client").(*model.McpClient)
		c.JSON(http.StatusOK, gin.H{"client": client.Name, "allow_list": json.RawMessage(client.AllowList)})
	})

	metadataURL := testPublicURL + "/.well-known/oauth-protected-resource/mcp"
	tests := []struct {
		name          string
		token         string
		wantStatus    int
		wantBody      string
		wantChallenge string
	}{
		{
			name:          "missing token points the client at the resource metadata",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Bearer resource_metadata="` + metadataURL + `"`,
		},
		{
			name:          "token for another audience",
			token:         issuer.Token(t, "alice", "other-api"),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Bearer error="invalid_token", resource_metadata="` + metadataURL + `"`,
		},
		{
			name:       "user gets their own allow-list",
			token:      issuer.Token(t, "alice", audience),
			wantStatus: http.StatusOK,
			wantBody:   `{"allow_list":["srva"],"client":"user:alice"}`,
		},
		{
			name:       "admin can access all servers",
			token:      issuer.Token(t, "admin", audience),
			wantStatus: http.StatusOK,
			wantBody:   `{"allow_list":["*"],"client":"user:admin"}`,
		},
		{
			name:       "signed-in user unknown to mcpjungle",
			token:      issuer.Token(t, "mallory", audience),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "static MCP client tokens keep working",
			token:      "static-client-token",
			wantStatus: http.StatusOK,
			wantBody:   `{"allow_list":["srvb"],"client":"cursor"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code, w.Body.String())
			if tt.wantBody != "" {
				assert.JSONEq(t, tt.wantBody, w.Body.String())
			}
			assert.Equal(t, tt.wantChallenge, w.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestProtectedResourceMetadataHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	verifier, err := clientoauth.NewVerifier(clientoauth.Config{Issuer: "https://idp.example.test", PublicURL: testPublicURL}, nil)
	require.NoError(t, err)

	server := &Server{clientOAuth: verifier}
	router := gin.New()
	router.GET(clientoauth.WellKnownPath, server.protectedResourceMetadataHandler())
	router.GET(clientoauth.WellKnownPath+"/*resource", server.protectedResourceMetadataHandler())

	for path, wantResource := range map[string]string{
		clientoauth.WellKnownPath:                      testPublicURL + "/mcp",
		clientoauth.WellKnownPath + "/mcp":             testPublicURL + "/mcp",
		clientoauth.WellKnownPath + "/v0/groups/x/mcp": testPublicURL + "/v0/groups/x/mcp",
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, w.Code, path)

		var md clientoauth.ResourceMetadata
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &md))
		assert.Equal(t, wantResource, md.Resource, path)
		assert.Equal(t, []string{"https://idp.example.test"}, md.AuthorizationServers, path)
	}
}
