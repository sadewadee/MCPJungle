package e2e_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mcpjungle/mcpjungle/internal/api"
	"github.com/mcpjungle/mcpjungle/internal/clientoauth"
	"github.com/mcpjungle/mcpjungle/internal/clientoauth/clientoauthtest"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newEchoUpstream starts a public streamable HTTP MCP server with a single "echo" tool.
func newEchoUpstream(t *testing.T) string {
	t.Helper()
	upstream := mcpserver.NewMCPServer("echo-upstream", "0.1.0")
	upstream.AddTool(
		mcp.NewTool("echo", mcp.WithString("msg")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("echo"), nil
		},
	)
	srv := httptest.NewServer(mcpserver.NewStreamableHTTPServer(upstream))
	t.Cleanup(srv.Close)
	return srv.URL + "/mcp"
}

func TestE2E_EnterpriseMode_OAuthUserSeesOnlyAllowedServers(t *testing.T) {
	issuer := clientoauthtest.NewIssuer(t)
	const publicURL = "https://mcp.example.test"
	verifier, err := clientoauth.NewVerifier(clientoauth.Config{Issuer: issuer.URL, PublicURL: publicURL}, nil)
	require.NoError(t, err)

	env := setupE2EServerWithOptions(t, model.ModeEnterprise, func(opts *api.ServerOptions) {
		opts.ClientOAuth = verifier
	})

	for _, name := range []string{"srva", "srvb", "srvc", "srvd"} {
		resp := env.do(t, http.MethodPost, "/api/v0/servers", map[string]any{
			"name": name, "transport": "streamable_http", "url": newEchoUpstream(t),
		}, env.adminToken)
		drain(resp)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	}

	// user1 may use three servers, user2 only two
	for username, allowed := range map[string][]string{"user1": {"srva", "srvb", "srvc"}, "user2": {"srvc", "srvd"}} {
		resp := env.do(t, http.MethodPost, "/api/v0/users", map[string]any{
			"username": username, "allow_list": allowed,
		}, env.adminToken)
		drain(resp)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	}

	connect := func(t *testing.T, username string) *client.Client {
		t.Helper()
		token := issuer.Token(t, username, publicURL+"/mcp")
		c, err := client.NewStreamableHttpClient(
			env.baseURL+"/mcp",
			transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + token}),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		init := mcp.InitializeRequest{}
		init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
		_, err = c.Initialize(context.Background(), init)
		require.NoError(t, err)
		return c
	}
	toolNamesOf := func(t *testing.T, c *client.Client) []string {
		t.Helper()
		res, err := c.ListTools(context.Background(), mcp.ListToolsRequest{})
		require.NoError(t, err)
		var names []string
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		return names
	}
	callEcho := func(c *client.Client, tool string) error {
		req := mcp.CallToolRequest{}
		req.Params.Name = tool
		req.Params.Arguments = map[string]any{"msg": "hi"}
		_, err := c.CallTool(context.Background(), req)
		return err
	}

	user1 := connect(t, "user1")
	assert.ElementsMatch(t, []string{"srva__echo", "srvb__echo", "srvc__echo"}, toolNamesOf(t, user1))
	assert.NoError(t, callEcho(user1, "srvb__echo"))
	assert.Error(t, callEcho(user1, "srvd__echo"))

	user2 := connect(t, "user2")
	assert.ElementsMatch(t, []string{"srvc__echo", "srvd__echo"}, toolNamesOf(t, user2))
	assert.NoError(t, callEcho(user2, "srvd__echo"))
	assert.Error(t, callEcho(user2, "srva__echo"))

	// without a token, the MCP endpoint tells the client where to sign in
	resp := env.do(t, http.MethodPost, "/mcp", map[string]any{}, "")
	drain(resp)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t,
		`Bearer resource_metadata="`+publicURL+`/.well-known/oauth-protected-resource/mcp"`,
		resp.Header.Get("WWW-Authenticate"),
	)
}
