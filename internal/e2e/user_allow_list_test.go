package e2e_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamWithEverything starts a streamable HTTP MCP server with one tool ("echo"),
// one prompt ("greet") and one resource ("resource://upstream/status").
func newUpstreamWithEverything(t *testing.T) string {
	t.Helper()
	upstream := mcpserver.NewMCPServer("upstream", "0.1.0")
	upstream.AddTool(
		mcp.NewTool("echo", mcp.WithString("msg")),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("echo"), nil
		},
	)
	upstream.AddPrompt(
		mcp.Prompt{Name: "greet"},
		func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Messages: []mcp.PromptMessage{
					mcp.NewPromptMessage(mcp.RoleAssistant, mcp.TextContent{Type: "text", Text: "hello"}),
				},
			}, nil
		},
	)
	upstream.AddResource(
		mcp.Resource{URI: "resource://upstream/status", Name: "status", MIMEType: "text/plain"},
		func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "text/plain", Text: "ok"},
			}, nil
		},
	)
	srv := httptest.NewServer(mcpserver.NewStreamableHTTPServer(upstream))
	t.Cleanup(srv.Close)
	return srv.URL + "/mcp"
}

func resourceURIOf(server string) string {
	return "mcpj://res/" + server + "/" + base64.RawStdEncoding.EncodeToString([]byte("resource://upstream/status"))
}

func TestE2E_EnterpriseMode_RestAPI_EnforcesUserAllowList(t *testing.T) {
	env := setupE2EServer(t, model.ModeEnterprise)

	for _, name := range []string{"srva", "srvb"} {
		resp := env.do(t, http.MethodPost, "/api/v0/servers", map[string]any{
			"name": name, "transport": "streamable_http", "url": newUpstreamWithEverything(t),
		}, env.adminToken)
		drain(resp)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
	}

	resp := env.do(t, http.MethodPost, "/api/v0/users", map[string]any{
		"username": "alice", "allow_list": []string{"srva"},
	}, env.adminToken)
	defer drain(resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created map[string]any
	decodeJSON(t, resp, &created)
	aliceToken, _ := created["access_token"].(string)
	require.NotEmpty(t, aliceToken)

	listNames := func(t *testing.T, path, token string) []string {
		t.Helper()
		resp := env.do(t, http.MethodGet, path, nil, token)
		defer drain(resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		var items []map[string]any
		decodeJSON(t, resp, &items)
		return toolNames(items)
	}
	status := func(t *testing.T, method, path string, body any, token string) int {
		t.Helper()
		resp := env.do(t, method, path, body, token)
		drain(resp)
		return resp.StatusCode
	}

	t.Run("lists show only allowed servers", func(t *testing.T) {
		assert.Equal(t, []string{"srva"}, listNames(t, "/api/v0/servers", aliceToken))
		assert.Equal(t, []string{"srva__echo"}, listNames(t, "/api/v0/tools", aliceToken))
		assert.Equal(t, []string{"srva__greet"}, listNames(t, "/api/v0/prompts", aliceToken))
		assert.Equal(t, []string{"srva__status"}, listNames(t, "/api/v0/resources", aliceToken))
	})

	t.Run("admin still sees all servers", func(t *testing.T) {
		assert.ElementsMatch(t, []string{"srva", "srvb"}, listNames(t, "/api/v0/servers", env.adminToken))
		assert.ElementsMatch(t, []string{"srva__echo", "srvb__echo"}, listNames(t, "/api/v0/tools", env.adminToken))
	})

	t.Run("allowed server", func(t *testing.T) {
		assert.Equal(t, []string{"srva__echo"}, listNames(t, "/api/v0/tools?server=srva", aliceToken))
		assert.Equal(t, http.StatusOK, status(t, http.MethodGet, "/api/v0/tool?name=srva__echo", nil, aliceToken))
		assert.Equal(t, http.StatusOK, status(t, http.MethodPost, "/api/v0/tools/invoke",
			map[string]any{"name": "srva__echo", "msg": "hi"}, aliceToken))
		assert.Equal(t, http.StatusOK, status(t, http.MethodGet, "/api/v0/prompt?name=srva__greet", nil, aliceToken))
		assert.Equal(t, http.StatusOK, status(t, http.MethodPost, "/api/v0/prompts/render",
			map[string]any{"name": "srva__greet"}, aliceToken))
		assert.Equal(t, http.StatusOK, status(t, http.MethodPost, "/api/v0/resources/get",
			map[string]any{"uri": resourceURIOf("srva")}, aliceToken))
		assert.Equal(t, http.StatusOK, status(t, http.MethodPost, "/api/v0/resources/read",
			map[string]any{"uri": resourceURIOf("srva")}, aliceToken))
	})

	t.Run("server outside the allow-list is forbidden", func(t *testing.T) {
		requests := []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, "/api/v0/tools?server=srvb", nil},
			{http.MethodGet, "/api/v0/prompts?server=srvb", nil},
			{http.MethodGet, "/api/v0/resources?server=srvb", nil},
			{http.MethodGet, "/api/v0/tool?name=srvb__echo", nil},
			{http.MethodPost, "/api/v0/tools/invoke", map[string]any{"name": "srvb__echo", "msg": "hi"}},
			{http.MethodGet, "/api/v0/prompt?name=srvb__greet", nil},
			{http.MethodPost, "/api/v0/prompts/render", map[string]any{"name": "srvb__greet"}},
			{http.MethodPost, "/api/v0/resources/get", map[string]any{"uri": resourceURIOf("srvb")}},
			{http.MethodPost, "/api/v0/resources/read", map[string]any{"uri": resourceURIOf("srvb")}},
		}
		for _, r := range requests {
			assert.Equal(t, http.StatusForbidden, status(t, r.method, r.path, r.body, aliceToken), "%s %s", r.method, r.path)
		}
	})

	t.Run("updating the allow-list takes effect immediately", func(t *testing.T) {
		resp := env.do(t, http.MethodPut, "/api/v0/users/alice", map[string]any{
			"username": "alice", "allow_list": []string{"srva", "srvb"},
		}, env.adminToken)
		drain(resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.ElementsMatch(t, []string{"srva__echo", "srvb__echo"}, listNames(t, "/api/v0/tools", aliceToken))

		resp = env.do(t, http.MethodPut, "/api/v0/users/alice", map[string]any{
			"username": "alice", "allow_list": []string{},
		}, env.adminToken)
		drain(resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, listNames(t, "/api/v0/tools", aliceToken))
		assert.Equal(t, http.StatusForbidden, status(t, http.MethodPost, "/api/v0/tools/invoke",
			map[string]any{"name": "srva__echo"}, aliceToken))
	})
}

func TestE2E_DevMode_RestAPI_HasNoAllowList(t *testing.T) {
	env := setupE2EServer(t, model.ModeDev)
	resp := env.do(t, http.MethodPost, "/api/v0/servers", map[string]any{
		"name": "srva", "transport": "streamable_http", "url": newUpstreamWithEverything(t),
	}, "")
	drain(resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp = env.do(t, http.MethodGet, "/api/v0/tools?server="+url.QueryEscape("srva"), nil, "")
	defer drain(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var tools []map[string]any
	decodeJSON(t, resp, &tools)
	assert.Equal(t, []string{"srva__echo"}, toolNames(tools))
}
