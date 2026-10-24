package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/model"
)

// serverAccessOf returns a function that reports whether the caller of a REST API request may use
// the given MCP server. In development mode, and for admins, every server is allowed.
// A standard user in enterprise mode may only use the servers in their allow-list.
func serverAccessOf(c *gin.Context) func(serverName string) bool {
	if mode, ok := c.Get("mode"); ok {
		if m, ok := mode.(model.ServerMode); ok && !model.IsEnterpriseMode(m) {
			return func(string) bool { return true }
		}
	}
	authenticatedUser, _ := c.Get("user")
	u, ok := authenticatedUser.(*model.User)
	if !ok || u == nil {
		// enterprise mode always authenticates the user before this point, so fail closed
		return func(string) bool { return false }
	}
	return u.ServerAccess()
}

// requireServerAccess rejects the request with 403 unless the caller may use the given MCP server.
// It returns false if the request was rejected.
func requireServerAccess(c *gin.Context, serverName string) bool {
	if serverAccessOf(c)(serverName) {
		return true
	}
	c.AbortWithStatusJSON(
		http.StatusForbidden,
		gin.H{"error": fmt.Sprintf("user is not authorized to access MCP server %s", serverName)},
	)
	return false
}

// keepAccessible returns the items whose MCP server the caller may use.
func keepAccessible[T any](c *gin.Context, items []T, serverOf func(T) string) []T {
	allowed := serverAccessOf(c)
	kept := make([]T, 0, len(items))
	for _, item := range items {
		if allowed(serverOf(item)) {
			kept = append(kept, item)
		}
	}
	return kept
}
