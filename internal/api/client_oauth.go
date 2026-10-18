package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/pkg/apierrors"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
)

// protectedResourceMetadataHandler serves the OAuth protected resource metadata for an MCP endpoint.
// The endpoint's path follows the well-known path, eg- /.well-known/oauth-protected-resource/mcp
// The bare well-known path describes the main /mcp endpoint.
func (s *Server) protectedResourceMetadataHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		resource := c.Param("resource")
		if resource == "" || resource == "/" {
			resource = "/mcp"
		}
		c.JSON(http.StatusOK, s.clientOAuth.ResourceMetadataFor(resource))
	}
}

// abortMcpUnauthorized rejects an MCP proxy request with 401.
// When OAuth is enabled for MCP clients, the WWW-Authenticate header points the client
// at the protected resource metadata, which is how MCP clients find out where users sign in.
// oauthError is an RFC 6750 error code such as "invalid_token", or empty when no token was sent.
func (s *Server) abortMcpUnauthorized(c *gin.Context, oauthError, message string) {
	if s.clientOAuth != nil {
		metadataURL := s.clientOAuth.ResourceMetadataURL(c.Request.URL.EscapedPath())
		challenge := fmt.Sprintf(`Bearer resource_metadata="%s"`, metadataURL)
		if oauthError != "" {
			challenge = fmt.Sprintf(`Bearer error="%s", resource_metadata="%s"`, oauthError, metadataURL)
		}
		c.Header("WWW-Authenticate", challenge)
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": message})
}

// mcpClientForUser returns the MCP client identity of a user who signed in with OAuth,
// carrying the user's server allow-list, so that the MCP proxy restricts the user exactly
// as it restricts MCP clients. Admins can access all MCP servers.
func (s *Server) mcpClientForUser(username string) (*model.McpClient, error) {
	u, err := s.userService.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	allowList := u.AllowList
	if u.Role == types.UserRoleAdmin {
		allowList = datatypes.JSON(fmt.Sprintf(`[%q]`, types.AllowAllMcpServers))
	}
	return &model.McpClient{Name: "user:" + u.Username, AllowList: allowList}, nil
}

// authenticateOAuthUser verifies an OAuth access token presented to the MCP proxy and
// returns the signed-in user's MCP client identity. On failure, it aborts the request.
func (s *Server) authenticateOAuthUser(c *gin.Context, token string) (*model.McpClient, bool) {
	username, err := s.clientOAuth.Verify(c.Request.Context(), token)
	if err != nil {
		log.Printf("[WARN] rejected MCP client token: %v", err)
		s.abortMcpUnauthorized(c, "invalid_token", "invalid MCP client token")
		return nil, false
	}
	client, err := s.mcpClientForUser(username)
	if err != nil {
		if errors.Is(err, apierrors.ErrNotFound) {
			c.AbortWithStatusJSON(
				http.StatusForbidden,
				gin.H{"error": fmt.Sprintf("user %s signed in, but is not registered in mcpjungle", username)},
			)
			return nil, false
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to look up user: " + err.Error()})
		return nil, false
	}
	return client, true
}
