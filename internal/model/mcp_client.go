package model

import (
	"encoding/json"

	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// McpClient represents MCP clients and their access to the MCP Servers provided MCPJungle MCP server
type McpClient struct {
	gorm.Model

	Name        string `json:"name" gorm:"uniqueIndex;not null"`
	Description string `json:"description"`

	AccessToken string `json:"access_token" gorm:"unique; not null"`

	// AllowList contains a list of MCP Server names that this client is allowed to view and call
	// storing the list of server names as a JSON array is a convenient way for now.
	// In the future, this will be removed in favor of a separate table for ACLs.
	AllowList datatypes.JSON `json:"allow_list" gorm:"type:jsonb; not null"`
}

// CheckHasServerAccess returns true if this client has access to the specified MCP server.
// If not, it returns false.
func (c *McpClient) CheckHasServerAccess(serverName string) bool {
	return allowListAccess(c.AllowList)(serverName)
}

// allowListAccess returns a function that reports whether a JSON allow-list of MCP server names
// permits the given server. A wildcard entry permits all servers.
// A missing or invalid allow-list permits no servers.
func allowListAccess(allowList datatypes.JSON) func(serverName string) bool {
	var allowedServers []string
	if allowList == nil || json.Unmarshal(allowList, &allowedServers) != nil {
		return func(string) bool { return false }
	}
	allowed := make(map[string]bool, len(allowedServers))
	for _, name := range allowedServers {
		if name == types.AllowAllMcpServers {
			return func(string) bool { return true }
		}
		allowed[name] = true
	}
	return func(serverName string) bool { return allowed[serverName] }
}
