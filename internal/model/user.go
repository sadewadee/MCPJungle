// Package model provides data models for the MCPJungle application.
package model

import (
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// User represents an authenticated, human user in enterprise mode.
// A user can be an admin or a regular user.
// There are no users if mcpjungle is running in development mode.
type User struct {
	gorm.Model

	Username    string         `json:"username" gorm:"unique; not null"`
	Role        types.UserRole `json:"role" gorm:"not null"`
	AccessToken string         `json:"access_token" gorm:"unique; not null"`

	// AllowList contains the names of the MCP servers this user can view and call, through the
	// REST API and through the MCP proxy after signing in with OAuth.
	// It is stored as a JSON array like McpClient.AllowList.
	// Admins can access all MCP servers regardless of this list.
	AllowList datatypes.JSON `json:"allow_list" gorm:"type:jsonb"`
}

// ServerAccess returns a function that reports whether the user may use the given MCP server.
// Admins may use all MCP servers. Standard users may only use the servers in their allow-list.
func (u *User) ServerAccess() func(serverName string) bool {
	if u.Role == types.UserRoleAdmin {
		return func(string) bool { return true }
	}
	return allowListAccess(u.AllowList)
}
