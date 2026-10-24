// Package migrations provides database migration functionality for the MCPJungle application.
package migrations

import (
	"fmt"

	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Migrate performs the database migration for the application.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&model.McpServer{}); err != nil {
		return fmt.Errorf("auto‑migration failed for McpServer model: %v", err)
	}
	if err := db.AutoMigrate(&model.Tool{}); err != nil {
		return fmt.Errorf("auto‑migration failed for Tool model: %v", err)
	}
	if err := db.AutoMigrate(&model.ServerConfig{}); err != nil {
		return fmt.Errorf("auto‑migration failed for ServerConfig model: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}); err != nil {
		return fmt.Errorf("auto‑migration failed for User model: %v", err)
	}
	// Standard users created before user allow-lists existed have no allow-list, and they could use
	// every MCP server through the REST API. Keep that access by allowing them all servers.
	// Users created since then always get an allow-list, so this only touches those older users.
	if err := db.Model(&model.User{}).
		Where("role = ? AND allow_list IS NULL", types.UserRoleUser).
		Update("allow_list", datatypes.JSON(fmt.Sprintf(`[%q]`, types.AllowAllMcpServers))).Error; err != nil {
		return fmt.Errorf("failed to set allow-lists of existing users: %v", err)
	}
	if err := db.AutoMigrate(&model.McpClient{}); err != nil {
		return fmt.Errorf("auto‑migration failed for McpClient model: %v", err)
	}
	if err := db.AutoMigrate(&model.ToolGroup{}); err != nil {
		return fmt.Errorf("auto‑migration failed for ToolGroup model: %v", err)
	}
	if err := db.AutoMigrate(&model.Prompt{}); err != nil {
		return fmt.Errorf("auto‑migration failed for Prompt model: %v", err)
	}
	if err := db.AutoMigrate(&model.Resource{}); err != nil {
		return fmt.Errorf("auto‑migration failed for Resource model: %v", err)
	}
	if err := db.AutoMigrate(&model.UpstreamOAuthPendingSession{}); err != nil {
		return fmt.Errorf("auto-migration failed for UpstreamOAuthPendingSession model: %v", err)
	}
	if err := db.AutoMigrate(&model.UpstreamOAuthToken{}); err != nil {
		return fmt.Errorf("auto-migration failed for UpstreamOAuthToken model: %v", err)
	}
	return nil
}
