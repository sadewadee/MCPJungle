package cmd

import (
	"fmt"
	"strings"

	"github.com/mcpjungle/mcpjungle/pkg/types"
	"github.com/mcpjungle/mcpjungle/pkg/util"
	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update entities",
	Annotations: map[string]string{
		"group": string(subCommandGroupAdvanced),
		"order": "8",
	},
}

var updateToolGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Update a tool group",
	Long: "Update an existing Tool Group\n" +
		"This option allows you to supply the modified configuration file of an existing Tool group.\n" +
		"The new configuration completely overrides the existing one.\n" +
		"Note that you cannot update the name of a group once it is created.\n" +
		"Updating a group does not cause any downtime for the MCP clients relying on its endpoint.\n\n" +
		"CAUTION: If you remove any tools from the configuration (by removing them from include or adding them to exclude), " +
		"calling update will immediately remove them from the group. " +
		"They will no longer be accessible by MCP clients using the group's MCP server.",
	RunE: runUpdateGroup,
}

var updateMcpClientCmd = &cobra.Command{
	Use:   "mcp-client [name]",
	Args:  cobra.ExactArgs(1),
	Short: "Update an MCP client",
	Long: "Update an existing MCP client\n" +
		"Currently, this command only supports updating the access token of the MCP client.\n" +
		"This is useful when you use custom tokens and you want to rotate the access token of a client.",
	RunE: runUpdateMcpClient,
}

var updateUserCmd = &cobra.Command{
	Use:   "user [name]",
	Args:  cobra.ExactArgs(1),
	Short: "Update a user",
	Long: "Update an existing user's access token, the MCP servers they can access, or both.\n\n" +
		"Use --access-token to rotate the access token of a user who uses a custom token.\n" +
		"Use --allow to replace the list of MCP servers the user can access through the API and the MCP proxy.\n" +
		"Pass --allow \"\" to remove the user's access to all MCP servers.",
	RunE: runUpdateUser,
}

var (
	updateToolGroupConfigFilePath string

	updateMcpClientAccessToken string

	updateUserAccessToken    string
	updateUserAllowedServers string
)

func init() {
	updateToolGroupCmd.Flags().StringVarP(
		&updateToolGroupConfigFilePath,
		"conf",
		"c",
		"",
		"Path to new JSON configuration file for the Tool Group",
	)
	_ = updateToolGroupCmd.MarkFlagRequired("conf")

	updateMcpClientCmd.Flags().StringVar(
		&updateMcpClientAccessToken,
		"access-token",
		"",
		"New access token for the MCP client",
	)
	_ = updateMcpClientCmd.MarkFlagRequired("access-token")

	updateUserCmd.Flags().StringVar(
		&updateUserAccessToken,
		"access-token",
		"",
		"New access token for the user",
	)
	updateUserCmd.Flags().StringVar(
		&updateUserAllowedServers,
		"allow",
		"",
		"Comma-separated list of MCP servers the user can access, replacing the current list (eg- \"github, notion\")",
	)
	updateUserCmd.MarkFlagsOneRequired("access-token", "allow")

	updateCmd.AddCommand(updateToolGroupCmd)
	updateCmd.AddCommand(updateMcpClientCmd)
	updateCmd.AddCommand(updateUserCmd)

	rootCmd.AddCommand(updateCmd)
}

func runUpdateGroup(cmd *cobra.Command, args []string) error {
	updatedConf, err := readToolGroupConfig(updateToolGroupConfigFilePath)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", updateToolGroupConfigFilePath, err)
	}

	resp, err := apiClient.UpdateToolGroup(updatedConf)
	if err != nil {
		return fmt.Errorf("failed to update tool group %s: %w", updatedConf.Name, err)
	}

	// Check if anything was actually changed
	toolsAdded, toolsRemoved := util.DiffTools(resp.Old.IncludedTools, resp.New.IncludedTools)
	serversAdded, serversRemoved := util.DiffTools(resp.Old.IncludedServers, resp.New.IncludedServers)
	excludedAdded, excludedRemoved := util.DiffTools(resp.Old.ExcludedTools, resp.New.ExcludedTools)

	noChangeInTools := len(toolsAdded) == 0 && len(toolsRemoved) == 0
	noChangeInServers := len(serversAdded) == 0 && len(serversRemoved) == 0
	noChangeInExcluded := len(excludedAdded) == 0 && len(excludedRemoved) == 0

	if resp.Old.Description == resp.New.Description && noChangeInTools && noChangeInServers && noChangeInExcluded {
		cmd.Printf("No changes detected for Tool Group %s. Nothing was updated.\n", resp.Name)
		return nil
	}

	cmd.Printf("Tool Group %s updated successfully\n\n", resp.Name)

	if resp.Old.Description != resp.New.Description {
		cmd.Printf("* Description updated from:\n    %s\nto:\n    %s\n\n", resp.Old.Description, resp.New.Description)
	}

	// Report changes in included_tools
	if noChangeInTools {
		cmd.Println("* No changes in included_tools")
	} else {
		if len(toolsRemoved) > 0 {
			cmd.Println("* Tools removed from included_tools:")
			for _, t := range toolsRemoved {
				cmd.Printf("    - %s\n", t)
			}
		}
		if len(toolsAdded) > 0 {
			cmd.Println("* Tools added to included_tools:")
			for _, t := range toolsAdded {
				cmd.Printf("    - %s\n", t)
			}
		}
	}
	cmd.Println()

	// Report changes in included_servers
	if !noChangeInServers {
		if len(serversRemoved) > 0 {
			cmd.Println("* Servers removed from included_servers:")
			for _, s := range serversRemoved {
				cmd.Printf("    - %s\n", s)
			}
		}
		if len(serversAdded) > 0 {
			cmd.Println("* Servers added to included_servers:")
			for _, s := range serversAdded {
				cmd.Printf("    - %s\n", s)
			}
		}
		cmd.Println()
	}

	// Report changes in excluded_tools
	if !noChangeInExcluded {
		if len(excludedRemoved) > 0 {
			cmd.Println("* Tools removed from excluded_tools:")
			for _, e := range excludedRemoved {
				cmd.Printf("    - %s\n", e)
			}
		}
		if len(excludedAdded) > 0 {
			cmd.Println("* Tools added to excluded_tools:")
			for _, e := range excludedAdded {
				cmd.Printf("    - %s\n", e)
			}
		}
		cmd.Println()
	}

	return nil
}

func runUpdateMcpClient(cmd *cobra.Command, args []string) error {
	client := &types.McpClient{
		Name:                args[0],
		AccessToken:         updateMcpClientAccessToken,
		IsCustomAccessToken: true,
	}
	if err := apiClient.UpdateMcpClient(client); err != nil {
		return fmt.Errorf("failed to update MCP client %s: %w", client.Name, err)
	}

	cmd.Printf("MCP client %s access token updated successfully.\n", client.Name)
	return nil
}

func runUpdateUser(cmd *cobra.Command, args []string) error {
	user := &types.UpdateUserRequest{
		Username:    args[0],
		AccessToken: updateUserAccessToken,
	}
	if cmd.Flags().Changed("allow") {
		allowList := parseAllowList(updateUserAllowedServers, cmd)
		user.AllowList = &allowList
	}
	_, err := apiClient.UpdateUser(user)
	if err != nil {
		return fmt.Errorf("failed to update user %s: %w", user.Username, err)
	}
	if user.AccessToken != "" {
		cmd.Printf("User %s access token updated successfully.\n", user.Username)
	}
	if user.AllowList != nil {
		if len(*user.AllowList) > 0 {
			cmd.Printf("User %s can now access: %s\n", user.Username, strings.Join(*user.AllowList, ","))
		} else {
			cmd.Printf("User %s can no longer access any MCP servers.\n", user.Username)
		}
	}
	return nil
}
