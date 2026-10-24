package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mcpjungle/mcpjungle/client"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"github.com/spf13/cobra"
)

func TestRunUpdateUser(t *testing.T) {
	testCases := []struct {
		name       string
		flags      map[string]string
		wantBody   string
		wantOutput string
	}{
		{
			name:       "access token only",
			flags:      map[string]string{"access-token": "new-token"},
			wantBody:   `{"username":"alice","access_token":"new-token"}`,
			wantOutput: "User alice access token updated successfully.",
		},
		{
			name:       "allow-list only",
			flags:      map[string]string{"allow": "github, notion"},
			wantBody:   `{"username":"alice","allow_list":["github","notion"]}`,
			wantOutput: "User alice can now access: github,notion",
		},
		{
			name:       "empty allow-list removes access",
			flags:      map[string]string{"allow": ""},
			wantBody:   `{"username":"alice","allow_list":[]}`,
			wantOutput: "User alice can no longer access any MCP servers.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut || r.URL.Path != "/api/v0/users/alice" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				var buf bytes.Buffer
				_, _ = buf.ReadFrom(r.Body)
				gotBody = strings.TrimSpace(buf.String())
				_ = json.NewEncoder(w).Encode(types.CreateOrUpdateUserResponse{Username: "alice", Role: "user"})
			}))
			defer server.Close()

			origClient, origToken, origAllow := apiClient, updateUserAccessToken, updateUserAllowedServers
			defer func() {
				apiClient, updateUserAccessToken, updateUserAllowedServers = origClient, origToken, origAllow
			}()
			apiClient = client.NewClient(server.URL, "", http.DefaultClient)
			updateUserAccessToken, updateUserAllowedServers = "", ""

			cmd := &cobra.Command{}
			cmd.Flags().StringVar(&updateUserAccessToken, "access-token", "", "")
			cmd.Flags().StringVar(&updateUserAllowedServers, "allow", "", "")
			for name, value := range tc.flags {
				if err := cmd.Flags().Set(name, value); err != nil {
					t.Fatalf("failed to set flag %s: %v", name, err)
				}
			}
			var out bytes.Buffer
			cmd.SetOut(&out)

			if err := runUpdateUser(cmd, []string{"alice"}); err != nil {
				t.Fatalf("runUpdateUser returned error: %v", err)
			}
			if gotBody != tc.wantBody {
				t.Fatalf("request body = %s, want %s", gotBody, tc.wantBody)
			}
			if !strings.Contains(out.String(), tc.wantOutput) {
				t.Fatalf("output = %q, want it to contain %q", out.String(), tc.wantOutput)
			}
		})
	}
}

func TestUpdateUserCmdRequiresAFlag(t *testing.T) {
	for _, name := range []string{"access-token", "allow"} {
		flag := updateUserCmd.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("update user command has no --%s flag", name)
		}
		group := flag.Annotations["cobra_annotation_one_required"]
		if len(group) != 1 || group[0] != "access-token allow" {
			t.Fatalf("--%s is not in the one-required group with --access-token and --allow: %v", name, group)
		}
	}
}
