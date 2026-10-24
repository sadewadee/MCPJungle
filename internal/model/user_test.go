package model

import (
	"testing"

	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
)

func TestUser_ServerAccess(t *testing.T) {
	cases := []struct {
		name   string
		user   User
		server string
		want   bool
	}{
		{
			name:   "admin can access any server",
			user:   User{Role: types.UserRoleAdmin},
			server: "server-a",
			want:   true,
		},
		{
			name:   "user without allow list",
			user:   User{Role: types.UserRoleUser},
			server: "server-a",
			want:   false,
		},
		{
			name:   "user with empty allow list",
			user:   User{Role: types.UserRoleUser, AllowList: datatypes.JSON("[]")},
			server: "server-a",
			want:   false,
		},
		{
			name:   "server in allow list",
			user:   User{Role: types.UserRoleUser, AllowList: datatypes.JSON(`["server-a","server-b"]`)},
			server: "server-b",
			want:   true,
		},
		{
			name:   "server not in allow list",
			user:   User{Role: types.UserRoleUser, AllowList: datatypes.JSON(`["server-a","server-b"]`)},
			server: "server-c",
			want:   false,
		},
		{
			name:   "wildcard allows any server",
			user:   User{Role: types.UserRoleUser, AllowList: datatypes.JSON(`["*"]`)},
			server: "server-c",
			want:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.user.ServerAccess()(tc.server); got != tc.want {
				t.Fatalf("ServerAccess()(%q) = %v, want %v", tc.server, got, tc.want)
			}
		})
	}
}
