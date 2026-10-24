package migrations

import (
	"testing"

	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestMigrate_GivesExistingUsersWithoutAllowListAllServers(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	if err := Migrate(db); err != nil {
		t.Fatalf("first migration failed: %v", err)
	}
	// users as they were stored before user allow-lists existed, plus one created since then
	users := []model.User{
		{Username: "old-user", Role: types.UserRoleUser, AccessToken: "t1"},
		{Username: "admin", Role: types.UserRoleAdmin, AccessToken: "t2"},
		{Username: "new-user", Role: types.UserRoleUser, AccessToken: "t3", AllowList: datatypes.JSON(`[]`)},
	}
	if err := db.Create(&users).Error; err != nil {
		t.Fatalf("failed to create users: %v", err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("second migration failed: %v", err)
	}

	want := map[string]string{"old-user": `["*"]`, "admin": "", "new-user": `[]`}
	for username, wantAllowList := range want {
		var u model.User
		if err := db.Where("username = ?", username).First(&u).Error; err != nil {
			t.Fatalf("failed to load %s: %v", username, err)
		}
		if string(u.AllowList) != wantAllowList {
			t.Errorf("%s allow-list = %q, want %q", username, string(u.AllowList), wantAllowList)
		}
	}
}
