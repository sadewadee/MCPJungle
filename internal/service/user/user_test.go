package user

import (
	"errors"
	"testing"

	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/pkg/apierrors"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
	"github.com/mcpjungle/mcpjungle/pkg/types"
)

func TestNewUserService(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	testhelpers.AssertNotNil(t, svc)
	testhelpers.AssertEqual(t, setup.DB, svc.db)
}

func TestCreateUser(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	u := &model.User{
		Username: "testuser2",
	}
	user, err := svc.CreateUser(u)
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertNotNil(t, user)
	// Verify user properties
	testhelpers.AssertEqual(t, u.Username, user.Username)
	testhelpers.AssertEqual(t, types.UserRoleUser, user.Role)
	if user.AccessToken == "" {
		t.Error("Expected access token to be generated")
	}
}

func TestCreateUserAllowList(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)

	withList, err := svc.CreateUser(&model.User{Username: "alice", AllowList: []byte(`["github","slack"]`)})
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertEqual(t, `["github","slack"]`, string(withList.AllowList))

	// without an allow-list, the user can access no servers
	withoutList, err := svc.CreateUser(&model.User{Username: "bob"})
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertEqual(t, `[]`, string(withoutList.AllowList))
}

func TestGetUserByUsername(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)

	created, err := svc.CreateUser(&model.User{Username: "alice"})
	testhelpers.AssertNoError(t, err)

	found, err := svc.GetUserByUsername("alice")
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertEqual(t, created.ID, found.ID)

	_, err = svc.GetUserByUsername("nobody")
	if !errors.Is(err, apierrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCreateUserWithExistingUsername(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	u := &model.User{
		Username: "testuser2",
	}
	// Create first user
	user1, _ := svc.CreateUser(u)
	testhelpers.AssertNotNil(t, user1)
	// Try to create another user with same username
	user2, err := svc.CreateUser(u)
	testhelpers.AssertError(t, err)
	if user2 != nil {
		t.Error("Expected second user creation to fail")
	}
}

func TestCreateAdminUser(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	user, err := svc.CreateAdminUser()
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertNotNil(t, user)
	// Verify admin user properties
	testhelpers.AssertEqual(t, "admin", user.Username)
	testhelpers.AssertEqual(t, types.UserRoleAdmin, user.Role)
	if user.AccessToken == "" {
		t.Error("Expected access token to be generated")
	}
}

func TestCreateUserAccessToken(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	u := &model.User{
		Username:    "testuser2",
		AccessToken: "custom-token-123",
	}
	user, err := svc.CreateUser(u)
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertNotNil(t, user)
	// Verify user properties
	testhelpers.AssertEqual(t, u.Username, user.Username)
	testhelpers.AssertEqual(t, types.UserRoleUser, user.Role)
	testhelpers.AssertEqual(t, u.AccessToken, user.AccessToken)
}

func TestCreateUserInvalidAccessToken(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	u := &model.User{
		Username:    "testuser2",
		AccessToken: "short", // invalid token (too short)
	}
	user, err := svc.CreateUser(u)
	testhelpers.AssertError(t, err)
	testhelpers.AssertTrue(t, errors.Is(err, apierrors.ErrInvalidInput), "expected ErrInvalidInput")
	if user != nil {
		t.Error("Expected user creation to fail due to invalid access token")
	}
}

func TestGetUserByAccessToken(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Create a test user first
	u := &model.User{
		Username: "testuser2",
	}
	user, _ := svc.CreateUser(u)
	// Test getting user by valid token
	retrievedUser, _ := svc.GetUserByAccessToken(user.AccessToken)
	testhelpers.AssertNotNil(t, retrievedUser)
	testhelpers.AssertEqual(t, u.Username, retrievedUser.Username)
	testhelpers.AssertEqual(t, user.AccessToken, retrievedUser.AccessToken)
	// Test getting user by invalid token
	_, err := svc.GetUserByAccessToken("invalid-token")
	testhelpers.AssertError(t, err)
}

func TestListUsers(t *testing.T) {
	setup := testhelpers.SetupTestDB(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Initially should be empty
	users, err := svc.ListUsers()
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertEqual(t, 0, len(users))
	// Create some users
	ua := &model.User{
		Username: "user1",
	}
	ub := &model.User{
		Username: "user2",
	}
	_, _ = svc.CreateUser(ua)
	_, _ = svc.CreateUser(ub)
	// Now should have 2 users
	users, _ = svc.ListUsers()
	testhelpers.AssertEqual(t, 2, len(users))
	// Verify all users are present
	usernames := make(map[string]bool)
	for _, user := range users {
		usernames[user.Username] = true
	}
	expectedUsernames := []string{"user1", "user2"}
	for _, expected := range expectedUsernames {
		if !usernames[expected] {
			t.Errorf("Expected user %s to be in list", expected)
		}
	}
}

func TestDeleteUser(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Create a test user
	u := &model.User{
		Username: "testuser2",
	}
	user, _ := svc.CreateUser(u)
	// Verify user exists
	_, err := svc.GetUserByAccessToken(user.AccessToken)
	testhelpers.AssertNoError(t, err)
	// Delete the user
	err = svc.DeleteUser(u.Username)
	testhelpers.AssertNoError(t, err)
	// Verify user was deleted
	_, err = svc.GetUserByAccessToken(user.AccessToken)
	testhelpers.AssertError(t, err)
}

func TestDeleteUserNotFound(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Try to delete non-existent user
	err := svc.DeleteUser("nonexistent")
	testhelpers.AssertError(t, err)
}

func TestDeleteAdminUser(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Create admin user
	admin, _ := svc.CreateAdminUser()
	// Try to delete admin user (should fail)
	err := svc.DeleteUser("admin")
	testhelpers.AssertError(t, err)
	testhelpers.AssertTrue(t, errors.Is(err, apierrors.ErrInvalidInput), "expected ErrInvalidInput")
	// Verify admin user still exists
	retrievedUser, _ := svc.GetUserByAccessToken(admin.AccessToken)
	testhelpers.AssertEqual(t, "admin", retrievedUser.Username)
}

func TestUpdateUser(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Create a test user
	u := &model.User{
		Username: "testuser2",
	}
	_, _ = svc.CreateUser(u)
	// Update the user's access token
	newToken := "new-custom-token-456"
	updateInput := &model.User{
		Username:    u.Username,
		AccessToken: newToken,
	}
	updatedUser, err := svc.UpdateUser(updateInput)
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertNotNil(t, updatedUser)
	testhelpers.AssertEqual(t, newToken, updatedUser.AccessToken)
	// Verify the update persisted
	retrievedUser, _ := svc.GetUserByAccessToken(newToken)
	testhelpers.AssertNotNil(t, retrievedUser)
	testhelpers.AssertEqual(t, u.Username, retrievedUser.Username)
}

func TestUpdateUserInvalidAccessToken(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Create a test user
	u := &model.User{
		Username: "testuser2",
	}
	_, _ = svc.CreateUser(u)
	// Try to update with invalid access token
	updateInput := &model.User{
		Username:    u.Username,
		AccessToken: "token\nwith\t\twhitespace", // invalid token
	}
	updatedUser, err := svc.UpdateUser(updateInput)
	testhelpers.AssertError(t, err)
	testhelpers.AssertTrue(t, errors.Is(err, apierrors.ErrInvalidInput), "expected ErrInvalidInput")
	if updatedUser != nil {
		t.Error("Expected update to fail due to invalid access token")
	}
}

func TestUpdateUserNotFound(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Try to update non-existent user
	updateInput := &model.User{
		Username:    "nonexistent",
		AccessToken: "new-token-789",
	}
	updatedUser, err := svc.UpdateUser(updateInput)
	testhelpers.AssertError(t, err)
	testhelpers.AssertTrue(t, errors.Is(err, apierrors.ErrNotFound), "expected ErrNotFound")
	if updatedUser != nil {
		t.Error("Expected update to fail for non-existent user")
	}
}

func TestUpdateUserNoAccessToken(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	// Create a test user
	u := &model.User{
		Username: "testuser2",
	}
	_, _ = svc.CreateUser(u)
	// Update without changing access token
	updateInput := &model.User{
		Username: u.Username,
		// No AccessToken field set
	}
	updatedUser, err := svc.UpdateUser(updateInput)
	testhelpers.AssertError(t, err)
	testhelpers.AssertTrue(t, errors.Is(err, apierrors.ErrInvalidInput), "expected ErrInvalidInput")
	if updatedUser != nil {
		t.Error("Expected update to fail for non-existent user")
	}
}

func TestUpdateUserAllowList(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	created, err := svc.CreateUser(&model.User{Username: "alice", AllowList: []byte(`["github"]`)})
	testhelpers.AssertNoError(t, err)

	// changing only the allow-list keeps the access token
	updated, err := svc.UpdateUser(&model.User{Username: "alice", AllowList: []byte(`["github","notion"]`)})
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertEqual(t, `["github","notion"]`, string(updated.AllowList))
	testhelpers.AssertEqual(t, created.AccessToken, updated.AccessToken)

	stored, err := svc.GetUserByUsername("alice")
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertEqual(t, `["github","notion"]`, string(stored.AllowList))

	// an empty or null allow-list removes access to all servers
	for _, revoke := range []string{`[]`, `null`} {
		updated, err = svc.UpdateUser(&model.User{Username: "alice", AllowList: []byte(revoke)})
		testhelpers.AssertNoError(t, err)
		testhelpers.AssertEqual(t, `[]`, string(updated.AllowList))
	}
}

func TestUpdateUserInvalidAllowList(t *testing.T) {
	setup, _ := testhelpers.SetupUserTest(t)
	defer setup.Cleanup()
	svc := NewUserService(setup.DB)
	_, err := svc.CreateUser(&model.User{Username: "alice"})
	testhelpers.AssertNoError(t, err)

	_, err = svc.UpdateUser(&model.User{Username: "alice", AllowList: []byte(`{"github":true}`)})
	testhelpers.AssertError(t, err)
	testhelpers.AssertTrue(t, errors.Is(err, apierrors.ErrInvalidInput), "expected ErrInvalidInput")
}
