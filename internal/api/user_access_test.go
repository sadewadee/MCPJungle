package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"github.com/stretchr/testify/assert"
	"gorm.io/datatypes"
)

func TestServerAccessOf(t *testing.T) {
	gin.SetMode(gin.TestMode)
	standardUser := &model.User{Role: types.UserRoleUser, AllowList: datatypes.JSON(`["srva"]`)}

	cases := []struct {
		name     string
		mode     any
		user     any
		wantSrva bool
		wantSrvb bool
	}{
		{name: "development mode allows all", mode: model.ModeDev, wantSrva: true, wantSrvb: true},
		{name: "admin allows all", mode: model.ModeEnterprise, user: &model.User{Role: types.UserRoleAdmin}, wantSrva: true, wantSrvb: true},
		{name: "standard user is limited to allow-list", mode: model.ModeEnterprise, user: standardUser, wantSrva: true},
		{name: "deprecated production mode is enterprise", mode: model.ModeProd, user: standardUser, wantSrva: true},
		{name: "enterprise mode without user allows none", mode: model.ModeEnterprise},
		{name: "missing mode without user allows none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			if tc.mode != nil {
				c.Set("mode", tc.mode)
			}
			if tc.user != nil {
				c.Set("user", tc.user)
			}
			allowed := serverAccessOf(c)
			assert.Equal(t, tc.wantSrva, allowed("srva"))
			assert.Equal(t, tc.wantSrvb, allowed("srvb"))
		})
	}
}

func TestRequireServerAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("mode", model.ModeEnterprise)
	c.Set("user", &model.User{Role: types.UserRoleUser, AllowList: datatypes.JSON(`["srva"]`)})

	assert.True(t, requireServerAccess(c, "srva"))
	assert.False(t, c.IsAborted())

	assert.False(t, requireServerAccess(c, "srvb"))
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "srvb")
}
