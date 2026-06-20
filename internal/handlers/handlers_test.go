package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/session"
)

func setupTestApp(t *testing.T) *fiber.App {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("failed to init test DB: %v", err)
	}

	translations = make(map[string]map[string]string)
	translations["en"] = map[string]string{
		"hello": "Hello",
		"login": "Login",
	}
	translations["ru"] = map[string]string{
		"hello": "Привет",
		"login": "Вход",
	}

	store = session.New(session.Config{
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
	})

	app := fiber.New()
	app.Use(csrf.New(csrf.Config{
		KeyLookup:      "header:X-Csrf-Token",
		CookieName:     "csrf_",
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		Session:        store,
		ContextKey:     "csrf_token",
		Next: func(c *fiber.Ctx) bool {
			return true
		},
	}))
	SetupRoutes(app)

	t.Cleanup(func() {
		database.CloseDB()
		os.Remove(dbPath)
	})

	return app
}

func TestCaptchaAction(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/api/auth/captcha", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "image/svg+xml") {
		t.Errorf("expected SVG content type, got %s", ct)
	}
}

func TestLoginAction_InvalidBody(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)

	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestLoginAction_WrongCredentials(t *testing.T) {
	app := setupTestApp(t)

	database.Query.AddUser(context.Background(), database.AddUserParams{
		ID:   "u1",
		Data: `{"username":"admin","password_hash":"invalidhash","role":"admin","enabled":true}`,
	})

	body := `{"username":"admin","password":"wrong","captcha":""}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)

	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestLoginAction_CorrectCredentials(t *testing.T) {
	app := setupTestApp(t)

	hash := HashPassword("correct_pass")
	database.Query.AddUser(context.Background(), database.AddUserParams{
		ID:   "u1",
		Data: `{"username":"testuser","password_hash":"` + hash + `","role":"admin","enabled":true}`,
	})

	body := `{"username":"testuser","password":"correct_pass","captcha":""}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)

	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "success" {
		t.Errorf("expected status success, got %v", result["status"])
	}
}

func TestLoginAction_DisabledUser(t *testing.T) {
	app := setupTestApp(t)

	hash := HashPassword("pass")
	database.Query.AddUser(context.Background(), database.AddUserParams{
		ID:   "u1",
		Data: `{"username":"disabled","password_hash":"` + hash + `","role":"user","enabled":false}`,
	})

	body := `{"username":"disabled","password":"pass","captcha":""}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)

	if resp.StatusCode != 403 {
		t.Errorf("expected 403 for disabled user, got %d", resp.StatusCode)
	}
}

func TestLoginAction_UserNotFound(t *testing.T) {
	app := setupTestApp(t)

	body := `{"username":"nobody","password":"pass","captcha":""}`
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)

	if resp.StatusCode != 401 {
		t.Errorf("expected 401 for nonexistent user, got %d", resp.StatusCode)
	}
}

func TestLogoutAction(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/logout", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 302 {
		t.Errorf("expected 302 redirect, got %d", resp.StatusCode)
	}
}

func TestSetLangAction(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/set_lang/ru", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "lang" && c.Value == "ru" {
			found = true
			break
		}
	}
	if !found {
		t.Error("lang cookie not set to 'ru'")
	}
}

func TestSetLangAction_InvalidLang(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/set_lang/xx", nil)
	resp, _ := app.Test(req)

	cookies := resp.Cookies()
	for _, c := range cookies {
		if c.Name == "lang" && c.Value == "xx" {
			t.Error("invalid lang should be rejected")
		}
	}
}

func TestSetLangAction_DefaultReferer(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/set_lang/en", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
}

func TestIndexPage_Unauthenticated(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 302 {
		t.Errorf("expected 302 redirect, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location != "/login" {
		t.Errorf("expected redirect to /login, got %s", location)
	}
}

func TestSettingsPage_Unauthenticated(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/settings", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
}

func TestUsersPage_Unauthenticated(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/users", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
}

func TestProtectedRoutes_Unauthenticated(t *testing.T) {
	app := setupTestApp(t)

	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/servers/add"},
		{"POST", "/api/servers/1/edit"},
		{"POST", "/api/servers/1/delete"},
		{"GET", "/api/servers/1/ping"},
		{"POST", "/api/servers/reorder"},
		{"POST", "/api/servers/1/install"},
		{"POST", "/api/servers/1/uninstall"},
		{"POST", "/api/servers/1/container/toggle"},
		{"POST", "/api/servers/1/server_config"},
		{"POST", "/api/servers/1/server_config/save"},
		{"POST", "/api/servers/1/check"},
		{"POST", "/api/servers/1/stats"},
		{"POST", "/api/servers/1/reboot"},
		{"POST", "/api/servers/1/clear"},
		{"GET", "/api/servers/1/socks5/credentials"},
		{"POST", "/api/servers/1/socks5/credentials"},
		{"GET", "/api/servers/1/connections"},
		{"POST", "/api/servers/1/connections/add"},
		{"POST", "/api/servers/1/connections/remove"},
		{"POST", "/api/servers/1/connections/edit"},
		{"POST", "/api/servers/1/connections/config"},
		{"POST", "/api/servers/1/connections/toggle"},
		{"GET", "/api/users/"},
		{"POST", "/api/users/add"},
		{"POST", "/api/users/u1/update"},
		{"POST", "/api/users/u1/delete"},
		{"POST", "/api/users/u1/toggle"},
		{"POST", "/api/users/u1/connections/add"},
		{"POST", "/api/settings/save"},
		{"POST", "/api/settings/telegram/toggle"},
		{"GET", "/api/settings/tokens"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		resp, _ := app.Test(req)

		if resp.StatusCode != 401 {
			t.Errorf("%s %s: expected 401, got %d", route.method, route.path, resp.StatusCode)
		}
	}
}

func TestAddServer_MissingFields(t *testing.T) {
	app := setupTestApp(t)

	body := `{"name":"test"}`
	req := httptest.NewRequest("POST", "/api/servers/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)

	if resp.StatusCode != 401 {
		t.Errorf("expected 401 (auth required), got %d", resp.StatusCode)
	}
}

func TestGetTokensAction(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/api/settings/tokens", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestServerDetailPage_InvalidID(t *testing.T) {
	app := setupTestApp(t)

	req := httptest.NewRequest("GET", "/server/abc", nil)
	resp, _ := app.Test(req)

	if resp.StatusCode != 302 {
		t.Errorf("expected 302 redirect, got %d", resp.StatusCode)
	}
}
