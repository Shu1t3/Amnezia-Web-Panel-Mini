package handlers

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/cache"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

var store *session.Store
var settingsCache = cache.NewSettingsCache(30 * time.Second)

func init() {
	store = session.New(session.Config{
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		Expiration:     24 * time.Hour,
	})
}

func GetSessionStore() *session.Store {
	return store
}

func SetupRoutes(app *fiber.App) {
	// Public Web Routes
	app.Get("/login", TemplateContextMiddleware, LoginPage)
	app.Get("/logout", LogoutAction)
	app.Get("/set_lang/:lang", SetLangAction)

	// Public API Routes
	api := app.Group("/api")
	auth := api.Group("/auth")
	auth.Get("/captcha", CaptchaAction)
	auth.Post("/login", LoginAction)

	// Protected Web Routes
	app.Get("/", AuthMiddleware, TemplateContextMiddleware, IndexPage)
	app.Get("/my", AuthMiddleware, TemplateContextMiddleware, MyConnectionsPage)
	app.Get("/users", AuthMiddleware, TemplateContextMiddleware, UsersPage)
	app.Get("/server/:server_id", AuthMiddleware, TemplateContextMiddleware, ServerDetailPage)
	app.Get("/settings", AuthMiddleware, TemplateContextMiddleware, SettingsPage)

	// Protected API Routes
	servers := api.Group("/servers", AuthMiddleware)
	servers.Post("/add", AddServer)
	servers.Post("/:server_id/edit", EditServer)
	servers.Post("/:server_id/delete", DeleteServer)
	servers.Get("/:server_id/ping", PingServer)
	servers.Post("/reorder", ReorderServers)

	servers.Post("/:server_id/install", InstallProtocol)
	servers.Post("/:server_id/uninstall", UninstallProtocol)
	servers.Post("/:server_id/container/toggle", ContainerToggle)
	servers.Post("/:server_id/server_config", ServerConfig)
	servers.Post("/:server_id/server_config/save", ServerConfigSave)
	servers.Post("/:server_id/check", CheckServer)
	servers.Post("/:server_id/stats", GetServerStats)
	servers.Post("/:server_id/reboot", RebootServer)
	servers.Post("/:server_id/clear", ClearServer)
	servers.Get("/:server_id/socks5/credentials", GetSocks5Credentials)
	servers.Post("/:server_id/socks5/credentials", UpdateSocks5Credentials)

	servers.Get("/:server_id/connections", GetConnections)
	servers.Post("/:server_id/connections/add", AddConnection)
	servers.Post("/:server_id/connections/remove", RemoveConnection)
	servers.Post("/:server_id/connections/edit", EditConnection)
	servers.Post("/:server_id/connections/config", GetConnectionConfig)
	servers.Post("/:server_id/connections/toggle", ToggleConnection)
	servers.Get("/:server_id/connections/:client_id/qr", GetConnectionQR)
	servers.Post("/:server_id/connections/expire", SetConnectionExpiry)

	users := api.Group("/users", AuthMiddleware)
	users.Get("/", GetUsers)
	users.Post("/add", AddUserHandler)
	users.Post("/:user_id/update", UpdateUser)
	users.Post("/:user_id/delete", DeleteUser)
	users.Post("/:user_id/toggle", ToggleUser)
	users.Post("/:user_id/connections/add", AddUserConnectionHandler)

	settingsAPI := api.Group("/settings", AuthMiddleware)
	settingsAPI.Post("/save", SaveSettingsAction)
	settingsAPI.Post("/telegram/toggle", ToggleTelegramAction)
	settingsAPI.Get("/tokens", GetTokensAction)
}

func AuthMiddleware(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		if strings.HasPrefix(c.Path(), "/api/") {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Redirect("/login")
	}
	userId := sess.Get("user_id")
	if userId == nil {
		if strings.HasPrefix(c.Path(), "/api/") {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}
		return c.Redirect("/login")
	}
	return c.Next()
}

func TemplateContextMiddleware(c *fiber.Ctx) error {
	lang := c.Cookies("lang", "en")
	c.Locals("lang", lang)
	c.Locals("_", func(textID string) string {
		return GetTranslation(lang, textID)
	})
	c.Locals("request", map[string]interface{}{
		"url": map[string]string{
			"scheme": c.Protocol(),
			"netloc": c.Hostname(),
		},
	})

	csrfToken, _ := c.Locals("csrf_token").(string)
	c.Locals("csrf_token", csrfToken)

	appearance := map[string]interface{}{}
	captcha := map[string]interface{}{}
	telegram := map[string]interface{}{}

	if v, ok := settingsCache.Get("appearance"); ok {
		json.Unmarshal([]byte(v), &appearance)
	} else if v, err := database.Query.GetSetting(c.Context(), "appearance"); err == nil && v != "" {
		json.Unmarshal([]byte(v), &appearance)
		settingsCache.Set("appearance", v)
	}

	if v, ok := settingsCache.Get("captcha"); ok {
		json.Unmarshal([]byte(v), &captcha)
	} else if v, err := database.Query.GetSetting(c.Context(), "captcha"); err == nil && v != "" {
		json.Unmarshal([]byte(v), &captcha)
		settingsCache.Set("captcha", v)
	}

	if v, ok := settingsCache.Get("telegram"); ok {
		json.Unmarshal([]byte(v), &telegram)
	} else if v, err := database.Query.GetSetting(c.Context(), "telegram"); err == nil && v != "" {
		json.Unmarshal([]byte(v), &telegram)
		settingsCache.Set("telegram", v)
	}
	c.Locals("site_settings", appearance)
	c.Locals("captcha_settings", captcha)
	c.Locals("telegram_settings", telegram)
	c.Locals("bot_running", false)

	translationsJSON := translationsCache.GetByLang(lang)
	if translationsJSON == "" {
		langMap := translations[lang]
		if langMap == nil {
			langMap = translations["en"]
		}
		if langMap == nil {
			langMap = make(map[string]string)
		}
		b, _ := json.Marshal(langMap)
		translationsJSON = string(b)
	}
	c.Locals("translations_json", translationsJSON)

	allTranslationsJSON := translationsCache.GetAll()
	if allTranslationsJSON == "" {
		b, _ := json.Marshal(translations)
		allTranslationsJSON = string(b)
	}
	c.Locals("all_translations_json", allTranslationsJSON)

	c.Locals("current_version", "v2.2.0")

	if sess, err := store.Get(c); err == nil {
		if userId := sess.Get("user_id"); userId != nil {
			idStr, _ := userId.(string)
			if uData, err := database.Query.GetUser(c.Context(), idStr); err == nil {
				var ud map[string]interface{}
				json.Unmarshal([]byte(uData), &ud)
				ud["id"] = idStr
				c.Locals("current_user", ud)
			}
		}
	}

	return c.Next()
}

func RenderTemplate(c *fiber.Ctx, templateName string, bind fiber.Map) error {
	if bind == nil {
		bind = fiber.Map{}
	}
	bind["lang"] = c.Locals("lang")
	bind["_"] = c.Locals("_")
	bind["request"] = c.Locals("request")
	bind["site_settings"] = c.Locals("site_settings")
	bind["captcha_settings"] = c.Locals("captcha_settings")
	bind["telegram_settings"] = c.Locals("telegram_settings")
	bind["bot_running"] = c.Locals("bot_running")
	bind["current_user"] = c.Locals("current_user")
	bind["translations_json"] = c.Locals("translations_json")
	bind["all_translations_json"] = c.Locals("all_translations_json")
	bind["current_version"] = c.Locals("current_version")
	bind["csrf_token"] = c.Locals("csrf_token")

	return c.Render(templateName, bind)
}
