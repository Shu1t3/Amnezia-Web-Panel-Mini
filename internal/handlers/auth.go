package handlers

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/gofiber/fiber/v2"
)

func LoginPage(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err == nil && sess.Get("user_id") != nil {
		return c.Redirect("/")
	}
	return RenderTemplate(c, "login", fiber.Map{})
}

func SetLangAction(c *fiber.Ctx) error {
	lang := c.Params("lang")
	ref := c.Get("Referer")
	if ref == "" {
		ref = "/"
	}

	hostname := c.Hostname()
	if strings.Contains(ref, "://") || strings.HasPrefix(ref, "//") {
		if !strings.Contains(ref, "://"+hostname) && !strings.Contains(ref, "@"+hostname) {
			ref = "/"
		}
	}

	c.Cookie(&fiber.Cookie{
		Name:     "lang",
		Value:    lang,
		MaxAge:   31536000,
		HTTPOnly: false,
	})

	return c.Redirect(ref)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Captcha  string `json:"captcha"`
}

func CaptchaAction(c *fiber.Ctx) error {
	transparentPNG := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 10, 73, 68, 65, 84, 120, 156, 99, 0, 1, 0, 0, 5, 0, 1, 13, 10, 45, 180, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130}
	c.Set("Content-Type", "image/png")
	return c.Send(transparentPNG)
}

func LoginAction(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	users, _ := database.Query.GetUsers(context.Background())
	for _, u := range users {
		var ud map[string]interface{}
		json.Unmarshal([]byte(u.Data), &ud)
		if uname, ok := ud["username"].(string); ok && uname == req.Username {
			if hash, ok := ud["password_hash"].(string); ok {
				if VerifyPassword(req.Password, hash) {
					role := "user"
					if r, ok := ud["role"].(string); ok {
						role = r
					}
					enabled := true
					if e, ok := ud["enabled"].(bool); ok {
						enabled = e
					}
					if !enabled {
						return c.Status(403).JSON(fiber.Map{"error": "Account disabled"})
					}
					sess, _ := store.Get(c)
					sess.Set("user_id", u.ID)
					sess.Save()
					return c.JSON(fiber.Map{"status": "success", "role": role})
				}
			}
		}
	}
	return c.Status(401).JSON(fiber.Map{"error": "Invalid login"})
}

func LogoutAction(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err == nil {
		sess.Destroy()
	}
	return c.Redirect("/login")
}

func IndexPage(c *fiber.Ctx) error {
	currentUser := c.Locals("current_user")
	if currentUser != nil {
		if ud, ok := currentUser.(map[string]interface{}); ok {
			if role, ok2 := ud["role"].(string); ok2 && role == "user" {
				return c.Redirect("/my")
			}
		}
	} else {
		return c.Redirect("/login")
	}

	servers, err := database.Query.GetServers(c.Context())
	if err != nil {
		return RenderTemplate(c, "index", fiber.Map{
			"servers": []interface{}{},
		})
	}

	var serversList []map[string]interface{}
	for _, s := range servers {
		var sd map[string]interface{}
		if err := json.Unmarshal([]byte(s.Data), &sd); err == nil {
			sd["server_id"] = s.ID
			serversList = append(serversList, sd)
		}
	}

	return RenderTemplate(c, "index", fiber.Map{
		"servers": serversList,
	})
}

func MyConnectionsPage(c *fiber.Ctx) error {
	currentUser := c.Locals("current_user")
	if currentUser == nil {
		return c.Redirect("/login")
	}
	ud, ok := currentUser.(map[string]interface{})
	if !ok {
		return c.Redirect("/login")
	}
	userID, _ := ud["id"].(string)

	conns, _ := database.Query.GetUserConnections(c.Context(), userID)
	servers, _ := database.Query.GetServers(c.Context())
	serversMap := make(map[int64]map[string]interface{})
	for _, s := range servers {
		var sd map[string]interface{}
		if json.Unmarshal([]byte(s.Data), &sd) == nil {
			serversMap[s.ID] = sd
		}
	}

	var connsList []map[string]interface{}
	for _, cStr := range conns {
		var cd map[string]interface{}
		if json.Unmarshal([]byte(cStr), &cd) == nil {
			serverIDVal, _ := cd["server_id"]
			var serverID int64
			switch v := serverIDVal.(type) {
			case float64:
				serverID = int64(v)
			case int64:
				serverID = v
			}
			serverName := "Unknown"
			if s, ok2 := serversMap[serverID]; ok2 {
				if name, ok3 := s["name"].(string); ok3 && name != "" {
					serverName = name
				} else if host, ok3 := s["host"].(string); ok3 {
					serverName = host
				}
			}
			cd["server_name"] = serverName
			connsList = append(connsList, cd)
		}
	}

	return RenderTemplate(c, "my_connections", fiber.Map{
		"connections": connsList,
	})
}

func SettingsPage(c *fiber.Ctx) error {
	currentUser := c.Locals("current_user")
	if currentUser != nil {
		if ud, ok := currentUser.(map[string]interface{}); ok {
			if role, ok2 := ud["role"].(string); ok2 && role == "user" {
				return c.Redirect("/my")
			}
		}
	} else {
		return c.Redirect("/login")
	}

	return RenderTemplate(c, "settings", fiber.Map{})
}

func SaveSettingsAction(c *fiber.Ctx) error {
	currentUser := c.Locals("current_user")
	if currentUser == nil {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	ud, ok := currentUser.(map[string]interface{})
	if !ok || ud["role"] != "admin" {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	var req map[string]interface{}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if app, ok2 := req["appearance"]; ok2 {
		appBytes, _ := json.Marshal(app)
		database.Query.SetSetting(c.Context(), database.SetSettingParams{Key: "appearance", Value: string(appBytes)})
	}
	if capVal, ok2 := req["captcha"]; ok2 {
		capBytes, _ := json.Marshal(capVal)
		database.Query.SetSetting(c.Context(), database.SetSettingParams{Key: "captcha", Value: string(capBytes)})
	}
	if tel, ok2 := req["telegram"]; ok2 {
		telBytes, _ := json.Marshal(tel)
		database.Query.SetSetting(c.Context(), database.SetSettingParams{Key: "telegram", Value: string(telBytes)})
	}
	if sslVal, ok2 := req["ssl"]; ok2 {
		sslBytes, _ := json.Marshal(sslVal)
		database.Query.SetSetting(c.Context(), database.SetSettingParams{Key: "ssl", Value: string(sslBytes)})
	}

	return c.JSON(fiber.Map{"status": "success"})
}

func ToggleTelegramAction(c *fiber.Ctx) error {
	currentUser := c.Locals("current_user")
	if currentUser == nil {
		return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
	}
	ud, ok := currentUser.(map[string]interface{})
	if !ok || ud["role"] != "admin" {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	cfgStr, err := database.Query.GetSetting(c.Context(), "telegram")
	var cfg map[string]interface{}
	if err == nil {
		json.Unmarshal([]byte(cfgStr), &cfg)
	}
	if cfg == nil {
		cfg = make(map[string]interface{})
	}

	enabled := false
	if e, ok2 := cfg["enabled"].(bool); ok2 {
		enabled = e
	}
	cfg["enabled"] = !enabled

	cfgBytes, _ := json.Marshal(cfg)
	database.Query.SetSetting(c.Context(), database.SetSettingParams{
		Key:   "telegram",
		Value: string(cfgBytes),
	})

	return c.JSON(fiber.Map{"status": "success"})
}

func GetTokensAction(c *fiber.Ctx) error {
	return c.JSON([]interface{}{})
}
