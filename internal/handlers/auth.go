package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/gofiber/fiber/v2"
)

type loginAttempt struct {
	timestamp time.Time
}

var (
	loginAttempts   = make(map[string][]loginAttempt)
	loginAttemptsMu sync.Mutex
)

func isLoginRateLimited(ip string) bool {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-15 * time.Minute)

	attempts := loginAttempts[ip]
	var valid []loginAttempt
	for _, a := range attempts {
		if a.timestamp.After(cutoff) {
			valid = append(valid, a)
		}
	}
	loginAttempts[ip] = valid

	return len(valid) >= 5
}

func recordLoginAttempt(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	loginAttempts[ip] = append(loginAttempts[ip], loginAttempt{timestamp: time.Now()})
}

func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			loginAttemptsMu.Lock()
			now := time.Now()
			for ip, attempts := range loginAttempts {
				var valid []loginAttempt
				for _, a := range attempts {
					if now.Sub(a.timestamp) < 15*time.Minute {
						valid = append(valid, a)
					}
				}
				if len(valid) == 0 {
					delete(loginAttempts, ip)
				} else {
					loginAttempts[ip] = valid
				}
			}
			loginAttemptsMu.Unlock()
		}
	}()
}

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

	validLangs := map[string]bool{"en": true, "ru": true, "fr": true, "zh": true, "fa": true}
	if !validLangs[lang] {
		lang = "en"
	}

	c.Cookie(&fiber.Cookie{
		Name:     "lang",
		Value:    lang,
		MaxAge:   31536000,
		HTTPOnly: true,
		SameSite: "Lax",
	})

	return c.Redirect(ref)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Captcha  string `json:"captcha"`
}

func CaptchaAction(c *fiber.Ctx) error {
	code := generateCaptchaCode()

	sess, err := store.Get(c)
	if err == nil {
		sess.Set("captcha_code", code)
		sess.Save()
	}

	width := 120
	height := 40
	fontSize := 24

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">
<rect width="100%%" height="100%%" fill="#f0f0f0"/>
<text x="50%%" y="50%%" dominant-baseline="central" text-anchor="middle" font-family="monospace" font-size="%d" fill="#333" letter-spacing="4">%s</text>
</svg>`, width, height, width, height, fontSize, code)

	c.Set("Content-Type", "image/svg+xml")
	return c.SendString(svg)
}

func generateCaptchaCode() string {
	chars := "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	code := make([]byte, 5)
	for i := range code {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		code[i] = chars[num.Int64()]
	}
	return string(code)
}

func verifyCaptcha(c *fiber.Ctx, input string) bool {
	if input == "" {
		return false
	}
	sess, err := store.Get(c)
	if err != nil {
		return false
	}
	stored, ok := sess.Get("captcha_code").(string)
	if !ok || stored == "" {
		return false
	}
	sess.Delete("captcha_code")
	sess.Save()
	return strings.EqualFold(input, stored)
}

func LoginAction(c *fiber.Ctx) error {
	ip := c.IP()
	if isLoginRateLimited(ip) {
		return c.Status(429).JSON(fiber.Map{"error": "Too many login attempts. Please try again later."})
	}

	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	captchaCfgStr, _ := database.Query.GetSetting(c.Context(), "captcha")
	var captchaCfg map[string]interface{}
	if captchaCfgStr != "" {
		json.Unmarshal([]byte(captchaCfgStr), &captchaCfg)
	}
	if captchaCfg != nil {
		if enabled, ok := captchaCfg["enabled"].(bool); ok && enabled {
			if !verifyCaptcha(c, req.Captcha) {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid CAPTCHA"})
			}
		}
	}

	user, err := database.Query.GetUserByUsername(c.Context(), req.Username)
	if err != nil {
		recordLoginAttempt(ip)
		return c.Status(401).JSON(fiber.Map{"error": "Invalid login"})
	}

	var ud map[string]interface{}
	json.Unmarshal([]byte(user.Data), &ud)

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
			sess.Set("user_id", user.ID)
			sess.Save()
			return c.JSON(fiber.Map{"status": "success", "role": role})
		}
	}
	recordLoginAttempt(ip)
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

	settingsCache.Invalidate()

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

	settingsCache.Invalidate()

	return c.JSON(fiber.Map{"status": "success"})
}

func GetTokensAction(c *fiber.Ctx) error {
	return c.JSON([]interface{}{})
}
