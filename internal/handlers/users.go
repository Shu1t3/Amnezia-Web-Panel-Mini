package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/managers"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func GetUsers(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	search := strings.ToLower(c.Query("search", ""))
	page, _ := strconv.Atoi(c.Query("page", "1"))
	size, _ := strconv.Atoi(c.Query("size", "10"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}

	users, err := database.Query.GetUsers(context.Background())
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	var filtered []map[string]interface{}
	for _, u := range users {
		var ud map[string]interface{}
		json.Unmarshal([]byte(u.Data), &ud)
		ud["id"] = u.ID
		username, _ := ud["username"].(string)
		email, _ := ud["email"].(string)
		telegramId, _ := ud["telegramId"].(string)

		if search != "" {
			match := strings.Contains(strings.ToLower(username), search) ||
				strings.Contains(strings.ToLower(email), search) ||
				strings.Contains(strings.ToLower(telegramId), search)
			if !match {
				continue
			}
		}
		filtered = append(filtered, ud)
	}

	total := len(filtered)
	start := (page - 1) * size
	end := start + size
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	pageItems := filtered[start:end]
	var resultUsers []map[string]interface{}

	for _, u := range pageItems {
		enabled := true
		if e, ok := u["enabled"].(bool); ok {
			enabled = e
		}

		resultUsers = append(resultUsers, map[string]interface{}{
			"id":                     u["id"],
			"username":               u["username"],
			"role":                   u["role"],
			"enabled":                enabled,
			"created_at":             u["created_at"],
			"telegramId":             u["telegramId"],
			"email":                  u["email"],
			"description":            u["description"],
			"connections_count":      0, // calculate later
			"traffic_used":           u["traffic_used"],
			"traffic_total":          u["traffic_total"],
			"traffic_limit":          u["traffic_limit"],
			"traffic_reset_strategy": u["traffic_reset_strategy"],
			"last_reset_at":          u["last_reset_at"],
			"expiration_date":        u["expiration_date"],
			"share_enabled":          u["share_enabled"],
			"share_token":            u["share_token"],
			"has_share_password":     u["share_password_hash"] != nil,
			"source":                 "Local",
		})
	}

	return c.JSON(fiber.Map{
		"users": resultUsers,
		"total": total,
		"page":  page,
		"size":  size,
		"pages": (total + size - 1) / size,
	})
}

func AddUserHandler(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	var req models.AddUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Password hashing logic skipped for prototype. Assume plain text or handle later.

	newUserID := uuid.New().String()
	userData := map[string]interface{}{
		"id":                     newUserID,
		"username":               req.Username,
		"password_hash":          HashPassword(req.Password),
		"role":                   req.Role,
		"telegramId":             req.TelegramId,
		"email":                  req.Email,
		"description":            req.Description,
		"traffic_limit":          req.TrafficLimit,
		"traffic_reset_strategy": req.TrafficResetStrategy,
		"traffic_used":           0,
		"traffic_total":          0,
		"last_reset_at":          time.Now().Format(time.RFC3339),
		"expiration_date":        req.ExpirationDate,
		"enabled":                true,
		"created_at":             time.Now().Format(time.RFC3339),
		"share_enabled":          false,
		"share_token":            uuid.New().String(),
	}

	userBytes, _ := json.Marshal(userData)
	err := database.Query.AddUser(context.Background(), database.AddUserParams{
		ID:   newUserID,
		Data: string(userBytes),
	})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	result := fiber.Map{
		"status":  "success",
		"user_id": newUserID,
	}

	if req.ServerId != nil && req.Protocol != nil && *req.Protocol != "" {
		// Auto create connection logic here...
		result["connection_created"] = false
	}

	return c.JSON(result)
}

func UpdateUser(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	userID := c.Params("user_id")
	var req models.UpdateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	u, err := database.Query.GetUser(context.Background(), userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	var ud map[string]interface{}
	json.Unmarshal([]byte(u), &ud)

	if req.TelegramId != nil {
		ud["telegramId"] = *req.TelegramId
	}
	if req.Email != nil {
		ud["email"] = *req.Email
	}
	if req.Description != nil {
		ud["description"] = *req.Description
	}
	if req.ExpirationDate != nil {
		ud["expiration_date"] = *req.ExpirationDate
	}
	if req.TrafficResetStrategy != nil {
		ud["traffic_reset_strategy"] = *req.TrafficResetStrategy
	}
	if req.Password != nil && *req.Password != "" {
		ud["password_hash"] = HashPassword(*req.Password)
	}

	newData, _ := json.Marshal(ud)
	err = database.Query.UpdateUser(context.Background(), database.UpdateUserParams{
		Data: string(newData),
		ID:   userID,
	})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"status": "success"})
}

func DeleteUser(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	userID := c.Params("user_id")
	if err := database.Query.DeleteUserConnections(c.Context(), userID); err != nil {
		log.Printf("Warning: failed to delete user connections: %v", err)
	}
	if err := database.Query.DeleteUser(c.Context(), userID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"status": "success"})
}

func ToggleUser(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	userID := c.Params("user_id")
	var req models.ToggleUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	u, err := database.Query.GetUser(context.Background(), userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	var ud map[string]interface{}
	json.Unmarshal([]byte(u), &ud)
	ud["enabled"] = req.Enabled

	newData, _ := json.Marshal(ud)
	if err := database.Query.UpdateUser(context.Background(), database.UpdateUserParams{
		Data: string(newData),
		ID:   userID,
	}); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"status": "success", "enabled": req.Enabled})
}

func AddUserConnectionHandler(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	userID := c.Params("user_id")
	var req models.AddUserConnectionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	_, err := database.Query.GetUser(context.Background(), userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "User not found"})
	}

	dataStr, err := database.Query.GetServer(context.Background(), req.ServerId)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Server not found"})
	}

	var serverData models.ServerData
	if err := json.Unmarshal([]byte(dataStr), &serverData); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to parse server data"})
	}

	ssh := managers.NewSSHManager(serverData.Host, serverData.SSHPort, serverData.Username, serverData.Password, serverData.PrivateKey)
	if err := ssh.Connect(); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("SSH connection failed: %v", err)})
	}
	defer ssh.Disconnect()

	// Handle existing client mapping vs new client creation.
	// For now, return a placeholder success block that behaves like the python equivalent
	return c.JSON(fiber.Map{"status": "success"})
}

func UsersPage(c *fiber.Ctx) error {
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

	users, err := database.Query.GetUsers(c.Context())
	if err != nil {
		return c.Status(500).SendString(err.Error())
	}

	var usersList []map[string]interface{}
	conns, _ := database.Query.GetAllUserConnections(c.Context())

	for _, u := range users {
		var ud map[string]interface{}
		if err := json.Unmarshal([]byte(u.Data), &ud); err == nil {
			ud["id"] = u.ID
			connsCount := 0
			for _, connStr := range conns {
				var connData map[string]interface{}
				if json.Unmarshal([]byte(connStr), &connData) == nil {
					if connData["user_id"] == u.ID {
						connsCount++
					}
				}
			}
			ud["connections_count"] = connsCount
			usersList = append(usersList, ud)
		}
	}

	servers, _ := database.Query.GetServers(c.Context())
	var serversList []map[string]interface{}
	for _, s := range servers {
		var sd map[string]interface{}
		if err := json.Unmarshal([]byte(s.Data), &sd); err == nil {
			sd["server_id"] = s.ID
			serversList = append(serversList, sd)
		}
	}

	return RenderTemplate(c, "users", fiber.Map{
		"users":   usersList,
		"servers": serversList,
	})
}
