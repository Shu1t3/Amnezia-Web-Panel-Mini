package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/managers"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func generateVpnLink(config string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(config))
	return fmt.Sprintf("vpn://%s", b64)
}

func GetConnections(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}
	protocol := c.Query("protocol", "awg2")

	dataStr, err := database.Query.GetServer(context.Background(), serverID)
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

	var clients []map[string]interface{}
	switch protocol {
	case "telemt":
		clients = managers.NewTelemtManager(ssh).GetClients()
	case "wireguard":
		clients = managers.NewWireGuardManager(ssh).GetClients()
	case "awg2":
		clients = managers.NewAWGManager(ssh).GetClients(protocol)
	default:
		clients = []map[string]interface{}{}
	}

	userConnsStrs, _ := database.Query.GetServerConnectionsByProtocol(context.Background(), database.GetServerConnectionsByProtocolParams{
		ServerID: serverID,
		Protocol: protocol,
	})

	usersMap := make(map[string]database.User)
	users, _ := database.Query.GetUsers(context.Background())
	for _, u := range users {
		usersMap[u.ID] = u
	}

	for _, client := range clients {
		cid, _ := client["clientId"].(string)
		for _, ucStr := range userConnsStrs {
			var uc models.UserConnectionData
			if err := json.Unmarshal([]byte(ucStr), &uc); err == nil {
				if uc.ClientID == cid && uc.Protocol == protocol {
					uid := uc.UserID
					if user, ok := usersMap[uid]; ok {
						var userData map[string]interface{}
						json.Unmarshal([]byte(user.Data), &userData)
						client["assigned_user"] = userData["username"]
						client["assigned_user_id"] = uid
					}
					break
				}
			}
		}
	}

	return c.JSON(fiber.Map{"clients": clients})
}

func AddConnection(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.AddConnectionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	dataStr, err := database.Query.GetServer(context.Background(), serverID)
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

	var result map[string]interface{}
	switch req.Protocol {
	case "telemt":
		mgr := managers.NewTelemtManager(ssh)
		port := "443"
		if p, ok := serverData.Protocols["telemt"].(map[string]interface{}); ok {
			if pt, ok2 := p["port"].(string); ok2 {
				port = pt
			}
		}
		result = mgr.AddClient(req.Name, serverData.Host, port, req.TelemtSecret)
	case "wireguard":
		mgr := managers.NewWireGuardManager(ssh)
		res, _ := mgr.AddClient(req.Name, serverData.Host)
		result = res
	case "awg2":
		mgr := managers.NewAWGManager(ssh)
		port := "55424"
		if p, ok := serverData.Protocols["awg2"].(map[string]interface{}); ok {
			if pt, ok2 := p["port"].(string); ok2 {
				port = pt
			}
		}
		res, _ := mgr.AddClient(req.Name, serverData.Host, port)
		result = res
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Unknown protocol"})
	}

	if configStr, ok := result["config"].(string); ok {
		result["vpn_link"] = generateVpnLink(configStr)
	}

	if req.UserID != "" {
		if clientID, ok := result["client_id"].(string); ok {
			connID := uuid.New().String()
			connData := models.UserConnectionData{
				ID:        connID,
				UserID:    req.UserID,
				ServerID:  serverID,
				Protocol:  req.Protocol,
				ClientID:  clientID,
				Name:      req.Name,
				CreatedAt: "now",
			}
			connBytes, _ := json.Marshal(connData)
			database.Query.AddConnection(context.Background(), database.AddConnectionParams{
				ID:       connID,
				UserID:   req.UserID,
				ServerID: serverID,
				Protocol: req.Protocol,
				ClientID: clientID,
				Data:     string(connBytes),
			})
		}
	}

	return c.JSON(result)
}

func RemoveConnection(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.ConnectionActionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	dataStr, err := database.Query.GetServer(context.Background(), serverID)
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

	switch req.Protocol {
	case "telemt":
		managers.NewTelemtManager(ssh).RemoveClient(req.ClientID)
	case "wireguard":
		managers.NewWireGuardManager(ssh).RemoveClient(req.ClientID)
	case "awg2":
		managers.NewAWGManager(ssh).RemoveClient(req.Protocol, req.ClientID)
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Unknown protocol"})
	}

	userConnsStrs, _ := database.Query.GetServerConnectionsByProtocol(context.Background(), database.GetServerConnectionsByProtocolParams{
		ServerID: serverID,
		Protocol: req.Protocol,
	})

	for _, ucStr := range userConnsStrs {
		var uc models.UserConnectionData
		if err := json.Unmarshal([]byte(ucStr), &uc); err == nil {
			if uc.ClientID == req.ClientID {
				database.Query.DeleteConnection(context.Background(), uc.ID)
			}
		}
	}

	return c.JSON(fiber.Map{"status": "success"})
}

func EditConnection(c *fiber.Ctx) error {
	// Not fully implemented, placeholder
	return c.JSON(fiber.Map{"status": "success"})
}

func GetConnectionConfig(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.ConnectionActionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	dataStr, err := database.Query.GetServer(context.Background(), serverID)
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

	var config string
	switch req.Protocol {
	case "telemt":
		port := "443"
		if p, ok := serverData.Protocols["telemt"].(map[string]interface{}); ok {
			if pt, ok2 := p["port"].(string); ok2 {
				port = pt
			}
		}
		config = managers.NewTelemtManager(ssh).GetClientConfig(req.ClientID, serverData.Host, port)
	case "wireguard":
		config = managers.NewWireGuardManager(ssh).GetClientConfig(req.ClientID, serverData.Host)
	case "awg2":
		port := "55424"
		if p, ok := serverData.Protocols["awg2"].(map[string]interface{}); ok {
			if pt, ok2 := p["port"].(string); ok2 {
				port = pt
			}
		}
		config = managers.NewAWGManager(ssh).GetClientConfig(req.Protocol, req.ClientID, serverData.Host, port)
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Unknown protocol"})
	}

	vpnLink := ""
	if config != "" && config != "Not found" {
		vpnLink = generateVpnLink(config)
	}

	return c.JSON(fiber.Map{"config": config, "vpn_link": vpnLink})
}

func ToggleConnection(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.ToggleConnectionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	dataStr, err := database.Query.GetServer(context.Background(), serverID)
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

	switch req.Protocol {
	case "wireguard":
		managers.NewWireGuardManager(ssh).ToggleClient(req.ClientID, req.Enable)
	case "awg2":
		managers.NewAWGManager(ssh).ToggleClient(req.Protocol, req.ClientID, req.Enable)
	}

	status := "disabled"
	if req.Enable {
		status = "enabled"
	}
	return c.JSON(fiber.Map{"status": "success", "enabled": req.Enable, "message": fmt.Sprintf("Connection %s", status)})
}
