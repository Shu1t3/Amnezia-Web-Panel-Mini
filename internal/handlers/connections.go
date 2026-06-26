package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/cache"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/managers"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

var clientsCache = cache.NewClientCache(30 * time.Second)

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
	serverIDStr := strconv.FormatInt(serverID, 10)
	protocol := c.Query("protocol", "awg2")
	sortBy := c.Query("sort", "name")
	order := c.Query("order", "asc")
	filter := strings.ToLower(c.Query("filter", ""))

	var clients []map[string]interface{}

	if cached, ok := clientsCache.Get(serverIDStr + ":" + protocol); ok {
		clients = cached
	} else {
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

		clientsCache.Set(serverIDStr+":"+protocol, clients)
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
					if uc.ExpiresAt != "" {
						client["expires_at"] = uc.ExpiresAt
					}
					break
				}
			}
		}
	}

	if filter != "" {
		var filtered []map[string]interface{}
		for _, client := range clients {
			name, _ := client["clientName"].(string)
			if strings.Contains(strings.ToLower(name), filter) {
				filtered = append(filtered, client)
			}
		}
		clients = filtered
	}

	sort.Slice(clients, func(i, j int) bool {
		var valI, valJ interface{}
		switch sortBy {
		case "name":
			valI, _ = clients[i]["clientName"].(string)
			valJ, _ = clients[j]["clientName"].(string)
		case "created":
			valI, _ = clients[i]["creationDate"].(string)
			valJ, _ = clients[j]["creationDate"].(string)
		case "ip":
			valI, _ = clients[i]["clientIp"].(string)
			valJ, _ = clients[j]["clientIp"].(string)
		default:
			valI, _ = clients[i]["clientName"].(string)
			valJ, _ = clients[j]["clientName"].(string)
		}
		sI, _ := valI.(string)
		sJ, _ := valJ.(string)
		if order == "desc" {
			return sI > sJ
		}
		return sI < sJ
	})

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
			if req.ExpiresAt != "" {
				connData.ExpiresAt = req.ExpiresAt
			}
			connBytes, _ := json.Marshal(connData)
			if err := database.Query.AddConnection(context.Background(), database.AddConnectionParams{
				ID:       connID,
				UserID:   req.UserID,
				ServerID: serverID,
				Protocol: req.Protocol,
				ClientID: clientID,
				Data:     string(connBytes),
			}); err != nil {
				log.Printf("Warning: failed to save connection: %v", err)
			}
		}
	}

	serverIDStr := strconv.FormatInt(serverID, 10)
	clientsCache.Invalidate(serverIDStr + ":" + req.Protocol)

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

	serverIDStr := strconv.FormatInt(serverID, 10)
	clientsCache.Invalidate(serverIDStr + ":" + req.Protocol)

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

func GetConnectionQR(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	clientID := c.Params("client_id")
	if clientID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Client ID required"})
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

	protocol := c.Query("protocol", "awg2")
	var config string
	switch protocol {
	case "wireguard":
		config = managers.NewWireGuardManager(ssh).GetClientConfig(clientID, serverData.Host)
	case "awg2":
		port := "55424"
		if p, ok := serverData.Protocols["awg2"].(map[string]interface{}); ok {
			if pt, ok2 := p["port"].(string); ok2 {
				port = pt
			}
		}
		config = managers.NewAWGManager(ssh).GetClientConfig(protocol, clientID, serverData.Host, port)
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Protocol not supported for QR"})
	}

	if config == "" || config == "Not found" {
		return c.Status(404).JSON(fiber.Map{"error": "Client config not found"})
	}

	qrData, err := managers.GenerateQRCodeBase64(config)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate QR code"})
	}

	return c.JSON(fiber.Map{"qr": qrData, "config": config})
}

func SetConnectionExpiry(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req struct {
		ClientID  string `json:"client_id"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	userConnsStrs, _ := database.Query.GetServerConnections(context.Background(), serverID)
	for _, ucStr := range userConnsStrs {
		var uc models.UserConnectionData
		if err := json.Unmarshal([]byte(ucStr), &uc); err == nil {
			if uc.ClientID == req.ClientID {
				uc.ExpiresAt = req.ExpiresAt
				ucBytes, _ := json.Marshal(uc)
				database.Query.UpdateConnection(context.Background(), database.UpdateConnectionParams{
					ID:   uc.ID,
					Data: string(ucBytes),
				})
				serverIDStr := strconv.FormatInt(serverID, 10)
				clientsCache.Invalidate(serverIDStr + ":" + uc.Protocol)
				return c.JSON(fiber.Map{"status": "success", "expires_at": req.ExpiresAt})
			}
		}
	}

	return c.Status(404).JSON(fiber.Map{"error": "Connection not found"})
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
