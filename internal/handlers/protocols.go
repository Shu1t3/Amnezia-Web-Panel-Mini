package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/managers"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/models"
	"github.com/gofiber/fiber/v2"
)

func InstallProtocol(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.InstallProtocolRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	validProtocols := map[string]bool{"awg2": true, "telemt": true, "dns": true, "wireguard": true, "socks5": true, "adguard": true}
	if !validProtocols[req.Protocol] {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid protocol type"})
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
		tlsEmul := true
		if req.TlsEmulation != nil {
			tlsEmul = *req.TlsEmulation
		}
		res, err := mgr.InstallProtocol(req.Port, tlsEmul, req.TlsDomain, req.MaxConnections)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		result = res
	case "wireguard":
		mgr := managers.NewWireGuardManager(ssh)
		res, _ := mgr.InstallProtocol(req.Port)
		result = res
	case "socks5":
		mgr := managers.NewSocks5Manager(ssh)
		result = mgr.InstallProtocol(req.Port, req.Socks5Username, req.Socks5Password)
	case "adguard":
		mgr := managers.NewAdguardManager(ssh)
		mode := req.AdguardMode
		if mode == "" {
			mode = "sidebyside"
		}
		dnsPort, _ := strconv.Atoi(req.Port)
		result = mgr.InstallProtocol(mode, req.AdguardWebPort, dnsPort, req.AdguardDotPort, req.AdguardDohPort, req.AdguardExposeWeb, req.AdguardExposeDns, req.AdguardExposeDot, req.AdguardExposeDoh)
	case "dns":
		mgr := managers.NewDNSManager(ssh)
		res, _ := mgr.InstallProtocol(req.Port)
		result = res
	case "awg2":
		mgr := managers.NewAWGManager(ssh)
		res, _ := mgr.InstallProtocol(req.Port, nil)
		result = res
	}

	if result["status"] == "error" {
		return c.Status(400).JSON(result)
	}

	protoRecord := map[string]interface{}{
		"installed": true,
		"port":      req.Port,
	}

	if awgParams, ok := result["awg_params"]; ok {
		protoRecord["awg_params"] = awgParams
	}

	if req.Protocol == "adguard" {
		protoRecord["mode"] = result["mode"]
		protoRecord["internal_ip"] = result["internal_ip"]
		protoRecord["web_port"] = result["web_port"]
		protoRecord["expose_web"] = result["expose_web"]
	}

	if serverData.Protocols == nil {
		serverData.Protocols = make(map[string]interface{})
	}
	serverData.Protocols[req.Protocol] = protoRecord

	newData, _ := json.Marshal(serverData)
	database.Query.UpdateServer(context.Background(), database.UpdateServerParams{
		Data: string(newData),
		ID:   serverID,
	})

	return c.JSON(result)
}

func UninstallProtocol(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.ProtocolRequest
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
		managers.NewTelemtManager(ssh).RemoveContainer()
	case "wireguard":
		managers.NewWireGuardManager(ssh).RemoveContainer()
	case "socks5":
		managers.NewSocks5Manager(ssh).RemoveContainer()
	case "adguard":
		managers.NewAdguardManager(ssh).RemoveContainer()
	case "dns":
		managers.NewDNSManager(ssh).RemoveContainer()
	case "awg2":
		managers.NewAWGManager(ssh).RemoveContainer()
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Unknown protocol"})
	}

	if serverData.Protocols != nil {
		delete(serverData.Protocols, req.Protocol)
		newData, _ := json.Marshal(serverData)
		database.Query.UpdateServer(context.Background(), database.UpdateServerParams{
			Data: string(newData),
			ID:   serverID,
		})
	}

	return c.JSON(fiber.Map{"status": "success"})
}

func ContainerToggle(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.ProtocolRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	containerNames := map[string]string{
		"awg2":      "amnezia-awg2",
		"telemt":    "telemt",
		"dns":       "amnezia-dns",
		"wireguard": "amnezia-wireguard",
		"socks5":    "amnezia-socks5proxy",
		"adguard":   "amnezia-adguard",
	}

	container := containerNames[req.Protocol]
	if container == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Unknown protocol"})
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

	out, _, _ := ssh.RunSudoCommand(fmt.Sprintf("docker inspect -f '{{.State.Running}}' %s 2>/dev/null", container))
	if strings.TrimSpace(out) == "" && req.Protocol == "socks5" {
		container = "socks5"
		out, _, _ = ssh.RunSudoCommand(fmt.Sprintf("docker inspect -f '{{.State.Running}}' %s 2>/dev/null", container))
	}

	if strings.TrimSpace(out) == "" {
		return c.Status(404).JSON(fiber.Map{"error": fmt.Sprintf("Container %s not found", container)})
	}

	isRunning := strings.ToLower(strings.TrimSpace(out)) == "true"
	var action string

	if isRunning {
		ssh.RunSudoCommand(fmt.Sprintf("docker stop %s", container))
		action = "stopped"
	} else {
		ssh.RunSudoCommand(fmt.Sprintf("docker start %s", container))
		action = "started"
	}

	return c.JSON(fiber.Map{
		"status":    "success",
		"action":    action,
		"container": container,
	})
}

func ServerConfig(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.ProtocolRequest
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
		config = managers.NewTelemtManager(ssh).GetServerConfig()
	case "wireguard":
		config, _ = managers.NewWireGuardManager(ssh).GetServerConfig()
	case "awg2":
		config, _ = managers.NewAWGManager(ssh).GetServerConfig()
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Config not supported for this protocol"})
	}

	return c.JSON(fiber.Map{"config": config})
}

func ServerConfigSave(c *fiber.Ctx) error {
	if !CheckAdmin(c) {
		return c.Status(403).JSON(fiber.Map{"error": "Forbidden"})
	}

	serverID, err := strconv.ParseInt(c.Params("server_id"), 10, 64)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid server ID"})
	}

	var req models.ServerConfigSaveRequest
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
		managers.NewTelemtManager(ssh).SaveServerConfig(req.Config)
	case "wireguard":
		managers.NewWireGuardManager(ssh).SaveServerConfig(req.Config)
	case "awg2":
		managers.NewAWGManager(ssh).SaveServerConfig(req.Config)
	default:
		return c.Status(400).JSON(fiber.Map{"error": "Config not supported for this protocol"})
	}

	return c.JSON(fiber.Map{"status": "success"})
}
