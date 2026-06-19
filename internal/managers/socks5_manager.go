package managers

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

const (
	Socks5ContainerName = "amnezia-socks5proxy"
	Socks5ImageName     = "3proxy/3proxy:0.9.5"
	Socks5ConfigDir     = "/opt/amnezia/socks5proxy"
	Socks5ConfigPath    = "/usr/local/3proxy/conf/3proxy.cfg"
	Socks5DefaultPort   = "38080"
	Socks5DefaultUser   = "proxy_user"
)

func generatePassword(length int) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[num.Int64()]
	}
	return string(result)
}

type Socks5Manager struct {
	ssh *SSHManager
}

func NewSocks5Manager(ssh *SSHManager) *Socks5Manager {
	return &Socks5Manager{ssh: ssh}
}

func (m *Socks5Manager) findContainerName() string {
	names := []string{Socks5ContainerName, "socks5"}
	for _, name := range names {
		out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", name))
		lines := strings.Split(strings.TrimSpace(out), "\n")
		for _, line := range lines {
			if line == name {
				return name
			}
		}
	}
	return ""
}

func (m *Socks5Manager) CheckProtocolInstalled() bool {
	return m.findContainerName() != ""
}

func (m *Socks5Manager) CheckContainerRunning() bool {
	name := m.findContainerName()
	if name == "" {
		return false
	}
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", name))
	return strings.Contains(out, "Up")
}

func (m *Socks5Manager) GetServerStatus() map[string]interface{} {
	exists := m.CheckProtocolInstalled()
	running := m.CheckContainerRunning()
	creds := make(map[string]string)
	if exists {
		creds = m.GetCredentials()
	}

	return map[string]interface{}{
		"container_exists":  exists,
		"container_running": running,
		"port":              creds["port"],
		"username":          creds["username"],
		"protocol":          "socks5",
	}
}

func (m *Socks5Manager) buildConfig(username, password, port string) string {
	return fmt.Sprintf(`#!/bin/3proxy
config %s
timeouts 1 5 30 60 180 1800 15 60
users %s:CL:%s
log /usr/local/3proxy/logs/3proxy.log
auth strong
allow %s
socks -p%s
`, Socks5ConfigPath, username, password, username, port)
}

func (m *Socks5Manager) readConfig() string {
	name := m.findContainerName()
	if name == "" {
		name = Socks5ContainerName
	}
	out, _, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec %s cat %s 2>/dev/null", name, Socks5ConfigPath))
	if code != 0 || strings.TrimSpace(out) == "" {
		out, _, code = m.ssh.RunSudoCommand(fmt.Sprintf("cat %s/3proxy.cfg 2>/dev/null", Socks5ConfigDir))
	}
	if code != 0 || strings.TrimSpace(out) == "" {
		return ""
	}
	return out
}

func (m *Socks5Manager) writeConfig(configText string) {
	name := m.findContainerName()
	if name == "" {
		name = Socks5ContainerName
	}
	m.ssh.RunSudoCommand(fmt.Sprintf("mkdir -p %s", Socks5ConfigDir))
	m.ssh.UploadFileSudo(configText, fmt.Sprintf("%s/3proxy.cfg", Socks5ConfigDir))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker cp %s/3proxy.cfg %s:%s 2>/dev/null || true", Socks5ConfigDir, name, Socks5ConfigPath))
}

func (m *Socks5Manager) parseCredentials(configText string) map[string]string {
	creds := map[string]string{"port": "", "username": "", "password": ""}
	if configText == "" {
		return creds
	}

	userRe := regexp.MustCompile(`(?m)^\s*users\s+([^:\s]+):CL:(\S+)`)
	userMatches := userRe.FindStringSubmatch(configText)
	if len(userMatches) > 2 {
		creds["username"] = userMatches[1]
		creds["password"] = userMatches[2]
	}

	portRe := regexp.MustCompile(`(?m)^\s*socks\s+-p(\d+)`)
	portMatches := portRe.FindStringSubmatch(configText)
	if len(portMatches) > 1 {
		creds["port"] = portMatches[1]
	}

	return creds
}

func (m *Socks5Manager) GetCredentials() map[string]string {
	return m.parseCredentials(m.readConfig())
}

func (m *Socks5Manager) InstallProtocol(port, username, password string) map[string]interface{} {
	if !CheckDockerInstalled(m.ssh) {
		return map[string]interface{}{"status": "error", "message": "Docker not installed"}
	}

	if port == "" {
		port = Socks5DefaultPort
	}
	if strings.TrimSpace(username) == "" {
		username = Socks5DefaultUser
	}
	if strings.TrimSpace(password) == "" {
		password = generatePassword(16)
	}

	m.ssh.RunSudoCommand(fmt.Sprintf("docker pull %s", Socks5ImageName))

	if m.CheckProtocolInstalled() {
		m.RemoveContainer()
	}

	configText := m.buildConfig(username, password, port)
	m.ssh.RunSudoCommand(fmt.Sprintf("mkdir -p %s", Socks5ConfigDir))
	m.ssh.UploadFileSudo(configText, fmt.Sprintf("%s/3proxy.cfg", Socks5ConfigDir))

	runCmd := fmt.Sprintf("docker run -d --restart always --name %s -p %s:%s/tcp -v %s/3proxy.cfg:%s:ro %s %s",
		Socks5ContainerName, port, port, Socks5ConfigDir, Socks5ConfigPath, Socks5ImageName, Socks5ConfigPath)
	_, errOut, code := m.ssh.RunSudoCommand(runCmd)

	if code != 0 {
		return map[string]interface{}{"status": "error", "message": fmt.Sprintf("Failed to start container: %s", errOut)}
	}

	return map[string]interface{}{
		"status":   "success",
		"protocol": "socks5",
		"port":     port,
		"username": username,
		"password": password,
		"message":  "SOCKS5 proxy installed",
		"log": []string{
			fmt.Sprintf("SOCKS5 proxy listening on port %s/TCP", port),
			fmt.Sprintf("Username: %s", username),
			fmt.Sprintf("Password: %s", password),
			"Save these credentials — the password can also be viewed later via 'Change settings'.",
		},
	}
}

func (m *Socks5Manager) UpdateCredentials(port, username, password string) map[string]interface{} {
	if !m.CheckProtocolInstalled() {
		return map[string]interface{}{"status": "error", "message": "SOCKS5 not installed"}
	}

	current := m.GetCredentials()
	newPort := port
	if newPort == "" {
		newPort = current["port"]
		if newPort == "" {
			newPort = Socks5DefaultPort
		}
	}
	newUser := strings.TrimSpace(username)
	if newUser == "" {
		newUser = current["username"]
		if newUser == "" {
			newUser = Socks5DefaultUser
		}
	}
	newPass := strings.TrimSpace(password)
	if newPass == "" {
		newPass = current["password"]
		if newPass == "" {
			newPass = generatePassword(16)
		}
	}

	oldPort := current["port"]
	if oldPort != "" && newPort != oldPort {
		return m.InstallProtocol(newPort, newUser, newPass)
	}

	configText := m.buildConfig(newUser, newPass, newPort)
	m.writeConfig(configText)

	name := m.findContainerName()
	if name == "" {
		name = Socks5ContainerName
	}
	m.ssh.RunSudoCommand(fmt.Sprintf("docker restart %s", name))

	return map[string]interface{}{
		"status":   "success",
		"port":     newPort,
		"username": newUser,
		"password": newPass,
	}
}

func (m *Socks5Manager) RemoveContainer() {
	name := m.findContainerName()
	if name == "" {
		name = Socks5ContainerName
	}
	m.ssh.RunSudoCommand(fmt.Sprintf("docker stop %s || true", name))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker rm -fv %s || true", name))
	m.ssh.RunSudoCommand(fmt.Sprintf("rm -rf %s", Socks5ConfigDir))
}
