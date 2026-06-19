package managers

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	TelemtContainerName = "telemt"
	TelemtApiUrl        = "http://127.0.0.1:9091"
)

type TelemtManager struct {
	ssh *SSHManager
}

func NewTelemtManager(ssh *SSHManager) *TelemtManager {
	return &TelemtManager{ssh: ssh}
}

func (m *TelemtManager) apiRequest(method, path string, data map[string]interface{}) map[string]interface{} {
	cmd := fmt.Sprintf("docker exec %s curl -s -X %s %s%s", TelemtContainerName, method, TelemtApiUrl, path)
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err == nil {
			safeJson := strings.ReplaceAll(string(jsonData), "\"", "\\\"")
			cmd += fmt.Sprintf(" -H 'Content-Type: application/json' -d \"%s\"", safeJson)
		}
	}

	out, _, code := m.ssh.RunSudoCommand(cmd)
	if code != 0 {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return nil
	}
	return result
}

func (m *TelemtManager) CheckProtocolInstalled() bool {
	out, _, _ := m.ssh.RunCommand(fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", TelemtContainerName))
	return strings.TrimSpace(out) == TelemtContainerName
}

func (m *TelemtManager) GetServerStatus() map[string]interface{} {
	exists := m.CheckProtocolInstalled()
	out, _, _ := m.ssh.RunCommand(fmt.Sprintf("docker inspect -f '{{.State.Running}}' %s 2>/dev/null", TelemtContainerName))
	isRunning := strings.ToLower(strings.TrimSpace(out)) == "true"

	status := map[string]interface{}{
		"container_exists":  exists,
		"container_running": isRunning,
	}

	if isRunning {
		outPort, _, _ := m.ssh.RunCommand(fmt.Sprintf("docker port %s 443 2>/dev/null", TelemtContainerName))
		if outPort != "" {
			parts := strings.Split(strings.TrimSpace(outPort), ":")
			status["port"] = strings.TrimSpace(parts[len(parts)-1])
		} else {
			status["port"] = nil
		}

		config := m.GetServerConfig()
		status["awg_params"] = m.parseTelemtParams(config)
	}

	return status
}

func (m *TelemtManager) ensureDockerCompose() error {
	out, _, code := m.ssh.RunCommand("docker compose version 2>/dev/null")
	if code == 0 && strings.TrimSpace(out) != "" {
		return nil
	}

	script := `
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || true
    apt-get install -y ca-certificates curl gnupg || exit 1
    install -m 0755 -d /etc/apt/keyrings
    . /etc/os-release
    DOCKER_DISTRO="$ID"
    case "$ID" in
        linuxmint|pop|elementary|zorin) DOCKER_DISTRO="ubuntu" ;;
        kali|parrot) DOCKER_DISTRO="debian" ;;
    esac
    if [ ! -s /etc/apt/keyrings/docker.asc ]; then
        curl -fsSL "https://download.docker.com/linux/${DOCKER_DISTRO}/gpg" -o /etc/apt/keyrings/docker.asc || exit 1
        chmod a+r /etc/apt/keyrings/docker.asc
    fi
    CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DOCKER_DISTRO} ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -y || exit 1
    apt-get install -y docker-buildx-plugin docker-compose-plugin || exit 1
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y dnf-plugins-core || exit 1
    . /etc/os-release
    dnf config-manager --add-repo "https://download.docker.com/linux/${ID}/docker-ce.repo" \
        || dnf config-manager --add-repo "https://download.docker.com/linux/centos/docker-ce.repo" \
        || exit 1
    dnf makecache || true
    dnf install -y docker-buildx-plugin docker-compose-plugin || exit 1
elif command -v yum >/dev/null 2>&1; then
    yum install -y yum-utils || exit 1
    . /etc/os-release
    yum-config-manager --add-repo "https://download.docker.com/linux/${ID}/docker-ce.repo" \
        || yum-config-manager --add-repo "https://download.docker.com/linux/centos/docker-ce.repo" \
        || exit 1
    yum makecache || true
    yum install -y docker-buildx-plugin docker-compose-plugin || exit 1
else
    echo "Unsupported package manager" >&2
    exit 1
fi
docker compose version
`
	out, errOut, code := m.ssh.RunSudoScript(script)
	if code != 0 {
		return fmt.Errorf("failed to install docker compose plugin: %s %s", errOut, out)
	}
	return nil
}

func (m *TelemtManager) InstallProtocol(port string, tlsEmulation bool, tlsDomain string, maxConnections int) (map[string]interface{}, error) {
	var results []string

	if !CheckDockerInstalled(m.ssh) {
		results = append(results, "Installing Docker...")
		m.ssh.RunSudoCommand("curl -fsSL https://get.docker.com | sh")
	}

	if m.CheckProtocolInstalled() {
		m.ssh.RunSudoCommand(fmt.Sprintf("docker rm -f %s", TelemtContainerName))
	}

	results = append(results, "Ensuring docker compose plugin...")
	if err := m.ensureDockerCompose(); err != nil {
		return nil, err
	}

	results = append(results, "Uploading Telemt files...")
	remoteDir := "/opt/amnezia/telemt"
	m.ssh.RunSudoCommand(fmt.Sprintf("mkdir -p %s", remoteDir))
	m.ssh.RunSudoCommand(fmt.Sprintf("chmod 755 %s", remoteDir))

	configBytes, err := os.ReadFile("protocol_telemt/config.toml")
	if err != nil {
		return nil, fmt.Errorf("failed to read local config.toml: %v", err)
	}
	configContent := string(configBytes)

	tlsEmulStr := "false"
	if tlsEmulation {
		tlsEmulStr = "true"
	}
	re := regexp.MustCompile(`(?i)tls_emulation\s*=\s*(true|false)`)
	configContent = re.ReplaceAllString(configContent, fmt.Sprintf("tls_emulation = %s", tlsEmulStr))

	if tlsEmulation && tlsDomain != "" {
		re = regexp.MustCompile(`tls_domain\s*=\s*".*?"`)
		configContent = re.ReplaceAllString(configContent, fmt.Sprintf(`tls_domain = "%s"`, tlsDomain))
	}

	if maxConnections > 0 {
		re = regexp.MustCompile(`max_connections\s*=\s*\d+`)
		configContent = re.ReplaceAllString(configContent, fmt.Sprintf("max_connections = %d", maxConnections))
	}

	if strings.Contains(configContent, "public_host =") {
		re = regexp.MustCompile(`(?m)^#?\s*public_host\s*=\s*".*?"`)
		configContent = re.ReplaceAllString(configContent, fmt.Sprintf(`public_host = "%s"`, m.ssh.Host))
	} else {
		configContent = strings.ReplaceAll(configContent, "[general.links]", fmt.Sprintf("[general.links]\npublic_host = \"%s\"", m.ssh.Host))
	}

	re = regexp.MustCompile(`public_port\s*=\s*\d+`)
	configContent = re.ReplaceAllString(configContent, fmt.Sprintf("public_port = %s", port))

	m.ssh.UploadFileSudo(configContent, fmt.Sprintf("%s/config.toml", remoteDir))

	composeBytes, err := os.ReadFile("protocol_telemt/docker-compose.yml")
	if err == nil {
		composeContent := string(composeBytes)
		composeContent = strings.ReplaceAll(composeContent, "\"443:443\"", fmt.Sprintf("\"%s:443\"", port))
		m.ssh.UploadFileSudo(composeContent, fmt.Sprintf("%s/docker-compose.yml", remoteDir))
	}

	dockerfileBytes, err := os.ReadFile("protocol_telemt/Dockerfile")
	if err == nil {
		m.ssh.UploadFileSudo(string(dockerfileBytes), fmt.Sprintf("%s/Dockerfile", remoteDir))
	}

	results = append(results, "Starting Telemt container...")
	_, _, code := m.ssh.RunSudoCommand(fmt.Sprintf("sh -c 'cd %s && docker compose up -d --build'", remoteDir))
	if code != 0 {
		m.ssh.RunSudoCommand(fmt.Sprintf("sh -c 'cd %s && docker-compose up -d --build'", remoteDir))
	}

	return map[string]interface{}{
		"status": "success",
		"host":   "",
		"port":   port,
		"log":    results,
	}, nil
}

func (m *TelemtManager) GetServerConfig() string {
	out, _, code := m.ssh.RunSudoCommand("cat /opt/amnezia/telemt/config.toml")
	if code != 0 {
		return ""
	}
	return out
}

func (m *TelemtManager) SaveServerConfig(configContent string) {
	m.ssh.UploadFileSudo(strings.ReplaceAll(configContent, "\r\n", "\n"), "/opt/amnezia/telemt/config.toml")
	m.ssh.RunSudoCommand(fmt.Sprintf("docker kill -s HUP %s || docker restart %s", TelemtContainerName, TelemtContainerName))
}

func (m *TelemtManager) parseTelemtParams(configText string) map[string]interface{} {
	params := make(map[string]interface{})
	re := regexp.MustCompile(`(?i)tls_emulation\s*=\s*(true|false)`)
	if match := re.FindStringSubmatch(configText); len(match) > 1 {
		params["tls_emulation"] = strings.ToLower(match[1]) == "true"
	}
	re = regexp.MustCompile(`tls_domain\s*=\s*"([^"]+)"`)
	if match := re.FindStringSubmatch(configText); len(match) > 1 {
		params["tls_domain"] = match[1]
	}
	re = regexp.MustCompile(`max_connections\s*=\s*(\d+)`)
	if match := re.FindStringSubmatch(configText); len(match) > 1 {
		params["max_connections"] = match[1]
	}
	return params
}

func (m *TelemtManager) RemoveContainer() {
	m.ssh.RunSudoCommand(fmt.Sprintf("docker rm -f %s", TelemtContainerName))
	m.ssh.RunSudoCommand("rm -rf /opt/amnezia/telemt")
}

func (m *TelemtManager) parseUsersFromConfig(configText string) map[string]string {
	users := make(map[string]string)
	lines := strings.Split(configText, "\n")
	inSection := false

	for _, line := range lines {
		stripped := strings.TrimSpace(line)
		if stripped == "[access.users]" {
			inSection = true
			continue
		}
		if inSection && strings.HasPrefix(stripped, "[") {
			break
		}
		if inSection && stripped != "" {
			commented := strings.HasPrefix(stripped, "#")
			content := strings.TrimSpace(strings.TrimPrefix(stripped, "#"))
			if strings.Contains(content, "=") {
				if strings.HasPrefix(strings.ToLower(content), "format:") {
					continue
				}
				parts := strings.SplitN(content, "=", 2)
				name := strings.Trim(strings.TrimSpace(parts[0]), "\"")
				secret := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				fullName := name
				if commented {
					fullName = "# " + name
				}
				users[fullName] = secret
			}
		}
	}
	return users
}

func (m *TelemtManager) AddClient(name, host, port, secret string) map[string]interface{} {
	username := regexp.MustCompile(`[^a-zA-Z0-9_.-]`).ReplaceAllString(strings.ReplaceAll(name, " ", "_"), "")
	if username == "" {
		username = "user_" + uuid.New().String()[:8]
	}

	configText := m.GetServerConfig()
	currentUsers := m.parseUsersFromConfig(configText)

	idx := 1
	baseUsername := username
	for {
		found := false
		for u := range currentUsers {
			if strings.TrimSpace(strings.TrimPrefix(u, "#")) == username {
				found = true
				break
			}
		}
		if !found {
			break
		}
		username = fmt.Sprintf("%s_%d", baseUsername, idx)
		idx++
	}

	if secret == "" {
		secret = uuid.New().String()[:16]
	}

	configText = m.insertIntoSection(configText, "access.users", fmt.Sprintf(`%s = "%s"`, username, secret))

	apiPayload := map[string]interface{}{
		"username": username,
		"secret":   secret,
	}

	m.ssh.UploadFileSudo(strings.ReplaceAll(configText, "\r\n", "\n"), "/opt/amnezia/telemt/config.toml")
	m.apiRequest("POST", "/v1/users", apiPayload)

	link := m.GetClientConfig(username, host, port)
	if link == "Not found" {
		link = fmt.Sprintf("tg://proxy?server=%s&port=%s&secret=%s", host, port, secret)
	}

	return map[string]interface{}{
		"client_id": username,
		"config":    link,
		"vpn_link":  link,
	}
}

func (m *TelemtManager) insertIntoSection(configText, sectionName, lineToInsert string) string {
	lines := strings.Split(configText, "\n")
	sectionStart := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == fmt.Sprintf("[%s]", sectionName) {
			sectionStart = i
			break
		}
	}
	if sectionStart == -1 {
		lines = append(lines, fmt.Sprintf("[%s]", sectionName), lineToInsert, "")
	} else {
		lines = append(lines[:sectionStart+1], append([]string{lineToInsert}, lines[sectionStart+1:]...)...)
	}
	return strings.Join(lines, "\n")
}

func (m *TelemtManager) RemoveClient(clientId string) {
	m.apiRequest("DELETE", fmt.Sprintf("/v1/users/%s", clientId), nil)

	configText := m.GetServerConfig()
	var newLines []string
	for _, line := range strings.Split(configText, "\n") {
		stripped := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		if strings.HasPrefix(stripped, clientId+" ") || strings.HasPrefix(stripped, clientId+"=") {
			continue
		}
		newLines = append(newLines, line)
	}
	m.ssh.UploadFileSudo(strings.ReplaceAll(strings.Join(newLines, "\n"), "\r\n", "\n"), "/opt/amnezia/telemt/config.toml")
}

func (m *TelemtManager) GetClientConfig(clientId, host, port string) string {
	resp := m.apiRequest("GET", fmt.Sprintf("/v1/users/%s", clientId), nil)
	if resp != nil {
		if ok, _ := resp["ok"].(bool); ok {
			data, _ := resp["data"].(map[string]interface{})
			links, _ := data["links"].(map[string]interface{})
			if tlsLinks, ok := links["tls"].([]interface{}); ok && len(tlsLinks) > 0 {
				return tlsLinks[0].(string)
			}
			if secureLinks, ok := links["secure"].([]interface{}); ok && len(secureLinks) > 0 {
				return secureLinks[0].(string)
			}
			if classicLinks, ok := links["classic"].([]interface{}); ok && len(classicLinks) > 0 {
				return classicLinks[0].(string)
			}
		}
	}

	configText := m.GetServerConfig()
	users := m.parseUsersFromConfig(configText)
	for k, v := range users {
		if strings.TrimSpace(strings.TrimPrefix(k, "#")) == clientId {
			return fmt.Sprintf("tg://proxy?server=%s&port=%s&secret=%s", host, port, v)
		}
	}
	return "Not found"
}
