package managers

import "strings"

func (m *TelemtManager) GetClients() []map[string]interface{} {
	configText := m.GetServerConfig()
	users := m.parseUsersFromConfig(configText)
	var result []map[string]interface{}
	for name, secret := range users {
		cleanName := strings.TrimSpace(strings.TrimPrefix(name, "#"))
		result = append(result, map[string]interface{}{
			"clientId": cleanName,
			"userData": map[string]interface{}{
				"clientName": cleanName,
				"secret":     secret,
				"enabled":    !strings.HasPrefix(name, "#"),
			},
		})
	}
	return result
}

func (m *TelemtManager) ToggleClient(clientID string, enable bool) {
	configText := m.GetServerConfig()
	lines := strings.Split(configText, "\n")
	for i, line := range lines {
		stripped := strings.TrimSpace(line)
		content := strings.TrimSpace(strings.TrimPrefix(stripped, "#"))
		if strings.HasPrefix(content, clientID+" ") || strings.HasPrefix(content, clientID+"=") || strings.HasPrefix(content, clientID+" =") {
			if enable {
				lines[i] = strings.TrimPrefix(strings.TrimPrefix(line, " "), "#")
			} else {
				lines[i] = "# " + strings.TrimPrefix(strings.TrimPrefix(line, " "), "#")
			}
		}
	}
	m.ssh.UploadFileSudo(strings.ReplaceAll(strings.Join(lines, "\n"), "\r\n", "\n"), "/opt/amnezia/telemt/config.toml")
}
