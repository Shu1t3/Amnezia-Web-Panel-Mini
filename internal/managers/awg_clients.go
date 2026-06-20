package managers

import (
	"fmt"
	"strings"
)

func (m *AWGManager) GetClients(protocol string) []map[string]interface{} {
	return m.GetClientsTable()
}

func (m *AWGManager) RemoveClient(protocol string, clientID string) {
	clients := m.GetClientsTable()
	var updated []map[string]interface{}
	for _, c := range clients {
		if cid, ok := c["clientId"].(string); ok && cid != clientID {
			updated = append(updated, c)
		}
	}
	m.SaveClientsTable(updated)
}

func (m *AWGManager) ToggleClient(protocol string, clientID string, enable bool) {
	clients := m.GetClientsTable()
	for _, c := range clients {
		if cid, ok := c["clientId"].(string); ok && cid == clientID {
			if userData, ok := c["userData"].(map[string]interface{}); ok {
				userData["enabled"] = enable
			}
		}
	}
	m.SaveClientsTable(clients)
}

func (m *AWGManager) GetClientConfig(protocol string, clientID string, host string, port string) string {
	clients := m.GetClientsTable()
	for _, c := range clients {
		if cid, ok := c["clientId"].(string); ok && cid == clientID {
			if userData, ok := c["userData"].(map[string]interface{}); ok {
				clientPrivKey, _ := userData["clientPrivateKey"].(string)
				clientIp, _ := userData["clientIp"].(string)
				psk, _ := userData["psk"].(string)
				serverPubKey, err := m.GetServerPublicKey()
				if err != nil {
					return ""
				}
				mtu := "1280"
				config, _ := m.GetServerConfig()
				for _, line := range strings.Split(config, "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "MTU") {
						parts := strings.SplitN(line, "=", 2)
						if len(parts) == 2 {
							mtu = strings.TrimSpace(parts[1])
						}
					}
				}
				return fmt.Sprintf("[Interface]\nAddress = %s/32\nDNS = %s, %s\nPrivateKey = %s\nMTU = %s\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n", clientIp, AwgDefaults["dns1"], AwgDefaults["dns2"], clientPrivKey, mtu, serverPubKey, psk, host, port)
			}
		}
	}
	return ""
}

func (m *AWGManager) SaveServerConfig(config string) {
	m.ssh.UploadFileSudo(config, AwgConfigPath)
}
