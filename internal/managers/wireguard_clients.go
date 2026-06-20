package managers

import "fmt"

func (m *WireGuardManager) GetClients() []map[string]interface{} {
	return m.GetClientsTable()
}

func (m *WireGuardManager) RemoveClient(clientID string) {
	clients := m.GetClientsTable()
	var updated []map[string]interface{}
	for _, c := range clients {
		if cid, ok := c["clientId"].(string); ok && cid != clientID {
			updated = append(updated, c)
		}
	}
	m.SaveClientsTable(updated)
}

func (m *WireGuardManager) ToggleClient(clientID string, enable bool) {
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

func (m *WireGuardManager) GetClientConfig(clientID string, host string) string {
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
				port := m.GetListenPort()
				mtu := m.GetMtu()
				return fmt.Sprintf("[Interface]\nAddress = %s/32\nDNS = %s, %s\nPrivateKey = %s\nMTU = %s\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n", clientIp, WgDefaults["dns1"], WgDefaults["dns2"], clientPrivKey, mtu, serverPubKey, psk, host, port)
			}
		}
	}
	return ""
}

func (m *WireGuardManager) SaveServerConfig(config string) {
	m.ssh.UploadFileSudo(config, WgConfigPath)
}
