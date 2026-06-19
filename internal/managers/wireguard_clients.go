package managers

func (m *WireGuardManager) GetClients() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (m *WireGuardManager) RemoveClient(clientID string) {
}

func (m *WireGuardManager) ToggleClient(clientID string, enable bool) {
}

func (m *WireGuardManager) GetClientConfig(clientID string, host string) string {
	return ""
}

func (m *WireGuardManager) SaveServerConfig(config string) {
}
