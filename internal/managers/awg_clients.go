package managers

func (m *AWGManager) GetClients(protocol string) []map[string]interface{} {
	return []map[string]interface{}{}
}

func (m *AWGManager) RemoveClient(protocol string, clientID string) {
}

func (m *AWGManager) ToggleClient(protocol string, clientID string, enable bool) {
}

func (m *AWGManager) GetClientConfig(protocol string, clientID string, host string, port string) string {
	return ""
}

func (m *AWGManager) SaveServerConfig(config string) {
}
