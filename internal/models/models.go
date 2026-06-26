package models

type ServerData struct {
	Name       string                 `json:"name"`
	Host       string                 `json:"host"`
	SSHPort    int                    `json:"ssh_port"`
	Username   string                 `json:"username"`
	Password   string                 `json:"password,omitempty"`
	PrivateKey string                 `json:"private_key,omitempty"`
	ServerInfo interface{}            `json:"server_info,omitempty"`
	Protocols  map[string]interface{} `json:"protocols,omitempty"`
}

type UserConnectionData struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	ServerID  int64  `json:"server_id"`
	Protocol  string `json:"protocol"`
	ClientID  string `json:"client_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Status    string `json:"status,omitempty"`
}

type AddServerRequest struct {
	Host       string `json:"host"`
	SSHPort    int    `json:"ssh_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Name       string `json:"name"`
}

type EditServerRequest struct {
	Name       string  `json:"name"`
	Host       string  `json:"host"`
	SSHPort    int     `json:"ssh_port"`
	Username   string  `json:"username"`
	Password   *string `json:"password"`
	PrivateKey *string `json:"private_key"`
}

type ReorderServersRequest struct {
	Order []int64 `json:"order"`
}

type InstallProtocolRequest struct {
	Protocol         string `json:"protocol"`
	Port             string `json:"port"`
	TlsEmulation     *bool  `json:"tls_emulation"`
	TlsDomain        string `json:"tls_domain"`
	MaxConnections   int    `json:"max_connections"`
	Socks5Username   string `json:"socks5_username"`
	Socks5Password   string `json:"socks5_password"`
	AdguardMode      string `json:"adguard_mode"`
	AdguardWebPort   int    `json:"adguard_web_port"`
	AdguardExposeWeb bool   `json:"adguard_expose_web"`
	AdguardDotPort   int    `json:"adguard_dot_port"`
	AdguardDohPort   int    `json:"adguard_doh_port"`
	AdguardExposeDns bool   `json:"adguard_expose_dns"`
	AdguardExposeDot bool   `json:"adguard_expose_dot"`
	AdguardExposeDoh bool   `json:"adguard_expose_doh"`
}

type ProtocolRequest struct {
	Protocol string `json:"protocol"`
}

type Socks5SettingsRequest struct {
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type ServerConfigSaveRequest struct {
	Protocol string `json:"protocol"`
	Config   string `json:"config"`
}

type AddConnectionRequest struct {
	Protocol       string `json:"protocol"`
	Name           string `json:"name"`
	UserID         string `json:"user_id"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	TelemtQuota    string `json:"telemt_quota"`
	TelemtMaxIps   int    `json:"telemt_max_ips"`
	TelemtExpiry   string `json:"telemt_expiry"`
	TelemtSecret   string `json:"telemt_secret"`
	TelemtAdTag    string `json:"telemt_ad_tag"`
	TelemtMaxConns int    `json:"telemt_max_conns"`
}

type EditConnectionRequest struct {
	Protocol       string `json:"protocol"`
	ClientID       string `json:"client_id"`
	TelemtQuota    string `json:"telemt_quota"`
	TelemtMaxIps   int    `json:"telemt_max_ips"`
	TelemtExpiry   string `json:"telemt_expiry"`
	TelemtSecret   string `json:"telemt_secret"`
	TelemtAdTag    string `json:"telemt_ad_tag"`
	TelemtMaxConns int    `json:"telemt_max_conns"`
}

type ConnectionActionRequest struct {
	Protocol string `json:"protocol"`
	ClientID string `json:"client_id"`
}

type ToggleConnectionRequest struct {
	Protocol string `json:"protocol"`
	ClientID string `json:"client_id"`
	Enable   bool   `json:"enable"`
}

type AddUserRequest struct {
	Username             string   `json:"username"`
	Password             string   `json:"password"`
	Role                 string   `json:"role"`
	TelegramId           *string  `json:"telegramId"`
	Email                *string  `json:"email"`
	Description          *string  `json:"description"`
	TrafficLimit         *float64 `json:"traffic_limit"`
	TrafficResetStrategy *string  `json:"traffic_reset_strategy"`
	ExpirationDate       *string  `json:"expiration_date"`
	ServerId             *int64   `json:"server_id"`
	Protocol             *string  `json:"protocol"`
	ConnectionName       *string  `json:"connection_name"`
	TelemtQuota          *string  `json:"telemt_quota"`
	TelemtMaxIps         *int     `json:"telemt_max_ips"`
	TelemtExpiry         *string  `json:"telemt_expiry"`
	TelemtSecret         *string  `json:"telemt_secret"`
	TelemtAdTag          *string  `json:"telemt_ad_tag"`
	TelemtMaxConns       *int     `json:"telemt_max_conns"`
}

type UpdateUserRequest struct {
	TelegramId           *string  `json:"telegramId"`
	Email                *string  `json:"email"`
	Description          *string  `json:"description"`
	TrafficLimit         *float64 `json:"traffic_limit"`
	TrafficResetStrategy *string  `json:"traffic_reset_strategy"`
	ExpirationDate       *string  `json:"expiration_date"`
	Password             *string  `json:"password"`
}

type ToggleUserRequest struct {
	Enabled bool `json:"enabled"`
}

type AddUserConnectionRequest struct {
	ServerId       int64   `json:"server_id"`
	Protocol       string  `json:"protocol"`
	ClientId       *string `json:"client_id"`
	ConnectionName *string `json:"connection_name"`
	TelemtQuota    *string `json:"telemt_quota"`
	TelemtMaxIps   *int    `json:"telemt_max_ips"`
	TelemtExpiry   *string `json:"telemt_expiry"`
	TelemtSecret   *string `json:"telemt_secret"`
	TelemtAdTag    *string `json:"telemt_ad_tag"`
	TelemtMaxConns *int    `json:"telemt_max_conns"`
}
