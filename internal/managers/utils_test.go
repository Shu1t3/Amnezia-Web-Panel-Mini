package managers

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"100 B", 100},
		{"1 KiB", 1024},
		{"1 MiB", 1024 * 1024},
		{"1 GiB", 1024 * 1024 * 1024},
		{"1 TiB", 1024 * 1024 * 1024 * 1024},
		{"1.5 KiB", 1536},
		{"500 MiB", 500 * 1024 * 1024},
		{"  100 B  ", 100},
		{"0 B", 0},
	}

	for _, tt := range tests {
		result := ParseBytes(tt.input)
		if result != tt.expected {
			t.Errorf("ParseBytes(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestParseBytes_Invalid(t *testing.T) {
	tests := []string{
		"",
		"invalid",
		"100",
		"KB",
		"100 unknown",
		"abc KiB",
	}

	for _, input := range tests {
		result := ParseBytes(input)
		if result != 0 {
			t.Errorf("ParseBytes(%q) = %d, want 0", input, result)
		}
	}
}

func TestGenerateWGKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("GenerateWGKeyPair() error: %v", err)
	}

	if privKey == "" {
		t.Error("private key should not be empty")
	}
	if pubKey == "" {
		t.Error("public key should not be empty")
	}

	privBytes, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		t.Fatalf("private key is not valid base64: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("private key should be 32 bytes, got %d", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		t.Fatalf("public key is not valid base64: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key should be 32 bytes, got %d", len(pubBytes))
	}
}

func TestGenerateWGKeyPair_Unique(t *testing.T) {
	key1, _, _ := GenerateWGKeyPair()
	key2, _, _ := GenerateWGKeyPair()

	if key1 == key2 {
		t.Error("two generated key pairs should differ")
	}
}

func TestGeneratePSK(t *testing.T) {
	psk, err := GeneratePSK()
	if err != nil {
		t.Fatalf("GeneratePSK() error: %v", err)
	}

	if psk == "" {
		t.Error("PSK should not be empty")
	}

	pskBytes, err := base64.StdEncoding.DecodeString(psk)
	if err != nil {
		t.Fatalf("PSK is not valid base64: %v", err)
	}
	if len(pskBytes) != 32 {
		t.Errorf("PSK should be 32 bytes, got %d", len(pskBytes))
	}
}

func TestGeneratePSK_Unique(t *testing.T) {
	psk1, _ := GeneratePSK()
	psk2, _ := GeneratePSK()

	if psk1 == psk2 {
		t.Error("two generated PSKs should differ")
	}
}

func TestGenerateAwgParams(t *testing.T) {
	params := GenerateAwgParams()

	requiredKeys := []string{
		"junk_packet_count", "junk_packet_min_size", "junk_packet_max_size",
		"init_packet_junk_size", "response_packet_junk_size",
		"cookie_reply_packet_junk_size", "transport_packet_junk_size",
		"init_packet_magic_header", "response_packet_magic_header",
		"underload_packet_magic_header", "transport_packet_magic_header",
	}

	for _, key := range requiredKeys {
		val, ok := params[key]
		if !ok {
			t.Errorf("missing required key: %s", key)
			continue
		}
		if val == "" {
			t.Errorf("empty value for key: %s", key)
		}
	}
}

func TestGenerateAwgParams_Ranges(t *testing.T) {
	for i := 0; i < 10; i++ {
		params := GenerateAwgParams()

		jc := params["junk_packet_count"]
		if jc == "" {
			t.Fatal("junk_packet_count should not be empty")
		}

		jmin := params["junk_packet_min_size"]
		jmax := params["junk_packet_max_size"]
		if jmin == "" || jmax == "" {
			t.Fatal("junk_packet sizes should not be empty")
		}
	}
}

func TestGenerateAwgParams_Unique(t *testing.T) {
	p1 := GenerateAwgParams()
	p2 := GenerateAwgParams()

	same := true
	for k, v := range p1 {
		if p2[k] != v {
			same = false
			break
		}
	}

	if same {
		t.Error("two generated param sets should differ (random)")
	}
}

func TestNewSSHManager(t *testing.T) {
	m := NewSSHManager("192.168.1.1", 22, "root", "password123", "")

	if m.Host != "192.168.1.1" {
		t.Errorf("Host = %v, want 192.168.1.1", m.Host)
	}
	if m.Port != 22 {
		t.Errorf("Port = %v, want 22", m.Port)
	}
	if m.Username != "root" {
		t.Errorf("Username = %v, want root", m.Username)
	}
	if m.Password != "password123" {
		t.Errorf("Password = %v, want password123", m.Password)
	}
	if m.PrivateKey != "" {
		t.Errorf("PrivateKey should be empty, got %v", m.PrivateKey)
	}
	if !m.isRoot {
		t.Error("isRoot should be true for root user")
	}
}

func TestNewSSHManager_NonRoot(t *testing.T) {
	m := NewSSHManager("host", 22, "admin", "pass", "")
	if m.isRoot {
		t.Error("isRoot should be false for non-root user")
	}
}

func TestNewSSHManager_WithKey(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
	m := NewSSHManager("host", 2222, "user", "", key)

	if m.PrivateKey != key {
		t.Error("private key not set correctly")
	}
	if m.Password != "" {
		t.Error("password should be empty when using key")
	}
	if m.Port != 2222 {
		t.Errorf("Port = %v, want 2222", m.Port)
	}
}

func TestSSHManager_Disconnect_Nil(t *testing.T) {
	m := NewSSHManager("host", 22, "user", "pass", "")
	m.Disconnect()
	// Should not panic
}

func TestSSHManager_RunCommand_NotConnected(t *testing.T) {
	m := NewSSHManager("host", 22, "user", "pass", "")
	stdout, stderr, code := m.RunCommand("echo hello")

	if code != -1 {
		t.Errorf("expected exit code -1, got %d", code)
	}
	if !strings.Contains(stderr, "Not connected") {
		t.Errorf("expected 'Not connected' in stderr, got: %s", stderr)
	}
	_ = stdout
}

func TestSSHManager_FileExists_NotConnected(t *testing.T) {
	m := NewSSHManager("host", 22, "user", "pass", "")
	if m.FileExists("/tmp/test") {
		t.Error("FileExists should return false when not connected")
	}
}

func TestSSHManager_DownloadFile_NotConnected(t *testing.T) {
	m := NewSSHManager("host", 22, "user", "pass", "")
	_, err := m.DownloadFile("/tmp/test")
	if err == nil {
		t.Error("DownloadFile should return error when not connected")
	}
}

func TestSSHManager_UploadFile_NotConnected(t *testing.T) {
	m := NewSSHManager("host", 22, "user", "pass", "")
	err := m.UploadFile("content", "/tmp/test")
	if err == nil {
		t.Error("UploadFile should return error when not connected")
	}
}

func TestSocks5Manager(t *testing.T) {
	m := NewSocks5Manager(NewSSHManager("host", 22, "user", "pass", ""))
	if m.ssh == nil {
		t.Error("ssh manager should be set")
	}
}

func TestWireGuardManager(t *testing.T) {
	m := NewWireGuardManager(NewSSHManager("host", 22, "user", "pass", ""))
	if m.ssh == nil {
		t.Error("ssh manager should be set")
	}
}

func TestAWGManager(t *testing.T) {
	m := NewAWGManager(NewSSHManager("host", 22, "user", "pass", ""))
	if m.ssh == nil {
		t.Error("ssh manager should be set")
	}
}

func TestTelemtManager(t *testing.T) {
	m := NewTelemtManager(NewSSHManager("host", 22, "user", "pass", ""))
	if m.ssh == nil {
		t.Error("ssh manager should be set")
	}
}

func TestDNSManager(t *testing.T) {
	m := NewDNSManager(NewSSHManager("host", 22, "user", "pass", ""))
	if m.ssh == nil {
		t.Error("ssh manager should be set")
	}
}

func TestAdguardManager(t *testing.T) {
	m := NewAdguardManager(NewSSHManager("host", 22, "user", "pass", ""))
	if m.ssh == nil {
		t.Error("ssh manager should be set")
	}
}
