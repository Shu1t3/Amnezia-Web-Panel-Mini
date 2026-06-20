package handlers

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestMathRound(t *testing.T) {
	tests := []struct {
		val       float64
		precision int
		expected  float64
	}{
		{3.14159, 2, 3.14},
		{3.14159, 0, 3},
		{3.5, 0, 4},
		{2.5, 0, 3},
		{-3.14159, 2, -3.14},
		{-2.5, 0, -3},
		{0.0, 5, 0.0},
		{1.005, 2, 1.0},
		{123.456, 1, 123.5},
	}

	for _, tt := range tests {
		result := mathRound(tt.val, tt.precision)
		if result != tt.expected {
			t.Errorf("mathRound(%v, %d) = %v, want %v", tt.val, tt.precision, result, tt.expected)
		}
	}
}

func TestGenerateVpnLink(t *testing.T) {
	config := "[Interface]\nPrivateKey = abc123\nAddress = 10.0.0.1/32\n\n[Peer]\nPublicKey = xyz789\n"
	expected := "vpn://" + base64.StdEncoding.EncodeToString([]byte(config))

	result := generateVpnLink(config)
	if result != expected {
		t.Errorf("generateVpnLink() = %v, want %v", result, expected)
	}
}

func TestGenerateVpnLink_Empty(t *testing.T) {
	result := generateVpnLink("")
	expected := "vpn://" + base64.StdEncoding.EncodeToString([]byte(""))
	if result != expected {
		t.Errorf("generateVpnLink('') = %v, want %v", result, expected)
	}
}

func TestIsLoginRateLimited(t *testing.T) {
	loginAttemptsMu.Lock()
	loginAttempts = make(map[string][]loginAttempt)
	loginAttemptsMu.Unlock()

	ip := "192.168.1.100"

	if isLoginRateLimited(ip) {
		t.Error("should not be rate limited with 0 attempts")
	}

	for i := 0; i < 4; i++ {
		recordLoginAttempt(ip)
	}

	if isLoginRateLimited(ip) {
		t.Error("should not be rate limited with 4 attempts")
	}

	recordLoginAttempt(ip)

	if !isLoginRateLimited(ip) {
		t.Error("should be rate limited with 5 attempts")
	}
}

func TestIsLoginRateLimited_DifferentIPs(t *testing.T) {
	loginAttemptsMu.Lock()
	loginAttempts = make(map[string][]loginAttempt)
	loginAttemptsMu.Unlock()

	for i := 0; i < 5; i++ {
		recordLoginAttempt("10.0.0.1")
	}

	if isLoginRateLimited("10.0.0.2") {
		t.Error("different IP should not be rate limited")
	}
}

func TestIsLoginRateLimited_OldAttemptsExpire(t *testing.T) {
	loginAttemptsMu.Lock()
	loginAttempts = make(map[string][]loginAttempt)
	loginAttemptsMu.Unlock()

	loginAttemptsMu.Lock()
	loginAttempts["old_ip"] = []loginAttempt{
		{timestamp: time.Now().Add(-20 * time.Minute)},
		{timestamp: time.Now().Add(-20 * time.Minute)},
		{timestamp: time.Now().Add(-20 * time.Minute)},
		{timestamp: time.Now().Add(-20 * time.Minute)},
		{timestamp: time.Now().Add(-20 * time.Minute)},
	}
	loginAttemptsMu.Unlock()

	if isLoginRateLimited("old_ip") {
		t.Error("old attempts should have expired")
	}
}

func TestGenerateCaptchaCode(t *testing.T) {
	code := generateCaptchaCode()
	if len(code) != 5 {
		t.Errorf("expected 5-char captcha, got %d chars", len(code))
	}

	for _, c := range code {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '9')) {
			t.Errorf("unexpected character in captcha: %c", c)
		}
	}
}

func TestGenerateCaptchaCode_Unique(t *testing.T) {
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code := generateCaptchaCode()
		if codes[code] {
			t.Errorf("duplicate captcha code: %s", code)
		}
		codes[code] = true
	}
}
