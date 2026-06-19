package managers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenerateWGKeyPair generates a WireGuard X25519 keypair (private, public) as base64 strings.
func GenerateWGKeyPair() (string, string, error) {
	var privateKey [32]byte
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return "", "", err
	}
	// clamp private key
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return base64.StdEncoding.EncodeToString(privateKey[:]), base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

// GeneratePSK generates a WireGuard preshared key.
func GeneratePSK() (string, error) {
	var psk [32]byte
	if _, err := io.ReadFull(rand.Reader, psk[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(psk[:]), nil
}

// DetectOptimalMTU detects optimal MTU by pinging with decreasing packet sizes.
func DetectOptimalMTU(ssh *SSHManager, targetHost string) int {
	if targetHost == "" {
		targetHost = "8.8.8.8"
	}

	maxPayload := 1472
	minPayload := 576
	low := minPayload
	high := maxPayload
	optimal := 1280

	for low <= high {
		mid := (low + high) / 2
		cmd := fmt.Sprintf("ping -M do -s %d -c 1 -W 2 %s 2>/dev/null", mid, targetHost)
		_, _, code := ssh.RunCommand(cmd)

		if code == 0 {
			optimal = mid + 28
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	if optimal < 1280 {
		optimal = 1280
	}
	if optimal > 1500 {
		optimal = 1500
	}

	log.Printf("Detected optimal MTU: %d for %s", optimal, targetHost)
	return optimal
}

// CheckDockerInstalled checks if Docker is installed and running.
func CheckDockerInstalled(ssh *SSHManager) bool {
	_, _, code := ssh.RunCommand("docker --version 2>/dev/null")
	if code != 0 {
		return false
	}
	out, _, _ := ssh.RunCommand("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null || (docker info >/dev/null 2>&1 && echo active)")
	return strings.Contains(out, "active") || strings.Contains(strings.ToLower(out), "running")
}

// InstallDocker installs Docker on the server.
func InstallDocker(ssh *SSHManager) (string, error) {
	script := `
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
elif which zypper > /dev/null 2>&1; then pm=$(which zypper); silent_inst="-nq install"; check_pkgs="-nq refresh"; docker_pkg="docker"; dist="opensuse";
elif which pacman > /dev/null 2>&1; then pm=$(which pacman); silent_inst="-S --noconfirm --noprogressbar --quiet"; check_pkgs="-Sup"; docker_pkg="docker"; dist="archlinux";
else echo "Packet manager not found"; exit 1; fi;
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl enable --now docker; sleep 5;
fi;
if [ "$(systemctl is-active docker)" != "active" ]; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl start docker; sleep 5;
fi;
docker --version
`
	out, errOut, code := ssh.RunSudoScript(script)
	if code != 0 {
		return "", fmt.Errorf("failed to install Docker: %s", errOut)
	}
	return out, nil
}

// ParseBytes parses human readable size string into bytes.
func ParseBytes(sizeStr string) int64 {
	parts := strings.Fields(strings.TrimSpace(sizeStr))
	if len(parts) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	unit := parts[1]
	units := map[string]int64{
		"B":   1,
		"KiB": 1024,
		"MiB": 1024 * 1024,
		"GiB": 1024 * 1024 * 1024,
		"TiB": 1024 * 1024 * 1024 * 1024,
	}
	if multiplier, ok := units[unit]; ok {
		return int64(val * float64(multiplier))
	}
	return 0
}
