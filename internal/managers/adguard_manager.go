package managers

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	AdguardContainerName = "amnezia-adguard"
	AdguardImageName     = "adguard/adguardhome:latest"
	AdguardNetworkName   = "amnezia-dns-net"
	AdguardNetworkSubnet = "172.29.172.0/24"
	AdguardReplaceIP     = "172.29.172.254"
	AdguardSidebysideIP  = "172.29.172.253"
	AdguardHostDir       = "/opt/amnezia/adguard"
)

var AdguardDefaults = map[string]int{
	"dns_port": 53,
	"web_port": 3000,
	"dot_port": 853,
	"doh_port": 443,
}

type AdguardManager struct {
	ssh *SSHManager
}

func NewAdguardManager(ssh *SSHManager) *AdguardManager {
	return &AdguardManager{ssh: ssh}
}

func (m *AdguardManager) CheckProtocolInstalled() bool {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", AdguardContainerName))
	return strings.Contains(out, AdguardContainerName)
}

func (m *AdguardManager) CheckContainerRunning() bool {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", AdguardContainerName))
	return strings.Contains(out, "Up")
}

func (m *AdguardManager) containerIP() string {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s 2>/dev/null", AdguardContainerName))
	if strings.TrimSpace(out) != "" {
		return strings.Split(strings.TrimSpace(out), " ")[0]
	}
	return ""
}

func (m *AdguardManager) detectMode() string {
	ip := m.containerIP()
	if ip == AdguardReplaceIP {
		return "replace"
	}
	if ip == AdguardSidebysideIP {
		return "sidebyside"
	}
	return ""
}

func (m *AdguardManager) exposedWebPort() int {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker port %s 3000/tcp 2>/dev/null", AdguardContainerName))
	if strings.TrimSpace(out) == "" {
		return 0
	}
	parts := strings.Split(strings.Split(strings.TrimSpace(out), "\n")[0], ":")
	last := strings.TrimSpace(parts[len(parts)-1])
	if p, err := strconv.Atoi(last); err == nil {
		return p
	}
	return 0
}

func (m *AdguardManager) GetServerStatus() map[string]interface{} {
	exists := m.CheckProtocolInstalled()
	running := m.CheckContainerRunning()
	mode := ""
	ip := ""
	exposedPort := 0

	if running {
		mode = m.detectMode()
		ip = m.containerIP()
		exposedPort = m.exposedWebPort()
	}

	webPort := AdguardDefaults["web_port"]
	if exposedPort > 0 {
		webPort = exposedPort
	}

	return map[string]interface{}{
		"container_exists":  exists,
		"container_running": running,
		"mode":              mode,
		"internal_ip":       ip,
		"web_port":          webPort,
		"web_exposed":       exposedPort > 0,
		"port":              AdguardDefaults["dns_port"],
		"protocol":          "adguard",
	}
}

func (m *AdguardManager) ensureNetwork() {
	m.ssh.RunSudoCommand(fmt.Sprintf("docker network ls | grep -q %s || docker network create --subnet %s %s", AdguardNetworkName, AdguardNetworkSubnet, AdguardNetworkName))
}

func (m *AdguardManager) InstallProtocol(mode string, webPort, dnsPort, dotPort, dohPort int, exposeWeb, exposeDns, exposeDot, exposeDoh bool) map[string]interface{} {
	if !CheckDockerInstalled(m.ssh) {
		return map[string]interface{}{"status": "error", "message": "Docker not installed"}
	}
	if mode != "replace" && mode != "sidebyside" {
		return map[string]interface{}{"status": "error", "message": fmt.Sprintf("Invalid mode '%s'", mode)}
	}

	if webPort == 0 {
		webPort = AdguardDefaults["web_port"]
	}
	if dnsPort == 0 {
		dnsPort = AdguardDefaults["dns_port"]
	}
	if dotPort == 0 {
		dotPort = AdguardDefaults["dot_port"]
	}
	if dohPort == 0 {
		dohPort = AdguardDefaults["doh_port"]
	}

	m.ssh.RunSudoCommand(fmt.Sprintf("mkdir -p %s/work %s/conf", AdguardHostDir, AdguardHostDir))
	m.ensureNetwork()

	targetIp := AdguardSidebysideIP
	if mode == "replace" {
		m.ssh.RunSudoCommand(fmt.Sprintf("docker network disconnect %s amnezia-dns 2>/dev/null || true", AdguardNetworkName))
		m.ssh.RunSudoCommand("docker stop amnezia-dns 2>/dev/null || true")
		m.ssh.RunSudoCommand("docker rm -fv amnezia-dns 2>/dev/null || true")
		targetIp = AdguardReplaceIP
	}

	if m.CheckProtocolInstalled() {
		m.ssh.RunSudoCommand(fmt.Sprintf("docker stop %s 2>/dev/null || true", AdguardContainerName))
		m.ssh.RunSudoCommand(fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", AdguardContainerName))
	}

	m.ssh.RunSudoCommand(fmt.Sprintf("docker pull %s", AdguardImageName))

	var ports []string
	if exposeWeb {
		ports = append(ports, fmt.Sprintf("-p %d:3000/tcp", webPort))
	}
	if exposeDns {
		ports = append(ports, fmt.Sprintf("-p %d:53/tcp -p %d:53/udp", dnsPort, dnsPort))
	}
	if exposeDot {
		ports = append(ports, fmt.Sprintf("-p %d:853/tcp", dotPort))
	}
	if exposeDoh {
		ports = append(ports, fmt.Sprintf("-p %d:443/tcp", dohPort))
	}
	portsStr := strings.Join(ports, " ")

	runCmd := fmt.Sprintf("docker run -d --name %s --restart always --network %s --ip %s -v %s/work:/opt/adguardhome/work -v %s/conf:/opt/adguardhome/conf %s %s",
		AdguardContainerName, AdguardNetworkName, targetIp, AdguardHostDir, AdguardHostDir, portsStr, AdguardImageName)
	_, errOut, code := m.ssh.RunSudoCommand(runCmd)

	if code != 0 {
		return map[string]interface{}{"status": "error", "message": fmt.Sprintf("Failed to start container: %s", errOut)}
	}

	vpnContainers := []string{"amnezia-awg2", "amnezia-wireguard", "telemt"}
	for _, c := range vpnContainers {
		m.ssh.RunSudoCommand(fmt.Sprintf("docker ps --format '{{.Names}}' | grep -q '^%s$' && docker network connect %s %s 2>/dev/null || true", c, AdguardNetworkName, c))
	}

	urlHost := targetIp
	if exposeWeb {
		urlHost = m.ssh.Host
	}
	adminUrl := fmt.Sprintf("http://%s:%d", urlHost, webPort)

	adminUiMsg := fmt.Sprintf("Admin UI: %s", adminUrl)
	if !exposeWeb {
		adminUiMsg += "  (VPN-only — connect via VPN to reach it)"
	}

	return map[string]interface{}{
		"status":      "success",
		"protocol":    "adguard",
		"mode":        mode,
		"internal_ip": targetIp,
		"web_port":    webPort,
		"expose_web":  exposeWeb,
		"admin_url":   adminUrl,
		"message":     "AdGuard Home installed. Complete the setup wizard via the web UI.",
		"log": []string{
			fmt.Sprintf("AdGuard Home installed in '%s' mode", mode),
			fmt.Sprintf("Internal IP: %s", targetIp),
			adminUiMsg,
			"Open the URL above to run the AdGuard setup wizard.",
		},
	}
}

func (m *AdguardManager) RemoveContainer() {
	m.ssh.RunSudoCommand(fmt.Sprintf("docker stop %s || true", AdguardContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker rm -fv %s || true", AdguardContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("rm -rf %s", AdguardHostDir))
}
