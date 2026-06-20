package managers

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	WgContainerName    = "amnezia-wireguard"
	WgDockerImage      = "amneziavpn/amnezia-wg:latest"
	WgConfigPath       = "/opt/amnezia/wireguard/wg0.conf"
	WgKeyDir           = "/opt/amnezia/wireguard"
	WgClientsTablePath = "/opt/amnezia/wireguard/clientsTable"
	WgInterface        = "wg0"
)

var WgDefaults = map[string]string{
	"port":           "51820",
	"mtu":            "1420",
	"subnet_address": "10.8.2.0",
	"subnet_cidr":    "24",
	"subnet_ip":      "10.8.2.1",
	"dns1":           "1.1.1.1",
	"dns2":           "1.0.0.1",
}

type WireGuardManager struct {
	ssh *SSHManager
}

func NewWireGuardManager(ssh *SSHManager) *WireGuardManager {
	return &WireGuardManager{ssh: ssh}
}

func (m *WireGuardManager) CheckContainerRunning() bool {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", WgContainerName))
	return strings.Contains(out, "Up")
}

func (m *WireGuardManager) CheckProtocolInstalled() bool {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", WgContainerName))
	names := strings.Split(strings.TrimSpace(out), "\n")
	for _, name := range names {
		if name == WgContainerName {
			return true
		}
	}
	return false
}

func (m *WireGuardManager) PrepareHost() {
	dockerfileFolder := fmt.Sprintf("/opt/amnezia/%s", WgContainerName)
	script := fmt.Sprintf(`
mkdir -p %s
mkdir -p %s
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net
fi
`, dockerfileFolder, WgKeyDir)
	_, err, code := m.ssh.RunSudoScript(script)
	if code != 0 {
		log.Printf("wg prepare_host warning: %s\n", err)
	}
}

func (m *WireGuardManager) SetupFirewall() {
	script := `
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -A FORWARD -j DOCKER-USER 2>/dev/null
`
	m.ssh.RunSudoScript(script)
}

func (m *WireGuardManager) InstallProtocol(port string) (map[string]interface{}, error) {
	if port == "" {
		port = WgDefaults["port"]
	}

	var results []string

	results = append(results, "Detecting optimal MTU...")
	optimalMtu := DetectOptimalMTU(m.ssh, "")
	results = append(results, fmt.Sprintf("Optimal MTU: %d", optimalMtu))

	if !CheckDockerInstalled(m.ssh) {
		results = append(results, "Installing Docker...")
		_, err := InstallDocker(m.ssh)
		if err != nil {
			return nil, err
		}
		results = append(results, "Docker installed successfully")
	} else {
		results = append(results, "Docker already installed")
	}

	results = append(results, "Preparing host...")
	m.PrepareHost()
	results = append(results, "Host prepared")

	if m.CheckProtocolInstalled() {
		results = append(results, "Removing old container...")
		m.RemoveContainer()
		results = append(results, "Old container removed")
	}

	results = append(results, "Building Docker image...")
	dockerfileFolder := fmt.Sprintf("/opt/amnezia/%s", WgContainerName)

	dockerfileContent := fmt.Sprintf(`FROM %s

LABEL maintainer="AmneziaVPN"

RUN apk add --no-cache curl wireguard-tools dumb-init iptables bash
RUN apk --update upgrade --no-cache

RUN mkdir -p /opt/amnezia
RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && echo "tail -f /dev/null" >> /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
`, WgDockerImage)

	m.ssh.RunSudoCommand(fmt.Sprintf("mkdir -p %s", dockerfileFolder))
	m.ssh.UploadFileSudo(dockerfileContent, fmt.Sprintf("%s/Dockerfile", dockerfileFolder))

	_, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker build --no-cache --pull -t %s %s", WgContainerName, dockerfileFolder))
	if code != 0 {
		return nil, fmt.Errorf("failed to build container: %s", errOut)
	}
	results = append(results, "Docker image built successfully")

	results = append(results, "Starting container...")
	runCmd := fmt.Sprintf(`docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p %s:%s/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name %s \
%s`, port, port, WgContainerName, WgContainerName)

	_, errOut, code = m.ssh.RunSudoCommand(runCmd)
	if code != 0 {
		return nil, fmt.Errorf("failed to run container: %s", errOut)
	}

	m.ssh.RunSudoCommand(fmt.Sprintf("docker network connect amnezia-dns-net %s", WgContainerName))

	results = append(results, "Waiting for container to start...")
	if err := m.WaitContainerRunning(30); err != nil {
		return nil, err
	}
	results = append(results, "Container started")

	results = append(results, "Configuring WireGuard...")
	if err := m.ConfigureContainer(port, optimalMtu); err != nil {
		return nil, err
	}
	results = append(results, "WireGuard configured")

	results = append(results, "Starting WireGuard service...")
	m.UploadStartScript(port)
	results = append(results, "WireGuard service started")

	results = append(results, "Setting up firewall...")
	m.SetupFirewall()
	results = append(results, "Firewall configured")

	return map[string]interface{}{
		"status":   "success",
		"protocol": "wireguard",
		"port":     port,
		"log":      results,
	}, nil
}

func (m *WireGuardManager) WaitContainerRunning(timeout int) error {
	for i := 0; i < timeout/2; i++ {
		out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker inspect --format='{{.State.Status}}' %s", WgContainerName))
		lastStatus := strings.TrimSpace(strings.Trim(out, "'\""))
		if lastStatus == "running" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	logsOut, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker logs --tail 50 %s 2>&1", WgContainerName))
	return fmt.Errorf("container did not start within %d seconds. Logs:\n%s", timeout, logsOut)
}

func (m *WireGuardManager) ConfigureContainer(port string, mtu int) error {
	subnetIp := WgDefaults["subnet_ip"]
	subnetCidr := WgDefaults["subnet_cidr"]

	configScript := fmt.Sprintf(`
mkdir -p %s
cd %s
WIREGUARD_SERVER_PRIVATE_KEY=$(wg genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > %s/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | wg pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > %s/wireguard_server_public_key.key

WIREGUARD_PSK=$(wg genpsk)
echo $WIREGUARD_PSK > %s/wireguard_psk.key

cat > %s <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = %s/%s
ListenPort = %s
MTU = %d
EOF
`, WgKeyDir, WgKeyDir, WgKeyDir, WgKeyDir, WgKeyDir, WgConfigPath, subnetIp, subnetCidr, port, mtu)

	_, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s bash -c '%s'", WgContainerName, configScript))
	if code != 0 {
		return fmt.Errorf("failed to configure container: %s", errOut)
	}
	return nil
}

func (m *WireGuardManager) UploadStartScript(port string) {
	subnetIp := WgDefaults["subnet_ip"]
	subnetCidr := WgDefaults["subnet_cidr"]

	startScript := fmt.Sprintf(`#!/bin/bash
echo "WireGuard container startup"

wg-quick down %s 2>/dev/null
if [ -f %s ]; then wg-quick up %s; fi

iptables -A INPUT -i %s -j ACCEPT
iptables -A FORWARD -i %s -j ACCEPT
iptables -A OUTPUT -o %s -j ACCEPT

iptables -A FORWARD -i %s -o eth0 -s %s/%s -j ACCEPT
iptables -A FORWARD -i %s -o eth1 -s %s/%s -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s %s/%s -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s %s/%s -o eth1 -j MASQUERADE

tail -f /dev/null
`, WgConfigPath, WgConfigPath, WgConfigPath, WgInterface, WgInterface, WgInterface, WgInterface, subnetIp, subnetCidr, WgInterface, subnetIp, subnetCidr, subnetIp, subnetCidr, subnetIp, subnetCidr)

	m.ssh.UploadFile(startScript, "/tmp/_wg_start.sh")
	m.ssh.RunSudoCommand(fmt.Sprintf("docker cp /tmp/_wg_start.sh %s:/opt/amnezia/start.sh", WgContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker exec %s chmod +x /opt/amnezia/start.sh", WgContainerName))
	m.ssh.RunCommand("rm -f /tmp/_wg_start.sh")

	m.ssh.RunSudoCommand(fmt.Sprintf("docker restart %s", WgContainerName))
	m.WaitContainerRunning(30)
}

func (m *WireGuardManager) RemoveContainer() {
	m.ssh.RunSudoCommand(fmt.Sprintf("docker stop %s", WgContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker rm -fv %s", WgContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker rmi %s", WgContainerName))
}

func (m *WireGuardManager) GetClientsTable() []map[string]interface{} {
	out, _, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null", WgContainerName, WgClientsTablePath))
	if code != 0 || strings.TrimSpace(out) == "" {
		return []map[string]interface{}{}
	}

	var data []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		return []map[string]interface{}{}
	}
	return data
}

func (m *WireGuardManager) SaveClientsTable(clients []map[string]interface{}) {
	b, _ := json.MarshalIndent(clients, "", "  ")
	m.ssh.UploadFile(string(b), "/tmp/_wg_clients.json")
	m.ssh.RunSudoCommand(fmt.Sprintf("docker cp /tmp/_wg_clients.json %s:%s", WgContainerName, WgClientsTablePath))
	m.ssh.RunCommand("rm -f /tmp/_wg_clients.json")
}

func (m *WireGuardManager) GetServerConfig() (string, error) {
	out, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s", WgContainerName, WgConfigPath))
	if code != 0 {
		return "", fmt.Errorf("failed to get server config: %s", errOut)
	}
	return out, nil
}

func (m *WireGuardManager) GetServerPublicKey() (string, error) {
	out, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s/wireguard_server_public_key.key", WgContainerName, WgKeyDir))
	if code != 0 {
		return "", fmt.Errorf("failed to get server public key: %s", errOut)
	}
	return strings.TrimSpace(out), nil
}

func (m *WireGuardManager) GetServerPsk() (string, error) {
	out, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s/wireguard_psk.key", WgContainerName, WgKeyDir))
	if code != 0 {
		return "", fmt.Errorf("failed to get psk: %s", errOut)
	}
	return strings.TrimSpace(out), nil
}

func (m *WireGuardManager) GetListenPort() string {
	config, err := m.GetServerConfig()
	if err != nil {
		return WgDefaults["port"]
	}
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ListenPort") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return WgDefaults["port"]
}

func (m *WireGuardManager) GetMtu() string {
	config, err := m.GetServerConfig()
	if err != nil {
		return WgDefaults["mtu"]
	}
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "MTU") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return WgDefaults["mtu"]
}

func (m *WireGuardManager) GetUsedIps() []string {
	config, _ := m.GetServerConfig()
	var ips []string
	re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AllowedIPs") || strings.HasPrefix(line, "Address") {
			match := re.FindStringSubmatch(line)
			if len(match) > 1 {
				ips = append(ips, match[1])
			}
		}
	}
	return ips
}

func (m *WireGuardManager) GetNextIp() string {
	usedIps := m.GetUsedIps()
	if len(usedIps) == 0 {
		parts := strings.Split(WgDefaults["subnet_address"], ".")
		parts[3] = "2"
		return strings.Join(parts, ".")
	}
	lastIp := usedIps[len(usedIps)-1]
	parts := strings.Split(lastIp, ".")
	lastOctet, _ := strconv.Atoi(parts[3])
	nextOctet := lastOctet + 1
	if nextOctet > 254 {
		nextOctet = 2
	}
	parts[3] = strconv.Itoa(nextOctet)
	return strings.Join(parts, ".")
}

func (m *WireGuardManager) WgShow() map[string]map[string]interface{} {
	out, _, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s bash -c 'wg show all'", WgContainerName))
	if code != 0 || strings.TrimSpace(out) == "" {
		return make(map[string]map[string]interface{})
	}

	result := make(map[string]map[string]interface{})
	var currentPeer string

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "peer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentPeer = strings.TrimSpace(parts[1])
				result[currentPeer] = make(map[string]interface{})
			}
		} else if currentPeer != "" && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "latest handshake":
				result[currentPeer]["latestHandshake"] = value
			case "transfer":
				transferParts := strings.Split(value, ",")
				if len(transferParts) == 2 {
					received := strings.Replace(strings.TrimSpace(transferParts[0]), " received", "", -1)
					sent := strings.Replace(strings.TrimSpace(transferParts[1]), " sent", "", -1)
					result[currentPeer]["dataReceived"] = received
					result[currentPeer]["dataSent"] = sent
					result[currentPeer]["dataReceivedBytes"] = ParseBytes(received)
					result[currentPeer]["dataSentBytes"] = ParseBytes(sent)
				}
			case "allowed ips":
				result[currentPeer]["allowedIps"] = value
			}
		}
	}
	return result
}

func (m *WireGuardManager) AddClient(clientName, serverHost string) (map[string]interface{}, error) {
	clientPrivKey, clientPubKey, err := GenerateWGKeyPair()
	if err != nil {
		return nil, err
	}

	serverPubKey, err := m.GetServerPublicKey()
	if err != nil {
		return nil, err
	}
	psk, err := m.GetServerPsk()
	if err != nil {
		return nil, err
	}
	port := m.GetListenPort()
	clientIp := m.GetNextIp()

	dns1 := WgDefaults["dns1"]
	dns2 := WgDefaults["dns2"]

	out, _, _ := m.ssh.RunSudoCommand("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
	if strings.Contains(out, "amnezia-dns") {
		dns1 = "172.29.172.254"
	}

	mtu := m.GetMtu()

	peerSection := fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s/32
`, clientPubKey, psk, clientIp)

	escapedPeer := strings.ReplaceAll(peerSection, "'", "'\\''")
	m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s bash -c 'echo \"%s\" >> %s'", WgContainerName, escapedPeer, WgConfigPath))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s bash -c 'wg syncconf %s <(wg-quick strip %s)'", WgContainerName, WgInterface, WgConfigPath))

	clientsTable := m.GetClientsTable()
	userData := map[string]interface{}{
		"clientName":       clientName,
		"creationDate":     time.Now().Format(time.RFC3339),
		"clientPrivateKey": clientPrivKey,
		"clientIp":         clientIp,
		"psk":              psk,
		"enabled":          true,
	}
	newClient := map[string]interface{}{
		"clientId": clientPubKey,
		"userData": userData,
	}
	clientsTable = append(clientsTable, newClient)
	m.SaveClientsTable(clientsTable)

	clientConfig := fmt.Sprintf(`[Interface]
Address = %s/32
DNS = %s, %s
PrivateKey = %s
MTU = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s:%s
PersistentKeepalive = 25
`, clientIp, dns1, dns2, clientPrivKey, mtu, serverPubKey, psk, serverHost, port)

	return map[string]interface{}{
		"client_name": clientName,
		"client_id":   clientPubKey,
		"client_ip":   clientIp,
		"config":      clientConfig,
	}, nil
}

func (m *WireGuardManager) GetServerStatus() map[string]interface{} {
	exists := m.CheckProtocolInstalled()
	running := false
	if exists {
		running = m.CheckContainerRunning()
	}

	info := map[string]interface{}{
		"container_exists":  exists,
		"container_running": running,
		"protocol":          "wireguard",
	}

	if running {
		config, err := m.GetServerConfig()
		if err == nil {
			for _, line := range strings.Split(config, "\n") {
				if strings.Contains(line, "ListenPort") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						info["port"] = strings.TrimSpace(parts[1])
						break
					}
				}
			}
			info["clients_count"] = len(m.GetClientsTable())
		}
	}
	return info
}
