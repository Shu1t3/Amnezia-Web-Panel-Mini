package managers

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	AwgContainerName    = "amnezia-awg2"
	AwgDockerImage      = "amneziavpn/amneziawg-go:latest"
	AwgConfigPath       = "/opt/amnezia/awg/awg0.conf"
	AwgKeyDir           = "/opt/amnezia/awg"
	AwgClientsTablePath = "/opt/amnezia/awg/clientsTable"
	AwgInterface        = "awg0"
)

var AwgDefaults = map[string]string{
	"port":                          "55424",
	"mtu":                           "1280",
	"subnet_address":                "10.8.1.0",
	"subnet_cidr":                   "24",
	"subnet_ip":                     "10.8.1.1",
	"dns1":                          "1.1.1.1",
	"dns2":                          "1.0.0.1",
	"junk_packet_count":             "3",
	"junk_packet_min_size":          "10",
	"junk_packet_max_size":          "30",
	"init_packet_junk_size":         "15",
	"response_packet_junk_size":     "18",
	"cookie_reply_packet_junk_size": "20",
	"transport_packet_junk_size":    "23",
	"init_packet_magic_header":      "1020325451",
	"response_packet_magic_header":  "3288052141",
	"transport_packet_magic_header": "2528465083",
	"underload_packet_magic_header": "1766607858",
}

func GenerateAwgParams() map[string]string {
	rand.Seed(time.Now().UnixNano())
	jmin := rand.Intn(16) + 5 // 5 to 20
	return map[string]string{
		"junk_packet_count":             strconv.Itoa(rand.Intn(10) + 1),
		"junk_packet_min_size":          strconv.Itoa(jmin),
		"junk_packet_max_size":          strconv.Itoa(rand.Intn(41) + jmin + 10), // jmin+10 to jmin+50
		"init_packet_junk_size":         strconv.Itoa(rand.Intn(41) + 10),        // 10 to 50
		"response_packet_junk_size":     strconv.Itoa(rand.Intn(41) + 10),
		"cookie_reply_packet_junk_size": strconv.Itoa(rand.Intn(41) + 10),
		"transport_packet_junk_size":    strconv.Itoa(rand.Intn(41) + 10),
		"init_packet_magic_header":      strconv.Itoa(rand.Intn(3294967295) + 1000000000),
		"response_packet_magic_header":  strconv.Itoa(rand.Intn(3294967295) + 1000000000),
		"underload_packet_magic_header": strconv.Itoa(rand.Intn(3294967295) + 1000000000),
		"transport_packet_magic_header": strconv.Itoa(rand.Intn(3294967295) + 1000000000),
	}
}

type AWGManager struct {
	ssh *SSHManager
}

func NewAWGManager(ssh *SSHManager) *AWGManager {
	return &AWGManager{ssh: ssh}
}

func (m *AWGManager) CheckContainerRunning() bool {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", AwgContainerName))
	return strings.Contains(out, "Up")
}

func (m *AWGManager) CheckProtocolInstalled() bool {
	out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", AwgContainerName))
	names := strings.Split(strings.TrimSpace(out), "\n")
	for _, name := range names {
		if name == AwgContainerName {
			return true
		}
	}
	return false
}

func (m *AWGManager) PrepareHost() {
	dockerfileFolder := fmt.Sprintf("/opt/amnezia/%s", AwgContainerName)
	script := fmt.Sprintf(`
mkdir -p %s
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net
fi
`, dockerfileFolder)
	_, err, code := m.ssh.RunSudoScript(script)
	if code != 0 {
		log.Printf("awg prepare_host warning: %s\n", err)
	}
}

func (m *AWGManager) SetupFirewall() {
	script := `
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -A FORWARD -j DOCKER-USER 2>/dev/null
`
	m.ssh.RunSudoScript(script)
}

func (m *AWGManager) InstallProtocol(port string, awgParams map[string]string) (map[string]interface{}, error) {
	if port == "" {
		port = AwgDefaults["port"]
	}
	if awgParams == nil {
		awgParams = GenerateAwgParams()
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

	results = append(results, "Pulling Docker image...")
	dockerfileFolder := fmt.Sprintf("/opt/amnezia/%s", AwgContainerName)

	dockerfileContent := fmt.Sprintf(`FROM %s

LABEL maintainer="AmneziaVPN"

RUN apk add --no-cache bash curl dumb-init iptables
RUN apk --update upgrade --no-cache

RUN mkdir -p /opt/amnezia
RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && echo "tail -f /dev/null" >> /opt/amnezia/start.sh
RUN chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
`, AwgDockerImage)

	m.ssh.RunSudoCommand(fmt.Sprintf("mkdir -p %s", dockerfileFolder))
	m.ssh.UploadFileSudo(dockerfileContent, fmt.Sprintf("%s/Dockerfile", dockerfileFolder))

	_, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker build --no-cache --pull -t %s %s", AwgContainerName, dockerfileFolder))
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
%s`, port, port, AwgContainerName, AwgContainerName)

	_, errOut, code = m.ssh.RunSudoCommand(runCmd)
	if code != 0 {
		return nil, fmt.Errorf("failed to run container: %s", errOut)
	}

	m.ssh.RunSudoCommand(fmt.Sprintf("docker network connect amnezia-dns-net %s", AwgContainerName))

	results = append(results, "Waiting for container to start...")
	if err := m.WaitContainerRunning(30); err != nil {
		return nil, err
	}
	results = append(results, "Container started")

	results = append(results, "Configuring AWG...")
	if err := m.ConfigureContainer(port, awgParams, optimalMtu); err != nil {
		return nil, err
	}
	results = append(results, "AWG configured")

	results = append(results, "Starting AWG service...")
	m.UploadStartScript(port, awgParams)
	results = append(results, "AWG service started")

	results = append(results, "Setting up firewall...")
	m.SetupFirewall()
	results = append(results, "Firewall configured")

	return map[string]interface{}{
		"status":     "success",
		"protocol":   "awg2",
		"port":       port,
		"awg_params": awgParams,
		"log":        results,
	}, nil
}

func (m *AWGManager) WaitContainerRunning(timeout int) error {
	for i := 0; i < timeout/2; i++ {
		out, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker inspect --format='{{.State.Status}}' %s", AwgContainerName))
		lastStatus := strings.TrimSpace(strings.Trim(out, "'\""))
		if lastStatus == "running" {
			time.Sleep(1 * time.Second)
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	logsOut, _, _ := m.ssh.RunSudoCommand(fmt.Sprintf("docker logs --tail 50 %s 2>&1", AwgContainerName))
	return fmt.Errorf("container did not start within %d seconds. Logs:\n%s", timeout, logsOut)
}

func (m *AWGManager) ConfigureContainer(port string, awgParams map[string]string, mtu int) error {
	subnetIp := AwgDefaults["subnet_ip"]
	subnetCidr := AwgDefaults["subnet_cidr"]

	configScript := fmt.Sprintf(`
mkdir -p %s
cd %s
WIREGUARD_SERVER_PRIVATE_KEY=$(awg genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > %s/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | awg pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > %s/wireguard_server_public_key.key

WIREGUARD_PSK=$(awg genpsk)
echo $WIREGUARD_PSK > %s/wireguard_psk.key

cat > %s <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = %s/%s
ListenPort = %s
MTU = %d
Jc = %s
Jmin = %s
Jmax = %s
S1 = %s
S2 = %s
S3 = %s
S4 = %s
H1 = %s
H2 = %s
H3 = %s
H4 = %s
EOF
`, AwgKeyDir, AwgKeyDir, AwgKeyDir, AwgKeyDir, AwgKeyDir, AwgConfigPath, subnetIp, subnetCidr, port, mtu,
		awgParams["junk_packet_count"], awgParams["junk_packet_min_size"], awgParams["junk_packet_max_size"],
		awgParams["init_packet_junk_size"], awgParams["response_packet_junk_size"], awgParams["cookie_reply_packet_junk_size"],
		awgParams["transport_packet_junk_size"], awgParams["init_packet_magic_header"], awgParams["response_packet_magic_header"],
		awgParams["underload_packet_magic_header"], awgParams["transport_packet_magic_header"])

	_, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s bash -c '%s'", AwgContainerName, configScript))
	if code != 0 {
		return fmt.Errorf("failed to configure container: %s", errOut)
	}
	return nil
}

func (m *AWGManager) UploadStartScript(port string, awgParams map[string]string) {
	subnetIp := AwgDefaults["subnet_ip"]
	subnetCidr := AwgDefaults["subnet_cidr"]

	startScript := fmt.Sprintf(`#!/bin/bash
echo "Container startup"

awg-quick down %s 2>/dev/null
if [ -f %s ]; then awg-quick up %s; fi

IFACE=$(basename %s .conf)
iptables -A INPUT -i $IFACE -j ACCEPT
iptables -A FORWARD -i $IFACE -j ACCEPT
iptables -A OUTPUT -o $IFACE -j ACCEPT

iptables -A FORWARD -i $IFACE -o eth0 -s %s/%s -j ACCEPT
iptables -A FORWARD -i $IFACE -o eth1 -s %s/%s -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s %s/%s -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s %s/%s -o eth1 -j MASQUERADE

tail -f /dev/null
`, AwgConfigPath, AwgConfigPath, AwgConfigPath, AwgConfigPath, subnetIp, subnetCidr, subnetIp, subnetCidr, subnetIp, subnetCidr, subnetIp, subnetCidr)

	m.ssh.UploadFile(startScript, "/tmp/_amnz_start.sh")
	m.ssh.RunSudoCommand(fmt.Sprintf("docker cp /tmp/_amnz_start.sh %s:/opt/amnezia/start.sh", AwgContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker exec %s chmod +x /opt/amnezia/start.sh", AwgContainerName))
	m.ssh.RunCommand("rm -f /tmp/_amnz_start.sh")

	m.ssh.RunSudoCommand(fmt.Sprintf("docker restart %s", AwgContainerName))
	time.Sleep(5 * time.Second)
}

func (m *AWGManager) RemoveContainer() {
	m.ssh.RunSudoCommand(fmt.Sprintf("docker stop %s", AwgContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker rm -fv %s", AwgContainerName))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker rmi %s", AwgContainerName))
}

func (m *AWGManager) GetClientsTable() []map[string]interface{} {
	out, _, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null", AwgContainerName, AwgClientsTablePath))
	if code != 0 || strings.TrimSpace(out) == "" {
		return []map[string]interface{}{}
	}

	var data []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		return []map[string]interface{}{}
	}
	return data
}

func (m *AWGManager) SaveClientsTable(clients []map[string]interface{}) {
	b, _ := json.MarshalIndent(clients, "", "  ")
	m.ssh.UploadFile(string(b), "/tmp/_amnz_clients.json")
	m.ssh.RunSudoCommand(fmt.Sprintf("docker cp /tmp/_amnz_clients.json %s:%s", AwgContainerName, AwgClientsTablePath))
	m.ssh.RunCommand("rm -f /tmp/_amnz_clients.json")
}

func (m *AWGManager) GetServerConfig() (string, error) {
	out, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s", AwgContainerName, AwgConfigPath))
	if code != 0 {
		return "", fmt.Errorf("failed to get server config: %s", errOut)
	}
	return out, nil
}

func (m *AWGManager) GetServerPublicKey() (string, error) {
	out, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s/wireguard_server_public_key.key", AwgContainerName, AwgKeyDir))
	if code != 0 {
		return "", fmt.Errorf("failed to get server public key: %s", errOut)
	}
	return strings.TrimSpace(out), nil
}

func (m *AWGManager) GetServerPsk() (string, error) {
	out, errOut, code := m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s cat %s/wireguard_psk.key", AwgContainerName, AwgKeyDir))
	if code != 0 {
		return "", fmt.Errorf("failed to get psk: %s", errOut)
	}
	return strings.TrimSpace(out), nil
}

func (m *AWGManager) GetAwgParamsFromConfig() map[string]string {
	config, err := m.GetServerConfig()
	if err != nil {
		return AwgDefaults
	}
	params := make(map[string]string)
	paramMap := map[string]string{
		"ListenPort": "port", "Jc": "junk_packet_count", "Jmin": "junk_packet_min_size", "Jmax": "junk_packet_max_size",
		"S1": "init_packet_junk_size", "S2": "response_packet_junk_size", "S3": "cookie_reply_packet_junk_size", "S4": "transport_packet_junk_size",
		"H1": "init_packet_magic_header", "H2": "response_packet_magic_header", "H3": "underload_packet_magic_header", "H4": "transport_packet_magic_header",
	}

	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "[") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if paramKey, ok := paramMap[key]; ok {
				params[paramKey] = val
			}
		}
	}
	return params
}

func (m *AWGManager) GetUsedIps() []string {
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

func (m *AWGManager) GetNextIp() string {
	usedIps := m.GetUsedIps()
	if len(usedIps) == 0 {
		parts := strings.Split(AwgDefaults["subnet_address"], ".")
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

func (m *AWGManager) AddClient(clientName, serverHost, port string) (map[string]interface{}, error) {
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
	clientIp := m.GetNextIp()
	awgParams := m.GetAwgParamsFromConfig()
	if p, ok := awgParams["port"]; ok && port == "" {
		port = p
	}

	dns1 := AwgDefaults["dns1"]
	dns2 := AwgDefaults["dns2"]

	out, _, _ := m.ssh.RunSudoCommand("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
	if strings.Contains(out, "amnezia-dns") {
		dns1 = "172.29.172.254"
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

	peerSection := fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s/32
`, clientPubKey, psk, clientIp)

	escapedPeer := strings.ReplaceAll(peerSection, "'", "'\\''")
	m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s bash -c 'echo \"%s\" >> %s'", AwgContainerName, escapedPeer, AwgConfigPath))
	m.ssh.RunSudoCommand(fmt.Sprintf("docker exec -i %s bash -c 'awg syncconf %s <(awg-quick strip %s)'", AwgContainerName, AwgInterface, AwgConfigPath))

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

	var configLines []string
	configLines = append(configLines, fmt.Sprintf("Address = %s/32", clientIp))
	configLines = append(configLines, fmt.Sprintf("DNS = %s, %s", dns1, dns2))
	configLines = append(configLines, fmt.Sprintf("PrivateKey = %s", clientPrivKey))
	configLines = append(configLines, fmt.Sprintf("MTU = %s", mtu))

	mapping := []struct {
		paramKey  string
		configKey string
	}{
		{"junk_packet_count", "Jc"}, {"junk_packet_min_size", "Jmin"}, {"junk_packet_max_size", "Jmax"},
		{"init_packet_junk_size", "S1"}, {"response_packet_junk_size", "S2"}, {"cookie_reply_packet_junk_size", "S3"},
		{"transport_packet_junk_size", "S4"}, {"init_packet_magic_header", "H1"}, {"response_packet_magic_header", "H2"},
		{"underload_packet_magic_header", "H3"}, {"transport_packet_magic_header", "H4"},
	}

	for _, m := range mapping {
		if val, ok := awgParams[m.paramKey]; ok && val != "" {
			configLines = append(configLines, fmt.Sprintf("%s = %s", m.configKey, val))
		}
	}

	clientConfig := "[Interface]\n" + strings.Join(configLines, "\n") + fmt.Sprintf(`

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s:%s
PersistentKeepalive = 25
`, serverPubKey, psk, serverHost, port)

	return map[string]interface{}{
		"client_name": clientName,
		"client_id":   clientPubKey,
		"client_ip":   clientIp,
		"config":      clientConfig,
	}, nil
}

func (m *AWGManager) GetServerStatus() map[string]interface{} {
	exists := m.CheckProtocolInstalled()
	running := false
	if exists {
		running = m.CheckContainerRunning()
	}

	info := map[string]interface{}{
		"container_exists":  exists,
		"container_running": running,
		"protocol":          "awg2",
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
			info["awg_params"] = m.GetAwgParamsFromConfig()
			info["clients_count"] = len(m.GetClientsTable())
		}
	}
	return info
}
