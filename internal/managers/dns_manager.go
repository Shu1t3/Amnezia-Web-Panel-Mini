package managers

import (
	"fmt"
	"strings"
)

type DNSManager struct {
	ssh *SSHManager
}

func NewDNSManager(ssh *SSHManager) *DNSManager {
	return &DNSManager{ssh: ssh}
}

func (m *DNSManager) InstallProtocol(port string) (map[string]interface{}, error) {
	if !CheckDockerInstalled(m.ssh) {
		return map[string]interface{}{"status": "error", "message": "Docker not installed"}, nil
	}

	m.ssh.RunSudoCommand("mkdir -p /opt/amnezia/dns")

	forwardConfig := `forward-zone:
   name: "."
   forward-tls-upstream: yes
   forward-addr: 1.1.1.1@853
   forward-addr: 1.0.0.1@853
`
	m.ssh.UploadFileSudo(forwardConfig, "/opt/amnezia/dns/forward-records.conf")

	dockerfile := `
FROM mvance/unbound:latest
LABEL maintainer="AmneziaVPN"
COPY forward-records.conf /opt/unbound/etc/unbound/forward-records.conf
`
	m.ssh.UploadFileSudo(dockerfile, "/opt/amnezia/dns/Dockerfile")

	m.ssh.RunSudoCommand("docker build -t amnezia-dns /opt/amnezia/dns")
	m.ssh.RunSudoCommand("docker stop amnezia-dns || true")
	m.ssh.RunSudoCommand("docker rm amnezia-dns || true")

	m.ssh.RunSudoCommand("docker network ls | grep -q amnezia-dns-net || docker network create --subnet 172.29.172.0/24 amnezia-dns-net")

	cmd := "docker run -d --name amnezia-dns --restart always --network amnezia-dns-net --ip=172.29.172.254 amnezia-dns"
	_, errOut, code := m.ssh.RunSudoCommand(cmd)
	if code != 0 {
		return map[string]interface{}{"status": "error", "message": errOut}, nil
	}

	vpnContainers := []string{"amnezia-awg2", "amnezia-wireguard", "telemt"}
	for _, c := range vpnContainers {
		m.ssh.RunSudoCommand(fmt.Sprintf("docker ps | grep -q %s && docker network connect amnezia-dns-net %s || true", c, c))
	}

	return map[string]interface{}{"status": "success", "message": "AmneziaDNS installed successfully"}, nil
}

func (m *DNSManager) GetServerStatus() map[string]interface{} {
	out, _, _ := m.ssh.RunSudoCommand("docker ps --filter name=^amnezia-dns$ --format '{{.Status}}'")
	isRunning := strings.Contains(out, "Up")

	outExists, _, _ := m.ssh.RunSudoCommand("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
	containerExists := false
	for _, name := range strings.Split(strings.TrimSpace(outExists), "\n") {
		if name == "amnezia-dns" {
			containerExists = true
			break
		}
	}

	return map[string]interface{}{
		"container_exists":  containerExists,
		"container_running": isRunning,
		"port":              "53",
		"protocol":          "dns",
	}
}

func (m *DNSManager) RemoveContainer() {
	m.ssh.RunSudoCommand("docker stop amnezia-dns || true")
	m.ssh.RunSudoCommand("docker rm amnezia-dns || true")
	m.ssh.RunSudoCommand("rm -rf /opt/amnezia/dns")
}
