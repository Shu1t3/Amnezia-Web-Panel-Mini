"""
AWG 2.0 Protocol Manager - handles AmneziaWG 2.0 protocol
installation, configuration, and client management on remote servers.
"""

import json
import secrets
import logging
import re
import random
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


def detect_optimal_mtu(ssh, target_host=None):
    """
    Detect optimal MTU by pinging with decreasing packet sizes.
    Uses the same approach as AmneziaVPN client scripts.
    
    Args:
        ssh: SSHManager instance
        target_host: Host to ping (default: 8.8.8.8)
    
    Returns:
        Optimal MTU value (int)
    """
    if not target_host:
        target_host = '8.8.8.8'
    
    max_payload = 1472
    min_payload = 576
    low = min_payload
    high = max_payload
    optimal = 1280  # Safe default for AWG
    
    while low <= high:
        mid = (low + high) // 2
        out, _, code = ssh.run_command(
            f"ping -M do -s {mid} -c 1 -W 2 {target_host} 2>/dev/null"
        )
        if code == 0:
            optimal = mid + 28
            low = mid + 1
        else:
            high = mid - 1
    
    optimal = max(1280, min(optimal, 1500))
    
    logger.info(f"Detected optimal MTU: {optimal} for {target_host}")
    return optimal

AWG_DEFAULTS = {
    'port': '55424',
    'mtu': '1280',
    'subnet_address': '10.8.1.0',
    'subnet_cidr': '24',
    'subnet_ip': '10.8.1.1',
    'dns1': '1.1.1.1',
    'dns2': '1.0.0.1',
    'junk_packet_count': '3',
    'junk_packet_min_size': '10',
    'junk_packet_max_size': '30',
    'init_packet_junk_size': '15',
    'response_packet_junk_size': '18',
    'cookie_reply_packet_junk_size': '20',
    'transport_packet_junk_size': '23',
    'init_packet_magic_header': '1020325451',
    'response_packet_magic_header': '3288052141',
    'transport_packet_magic_header': '2528465083',
    'underload_packet_magic_header': '1766607858',
}

CONTAINER_NAME = 'amnezia-awg2'
DOCKER_IMAGE = 'amneziavpn/amneziawg-go:latest'
CONFIG_PATH = '/opt/amnezia/awg/awg0.conf'
KEY_DIR = '/opt/amnezia/awg'
CLIENTS_TABLE_PATH = '/opt/amnezia/awg/clientsTable'
INTERFACE = 'awg0'


def generate_wg_keypair():
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return b64encode(private_bytes).decode(), b64encode(public_bytes).decode()


def generate_psk():
    return b64encode(secrets.token_bytes(32)).decode()


def generate_awg_params():
    jc = random.randint(1, 10)
    jmin = random.randint(5, 20)
    jmax = random.randint(jmin + 10, jmin + 50)
    s1 = random.randint(10, 50)
    s2 = random.randint(10, 50)
    s3 = random.randint(10, 50)
    s4 = random.randint(10, 50)
    h1 = str(random.randint(1000000000, 4294967295))
    h2 = str(random.randint(1000000000, 4294967295))
    h3 = str(random.randint(1000000000, 4294967295))
    h4 = str(random.randint(1000000000, 4294967295))
    return {
        'junk_packet_count': str(jc),
        'junk_packet_min_size': str(jmin),
        'junk_packet_max_size': str(jmax),
        'init_packet_junk_size': str(s1),
        'response_packet_junk_size': str(s2),
        'cookie_reply_packet_junk_size': str(s3),
        'transport_packet_junk_size': str(s4),
        'init_packet_magic_header': h1,
        'response_packet_magic_header': h2,
        'underload_packet_magic_header': h3,
        'transport_packet_magic_header': h4,
    }


class AWGManager:
    """Manages AmneziaWG 2.0 protocol installation and client management."""

    def __init__(self, ssh_manager):
        self.ssh = ssh_manager

    def check_docker_installed(self):
        out, err, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, _ = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || "
            "service docker status 2>/dev/null || "
            "(docker info >/dev/null 2>&1 && echo active)"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def install_docker(self):
        script = r"""
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
elif which zypper > /dev/null 2>&1; then pm=$(which zypper); silent_inst="-nq install"; check_pkgs="-nq refresh"; docker_pkg="docker"; dist="opensuse";
elif which pacman > /dev/null 2>&1; then pm=$(which pacman); silent_inst="-S --noconfirm --noprogressbar --quiet"; check_pkgs="-Sup"; docker_pkg="docker"; dist="archlinux";
else echo "Packet manager not found"; exit 1; fi;
echo "Dist: $dist, Packet manager: $pm";
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
"""
        out, err, code = self.ssh.run_sudo_script(script, timeout=180)
        if code != 0:
            raise RuntimeError(f"Failed to install Docker: {err}")
        return out

    def check_container_running(self):
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self):
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{CONTAINER_NAME}$ --format '{{{{.Names}}}}'"
        )
        return CONTAINER_NAME in out.strip().split('\n')

    def prepare_host(self):
        dockerfile_folder = f"/opt/amnezia/{CONTAINER_NAME}"
        script = f"""
mkdir -p {dockerfile_folder}
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net
fi
"""
        out, err, code = self.ssh.run_sudo_script(script)
        if code != 0:
            logger.warning(f"prepare_host warning: {err}")
        return True

    def setup_firewall(self):
        script = """
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -A FORWARD -j DOCKER-USER 2>/dev/null
"""
        self.ssh.run_sudo_script(script)
        return True

    def install_protocol(self, protocol_type=None, port=None, awg_params=None):
        if port is None:
            port = AWG_DEFAULTS['port']
        if awg_params is None:
            awg_params = generate_awg_params()

        results = []

        # Detect optimal MTU
        results.append("Detecting optimal MTU...")
        try:
            optimal_mtu = detect_optimal_mtu(self.ssh)
            results.append(f"Optimal MTU: {optimal_mtu}")
        except Exception as e:
            logger.warning(f"MTU detection failed, using default: {e}")
            optimal_mtu = int(AWG_DEFAULTS['mtu'])
            results.append(f"Using default MTU: {optimal_mtu}")

        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.install_docker()
            results.append("Docker installed successfully")
        else:
            results.append("Docker already installed")

        results.append("Preparing host...")
        self.prepare_host()
        results.append("Host prepared")

        if self.check_protocol_installed():
            results.append("Removing old container...")
            self.remove_container()
            results.append("Old container removed")

        results.append("Pulling Docker image...")
        dockerfile_folder = f"/opt/amnezia/{CONTAINER_NAME}"

        dockerfile_content = (
            f"FROM {DOCKER_IMAGE}\n"
            f"\n"
            f'LABEL maintainer="AmneziaVPN"\n'
            f"\n"
            f"RUN apk add --no-cache bash curl dumb-init iptables\n"
            f"RUN apk --update upgrade --no-cache\n"
            f"\n"
            f"RUN mkdir -p /opt/amnezia\n"
            f'RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && '
            f'echo "tail -f /dev/null" >> /opt/amnezia/start.sh\n'
            f"RUN chmod a+x /opt/amnezia/start.sh\n"
            f"\n"
            f'ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]\n'
        )
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")

        out, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache --pull -t {CONTAINER_NAME} {dockerfile_folder}",
            timeout=300
        )
        if code != 0:
            raise RuntimeError(f"Failed to build container: {err}")
        results.append("Docker image built successfully")

        results.append("Starting container...")
        run_cmd = f"""docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p {port}:{port}/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name {CONTAINER_NAME} \
{CONTAINER_NAME}"""

        out, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")

        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {CONTAINER_NAME}")

        results.append("Waiting for container to start...")
        self._wait_container_running()
        results.append("Container started")

        results.append("Configuring AWG...")
        self._configure_container(port, awg_params, optimal_mtu)
        results.append("AWG configured")

        results.append("Starting AWG service...")
        self._upload_start_script(port, awg_params)
        results.append("AWG service started")

        results.append("Setting up firewall...")
        self.setup_firewall()
        results.append("Firewall configured")

        return {
            'status': 'success',
            'protocol': 'awg2',
            'port': port,
            'awg_params': awg_params,
            'log': results,
        }

    def _wait_container_running(self, timeout=30):
        import time
        last_status = 'unknown'
        for i in range(timeout // 2):
            out, _, _ = self.ssh.run_sudo_command(
                f"docker inspect --format='{{{{.State.Status}}}}' {CONTAINER_NAME}"
            )
            last_status = out.strip().strip("'\"")
            if last_status == 'running':
                logger.info(f"Container {CONTAINER_NAME} is running")
                time.sleep(1)
                return True
            logger.info(f"Container {CONTAINER_NAME} status: {last_status}, waiting...")
            time.sleep(2)

        logs_out, _, _ = self.ssh.run_sudo_command(
            f"docker logs --tail 50 {CONTAINER_NAME} 2>&1"
        )
        raise RuntimeError(
            f"Container {CONTAINER_NAME} did not start within {timeout}s "
            f"(status: {last_status}). Logs:\n{logs_out}"
        )

    def _configure_container(self, port, awg_params, mtu=None):
        subnet_ip = AWG_DEFAULTS['subnet_ip']
        subnet_cidr = AWG_DEFAULTS['subnet_cidr']
        if mtu is None:
            mtu = int(AWG_DEFAULTS['mtu'])

        config_script = f"""
mkdir -p /opt/amnezia/awg
cd /opt/amnezia/awg
WIREGUARD_SERVER_PRIVATE_KEY=$(awg genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > /opt/amnezia/awg/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | awg pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > /opt/amnezia/awg/wireguard_server_public_key.key

WIREGUARD_PSK=$(awg genpsk)
echo $WIREGUARD_PSK > /opt/amnezia/awg/wireguard_psk.key

cat > {CONFIG_PATH} <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = {subnet_ip}/{subnet_cidr}
ListenPort = {port}
MTU = {mtu}
Jc = {awg_params['junk_packet_count']}
Jmin = {awg_params['junk_packet_min_size']}
Jmax = {awg_params['junk_packet_max_size']}
S1 = {awg_params['init_packet_junk_size']}
S2 = {awg_params['response_packet_junk_size']}
S3 = {awg_params['cookie_reply_packet_junk_size']}
S4 = {awg_params['transport_packet_junk_size']}
H1 = {awg_params['init_packet_magic_header']}
H2 = {awg_params['response_packet_magic_header']}
H3 = {awg_params['underload_packet_magic_header']}
H4 = {awg_params['transport_packet_magic_header']}
EOF
"""
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} bash -c '{config_script}'"
        )
        if code != 0:
            raise RuntimeError(f"Failed to configure container: {err}")

    def _upload_start_script(self, port, awg_params):
        subnet_ip = AWG_DEFAULTS['subnet_ip']
        subnet_cidr = AWG_DEFAULTS['subnet_cidr']

        start_script = f"""#!/bin/bash
echo "Container startup"

awg-quick down {CONFIG_PATH} 2>/dev/null

if [ -f {CONFIG_PATH} ]; then awg-quick up {CONFIG_PATH}; fi

IFACE=$(basename {CONFIG_PATH} .conf)
iptables -A INPUT -i $IFACE -j ACCEPT
iptables -A FORWARD -i $IFACE -j ACCEPT
iptables -A OUTPUT -o $IFACE -j ACCEPT

iptables -A FORWARD -i $IFACE -o eth0 -s {subnet_ip}/{subnet_cidr} -j ACCEPT
iptables -A FORWARD -i $IFACE -o eth1 -s {subnet_ip}/{subnet_cidr} -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s {subnet_ip}/{subnet_cidr} -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s {subnet_ip}/{subnet_cidr} -o eth1 -j MASQUERADE

tail -f /dev/null
"""
        self.ssh.upload_file(start_script, "/tmp/_amnz_start.sh")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_start.sh {CONTAINER_NAME}:/opt/amnezia/start.sh")
        self.ssh.run_sudo_command(f"docker exec {CONTAINER_NAME} chmod +x /opt/amnezia/start.sh")
        self.ssh.run_command("rm -f /tmp/_amnz_start.sh")

        self.ssh.run_sudo_command(f"docker restart {CONTAINER_NAME}")
        import time
        time.sleep(5)

    def remove_container(self):
        self.ssh.run_sudo_command(f"docker stop {CONTAINER_NAME}")
        self.ssh.run_sudo_command(f"docker rm -fv {CONTAINER_NAME}")
        self.ssh.run_sudo_command(f"docker rmi {CONTAINER_NAME}")
        return True

    def _get_clients_table(self):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} cat {CLIENTS_TABLE_PATH} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            return []

        try:
            data = json.loads(out)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                result = []
                for client_id, info in data.items():
                    result.append({
                        'clientId': client_id,
                        'userData': {
                            'clientName': info.get('clientName', 'Unknown'),
                        }
                    })
                return result
        except json.JSONDecodeError:
            return []

    def _save_clients_table(self, clients_table):
        content = json.dumps(clients_table, indent=2)
        self.ssh.upload_file(content, "/tmp/_amnz_clients.json")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_clients.json {CONTAINER_NAME}:{CLIENTS_TABLE_PATH}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_clients.json")

    def _get_server_config(self, protocol_type=None):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} cat {CONFIG_PATH}"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server config: {err}")
        return out

    def _get_mtu(self):
        """Extract MTU from server config."""
        config = self._get_server_config()
        for line in config.split('\n'):
            if line.strip().startswith('MTU'):
                return line.split('=', 1)[1].strip()
        return AWG_DEFAULTS['mtu']

    def save_server_config(self, protocol_type, config_content):
        self.ssh.upload_file(config_content.replace('\r\n', '\n'), "/tmp/_amnz_edit_config.conf")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_edit_config.conf {CONTAINER_NAME}:{CONFIG_PATH}")
        self.ssh.run_command("rm -f /tmp/_amnz_edit_config.conf")
        self.ssh.run_sudo_command(f"docker restart {CONTAINER_NAME}")

    def _get_server_public_key(self):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} cat /opt/amnezia/awg/wireguard_server_public_key.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server public key: {err}")
        return out.strip()

    def _get_server_psk(self):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} cat /opt/amnezia/awg/wireguard_psk.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get PSK: {err}")
        return out.strip()

    def _get_awg_params_from_config(self):
        config = self._get_server_config()
        params = {}
        param_map = {
            'ListenPort': 'port',
            'Jc': 'junk_packet_count',
            'Jmin': 'junk_packet_min_size',
            'Jmax': 'junk_packet_max_size',
            'S1': 'init_packet_junk_size',
            'S2': 'response_packet_junk_size',
            'S3': 'cookie_reply_packet_junk_size',
            'S4': 'transport_packet_junk_size',
            'H1': 'init_packet_magic_header',
            'H2': 'response_packet_magic_header',
            'H3': 'underload_packet_magic_header',
            'H4': 'transport_packet_magic_header',
            'I1': 'i1',
            'I2': 'i2',
            'I3': 'i3',
            'I4': 'i4',
            'I5': 'i5',
            'CPS': 'cps',
        }
        for line in config.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('#') and not line.startswith('['):
                parts = line.split('=', 1)
                key = parts[0].strip()
                val = parts[1].strip()
                if key in param_map:
                    params[param_map[key]] = val
        return params

    def _get_used_ips(self):
        config = self._get_server_config()
        ips = []
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('AllowedIPs'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
            elif line.startswith('Address'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
        return ips

    def _get_next_ip(self):
        used_ips = self._get_used_ips()
        if not used_ips:
            base = AWG_DEFAULTS['subnet_address']
            parts = base.split('.')
            parts[3] = '2'
            return '.'.join(parts)

        last_ip = used_ips[-1]
        parts = last_ip.split('.')
        last_octet = int(parts[3])

        if last_octet >= 254:
            next_octet = 2
        else:
            next_octet = last_octet + 1

        parts[3] = str(next_octet)
        return '.'.join(parts)

    def _parse_peers_from_config(self):
        try:
            config = self._get_server_config()
        except Exception:
            return {}
        peers = {}
        current_key = None
        for line in config.split('\n'):
            line = line.strip()
            if line == '[Peer]':
                current_key = None
            elif current_key is None and line.startswith('PublicKey'):
                current_key = line.split('=', 1)[1].strip()
                peers[current_key] = {'allowedIps': ''}
            elif current_key and line.startswith('AllowedIPs'):
                peers[current_key]['allowedIps'] = line.split('=', 1)[1].strip()
        return peers

    def get_clients(self, protocol_type=None):
        clients_table = self._get_clients_table()

        try:
            wg_show_data = self._wg_show()
        except Exception:
            wg_show_data = {}

        known_ids = set()
        for client in clients_table:
            client_id = client.get('clientId', '')
            known_ids.add(client_id)
            if client_id in wg_show_data:
                show_data = wg_show_data[client_id]
                user_data = client.get('userData', {})
                user_data['latestHandshake'] = show_data.get('latestHandshake', '')
                user_data['dataReceived'] = show_data.get('dataReceived', '')
                user_data['dataSent'] = show_data.get('dataSent', '')
                user_data['dataReceivedBytes'] = show_data.get('dataReceivedBytes', 0)
                user_data['dataSentBytes'] = show_data.get('dataSentBytes', 0)
                user_data['allowedIps'] = show_data.get('allowedIps', '')
                client['userData'] = user_data

        try:
            conf_peers = self._parse_peers_from_config()
            for pub_key, peer_info in conf_peers.items():
                if pub_key in known_ids:
                    continue
                show_data = wg_show_data.get(pub_key, {})
                allowed_ip = peer_info.get('allowedIps', '') or show_data.get('allowedIps', '')
                ip_part = ''
                if allowed_ip:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', allowed_ip)
                    if m:
                        ip_part = m.group(1)
                display_name = f'External ({ip_part})' if ip_part else 'External (native app)'
                clients_table.append({
                    'clientId': pub_key,
                    'userData': {
                        'clientName': display_name,
                        'clientPrivateKey': '',
                        'externalClient': True,
                        'clientIp': ip_part,
                        'latestHandshake': show_data.get('latestHandshake', ''),
                        'dataReceived': show_data.get('dataReceived', ''),
                        'dataSent': show_data.get('dataSent', ''),
                        'dataReceivedBytes': show_data.get('dataReceivedBytes', 0),
                        'dataSentBytes': show_data.get('dataSentBytes', 0),
                        'allowedIps': allowed_ip,
                    }
                })
        except Exception as e:
            logger.warning(f'get_clients: failed to parse conf peers: {e}')

        return clients_table

    def _parse_bytes(self, size_str):
        try:
            parts = size_str.strip().split()
            if len(parts) != 2:
                return 0
            val, unit = float(parts[0]), parts[1]
            units = {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3, 'TiB': 1024**4}
            return int(val * units.get(unit, 1))
        except Exception:
            return 0

    def _wg_show(self):
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} bash -c 'awg show all'"
        )
        if code != 0 or not out.strip():
            return {}

        result = {}
        current_peer = None

        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_peer = line.split(':', 1)[1].strip()
                result[current_peer] = {}
            elif current_peer and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key == 'latest handshake':
                    result[current_peer]['latestHandshake'] = value
                elif key == 'transfer':
                    parts = value.split(',')
                    if len(parts) == 2:
                        received = parts[0].strip().replace(' received', '')
                        sent = parts[1].strip().replace(' sent', '')
                        result[current_peer]['dataReceived'] = received
                        result[current_peer]['dataSent'] = sent
                        result[current_peer]['dataReceivedBytes'] = self._parse_bytes(received)
                        result[current_peer]['dataSentBytes'] = self._parse_bytes(sent)
                elif key == 'allowed ips':
                    result[current_peer]['allowedIps'] = value

        return result

    def add_client(self, protocol_type=None, client_name=None, server_host=None, port=None):
        client_priv_key, client_pub_key = generate_wg_keypair()
        server_pub_key = self._get_server_public_key()
        psk = self._get_server_psk()
        client_ip = self._get_next_ip()
        awg_params = self._get_awg_params_from_config()
        if awg_params.get('port'):
            port = awg_params['port']

        peer_section = f"""
[Peer]
PublicKey = {client_pub_key}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32

"""
        escaped_peer = peer_section.replace("'", "'\\''")
        self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} bash -c 'echo \"{escaped_peer}\" >> {CONFIG_PATH}'"
        )

        self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} bash -c 'awg syncconf {INTERFACE} <(awg-quick strip {CONFIG_PATH})'"
        )

        clients_table = self._get_clients_table()
        new_client = {
            'clientId': client_pub_key,
            'userData': {
                'clientName': client_name,
                'creationDate': __import__('datetime').datetime.now().isoformat(),
                'clientPrivateKey': client_priv_key,
                'clientIp': client_ip,
                'psk': psk,
                'enabled': True,
            }
        }
        clients_table.append(new_client)
        self._save_clients_table(clients_table)

        awg_params = self._get_awg_params_from_config()
        if awg_params.get('port'):
            port = awg_params['port']

        dns1 = AWG_DEFAULTS['dns1']
        dns2 = AWG_DEFAULTS['dns2']

        out, _, _ = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
        if 'amnezia-dns' in out:
            dns1 = '172.29.172.254'

        mtu = self._get_mtu()

        config_lines = [
            f"Address = {client_ip}/32",
            f"DNS = {dns1}, {dns2}",
            f"PrivateKey = {client_priv_key}",
            f"MTU = {mtu}"
        ]

        mapping = [
            ('junk_packet_count', 'Jc'),
            ('junk_packet_min_size', 'Jmin'),
            ('junk_packet_max_size', 'Jmax'),
            ('init_packet_junk_size', 'S1'),
            ('response_packet_junk_size', 'S2'),
            ('cookie_reply_packet_junk_size', 'S3'),
            ('transport_packet_junk_size', 'S4'),
            ('init_packet_magic_header', 'H1'),
            ('response_packet_magic_header', 'H2'),
            ('underload_packet_magic_header', 'H3'),
            ('transport_packet_magic_header', 'H4'),
            ('i1', 'I1'),
            ('i2', 'I2'),
            ('i3', 'I3'),
            ('i4', 'I4'),
            ('i5', 'I5'),
            ('cps', 'CPS')
        ]

        for param_key, config_key in mapping:
            val = awg_params.get(param_key)
            if val:
                config_lines.append(f"{config_key} = {val}")

        client_config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""

        return {
            'client_name': client_name,
            'client_id': client_pub_key,
            'client_ip': client_ip,
            'config': client_config,
        }

    def get_client_config(self, protocol_type=None, client_id=None, server_host=None, port=None):
        clients_table = self._get_clients_table()
        client = None
        for c in clients_table:
            if c.get('clientId') == client_id:
                client = c
                break

        if not client:
            raise RuntimeError(f"Client {client_id} not found")

        ud = client.get('userData', {})
        client_priv_key = ud.get('clientPrivateKey', '')
        client_ip = ud.get('clientIp', '')
        psk = ud.get('psk', '')

        if not client_priv_key:
            raise RuntimeError("Client private key not stored. Config cannot be reconstructed.")

        server_pub_key = self._get_server_public_key()
        if not psk:
            psk = self._get_server_psk()

        awg_params = self._get_awg_params_from_config()
        if awg_params.get('port'):
            port = awg_params['port']

        dns1 = AWG_DEFAULTS['dns1']
        dns2 = AWG_DEFAULTS['dns2']

        out, _, _ = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
        if 'amnezia-dns' in out:
            dns1 = '172.29.172.254'

        mtu = self._get_mtu()

        config_lines = [
            f"Address = {client_ip}/32",
            f"DNS = {dns1}, {dns2}",
            f"PrivateKey = {client_priv_key}",
            f"MTU = {mtu}"
        ]

        mapping = [
            ('junk_packet_count', 'Jc'),
            ('junk_packet_min_size', 'Jmin'),
            ('junk_packet_max_size', 'Jmax'),
            ('init_packet_junk_size', 'S1'),
            ('response_packet_junk_size', 'S2'),
            ('cookie_reply_packet_junk_size', 'S3'),
            ('transport_packet_junk_size', 'S4'),
            ('init_packet_magic_header', 'H1'),
            ('response_packet_magic_header', 'H2'),
            ('underload_packet_magic_header', 'H3'),
            ('transport_packet_magic_header', 'H4'),
            ('i1', 'I1'),
            ('i2', 'I2'),
            ('i3', 'I3'),
            ('i4', 'I4'),
            ('i5', 'I5'),
            ('cps', 'CPS')
        ]

        for param_key, config_key in mapping:
            val = awg_params.get(param_key)
            if val:
                config_lines.append(f"{config_key} = {val}")

        config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""
        return config

    def toggle_client(self, protocol_type=None, client_id=None, enable=True):
        if enable:
            clients_table = self._get_clients_table()
            client = None
            for c in clients_table:
                if c.get('clientId') == client_id:
                    client = c
                    break
            if not client:
                raise RuntimeError(f"Client {client_id} not found")

            ud = client.get('userData', {})
            psk = ud.get('psk', '')
            client_ip = ud.get('clientIp', '')

            if not psk:
                psk = self._get_server_psk()

            peer_section = f"""
[Peer]
PublicKey = {client_id}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32

"""
            escaped_peer = peer_section.replace("'", "'\\''")
            self.ssh.run_sudo_command(
                f"docker exec -i {CONTAINER_NAME} bash -c 'echo \"{escaped_peer}\" >> {CONFIG_PATH}'"
            )
        else:
            config = self._get_server_config()
            sections = config.split('[')
            new_sections = []
            for section in sections:
                if not section.strip():
                    continue
                if client_id in section:
                    continue
                new_sections.append(section)

            new_config = '[' + '['.join(new_sections)
            self.ssh.upload_file(new_config, "/tmp/_amnz_config.conf")
            self.ssh.run_sudo_command(
                f"docker cp /tmp/_amnz_config.conf {CONTAINER_NAME}:{CONFIG_PATH}"
            )
            self.ssh.run_command("rm -f /tmp/_amnz_config.conf")

        self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} bash -c 'awg syncconf {INTERFACE} <(awg-quick strip {CONFIG_PATH})'"
        )

        clients_table = self._get_clients_table()
        for c in clients_table:
            if c.get('clientId') == client_id:
                c.setdefault('userData', {})['enabled'] = enable
                break
        self._save_clients_table(clients_table)

    def remove_client(self, protocol_type=None, client_id=None):
        config = self._get_server_config()
        sections = config.split('[')
        new_sections = []
        for section in sections:
            if not section.strip():
                continue
            if client_id in section:
                continue
            new_sections.append(section)

        new_config = '[' + '['.join(new_sections)

        self.ssh.upload_file(new_config, "/tmp/_amnz_config.conf")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_config.conf {CONTAINER_NAME}:{CONFIG_PATH}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_config.conf")

        self.ssh.run_sudo_command(
            f"docker exec -i {CONTAINER_NAME} bash -c 'awg syncconf {INTERFACE} <(awg-quick strip {CONFIG_PATH})'"
        )

        clients_table = self._get_clients_table()
        clients_table = [c for c in clients_table if c.get('clientId') != client_id]
        self._save_clients_table(clients_table)

        return True

    def get_server_status(self, protocol_type=None):
        info = {
            'container_exists': self.check_protocol_installed(),
            'container_running': False,
            'protocol': 'awg2',
        }

        if info['container_exists']:
            info['container_running'] = self.check_container_running()

            if info['container_running']:
                try:
                    config = self._get_server_config()
                    for line in config.split('\n'):
                        if 'ListenPort' in line:
                            info['port'] = line.split('=')[1].strip()
                            break
                    info['awg_params'] = self._get_awg_params_from_config()
                    info['clients_count'] = len(self._get_clients_table())
                except Exception as e:
                    info['error'] = str(e)

        return info
