package managers

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHManager struct {
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string

	client     *ssh.Client
	sftpClient *sftp.Client
	isRoot     bool
}

var (
	knownHostsPath = "known_hosts"
	knownHostsMu   sync.Mutex
)

func getKnownHostsCallback() ssh.HostKeyCallback {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		os.WriteFile(knownHostsPath, []byte{}, 0600)
	}

	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		log.Printf("Warning: failed to load known_hosts: %v", err)
		return ssh.InsecureIgnoreHostKey()
	}
	return callback
}

func SaveKnownHost(host string, port int, key ssh.PublicKey) error {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()

	addr := fmt.Sprintf("%s:%d", host, port)
	entry := knownhosts.Line([]string{addr}, key)

	khDB, _ := os.ReadFile(knownHostsPath)
	khDB = append(khDB, []byte(entry)...)
	khDB = append(khDB, '\n')

	return os.WriteFile(knownHostsPath, khDB, 0600)
}

func NewSSHManager(host string, port int, username, password, privateKey string) *SSHManager {
	return &SSHManager{
		Host:       host,
		Port:       port,
		Username:   username,
		Password:   password,
		PrivateKey: privateKey,
		isRoot:     username == "root",
	}
}

func (m *SSHManager) Connect() error {
	var authMethods []ssh.AuthMethod

	if m.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(m.PrivateKey))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else if m.Password != "" {
		authMethods = append(authMethods, ssh.Password(m.Password))
	}

	hostKeyCB := m.buildHostKeyCallback()

	config := &ssh.ClientConfig{
		User:            m.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCB,
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", m.Host, m.Port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to dial: %w", err)
	}
	m.client = client

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return fmt.Errorf("failed to create sftp client: %w", err)
	}
	m.sftpClient = sftpClient

	return nil
}

func (m *SSHManager) buildHostKeyCallback() ssh.HostKeyCallback {
	knownCallback := getKnownHostsCallback()

	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := knownCallback(host, remote, key)
		if err == nil {
			return nil
		}

		var khErr *knownhosts.KeyError
		if errors.As(err, &khErr) && len(khErr.Want) == 0 {
			if saveErr := SaveKnownHost(m.Host, m.Port, key); saveErr != nil {
				log.Printf("Warning: failed to save host key: %v", saveErr)
			}
			return nil
		}

		return err
	}
}

func (m *SSHManager) Disconnect() {
	if m.sftpClient != nil {
		m.sftpClient.Close()
	}
	if m.client != nil {
		m.client.Close()
	}
}

func (m *SSHManager) RunCommand(command string) (string, string, int) {
	if m.client == nil {
		return "", "Not connected", -1
	}

	session, err := m.client.NewSession()
	if err != nil {
		return "", err.Error(), -1
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	err = session.Run(command)
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*ssh.ExitError); ok {
			exitCode = exitError.ExitStatus()
		} else {
			exitCode = -1
		}
	}

	return strings.TrimSpace(stdoutBuf.String()), strings.TrimSpace(stderrBuf.String()), exitCode
}

func (m *SSHManager) TestConnection() map[string]interface{} {
	info := make(map[string]interface{})
	out, _, code := m.RunCommand("uname -a")
	if code == 0 {
		info["os"] = strings.TrimSpace(out)
	}
	return info
}

func (m *SSHManager) RunSudoCommand(command string) (string, string, int) {
	cleanCmd := strings.TrimPrefix(strings.TrimSpace(command), "sudo ")

	if m.isRoot {
		return m.RunCommand(cleanCmd)
	}

	if m.Password != "" {
		return m.runWithSudoPassword(cleanCmd)
	}

	fullCmd := fmt.Sprintf("sudo %s", cleanCmd)
	return m.RunCommand(fullCmd)
}

func (m *SSHManager) runWithSudoPassword(command string) (string, string, int) {
	if m.client == nil {
		return "", "Not connected", -1
	}

	session, err := m.client.NewSession()
	if err != nil {
		return "", err.Error(), -1
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err.Error(), -1
	}

	go func() {
		defer stdin.Close()
		fmt.Fprintf(stdin, "%s\n", m.Password)
	}()

	err = session.Run(fmt.Sprintf("sudo -S -p '' %s", command))
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*ssh.ExitError); ok {
			exitCode = exitError.ExitStatus()
		} else {
			exitCode = -1
		}
	}

	return strings.TrimSpace(stdoutBuf.String()), strings.TrimSpace(stderrBuf.String()), exitCode
}

func (m *SSHManager) RunSudoScript(script string) (string, string, int) {
	if m.isRoot {
		return m.RunCommand(script)
	}

	scriptHash := fmt.Sprintf("%x", md5.Sum([]byte(script)))[:8]
	tmpScript := fmt.Sprintf("/tmp/_amnz_script_%s.sh", scriptHash)

	if err := m.UploadFile(script, tmpScript); err != nil {
		return "", err.Error(), -1
	}

	if m.Password != "" {
		return m.runWithSudoPassword(fmt.Sprintf("bash %s; rm -f %s", tmpScript, tmpScript))
	}

	fullCmd := fmt.Sprintf("sudo bash %s; rm -f %s", tmpScript, tmpScript)
	return m.RunCommand(fullCmd)
}

func (m *SSHManager) UploadFile(content, remotePath string) error {
	if m.sftpClient == nil {
		return fmt.Errorf("not connected to server")
	}

	content = strings.ReplaceAll(content, "\r\n", "\n")

	f, err := m.sftpClient.Create(remotePath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte(content))
	return err
}

func (m *SSHManager) UploadFileSudo(content, remotePath string) error {
	content = strings.ReplaceAll(content, "\r\n", "\n")

	hash := fmt.Sprintf("%x", md5.Sum([]byte(remotePath)))[:8]
	tmpName := fmt.Sprintf("/tmp/_amnz_%s", hash)

	if err := m.UploadFile(content, tmpName); err != nil {
		return err
	}

	if _, _, code := m.RunSudoCommand(fmt.Sprintf("mv %s %s", tmpName, remotePath)); code != 0 {
		return fmt.Errorf("failed to move file to %s", remotePath)
	}
	if _, _, code := m.RunSudoCommand(fmt.Sprintf("chmod 644 %s", remotePath)); code != 0 {
		return fmt.Errorf("failed to chmod %s", remotePath)
	}

	return nil
}

func (m *SSHManager) DownloadFile(remotePath string) (string, error) {
	if m.sftpClient == nil {
		return "", fmt.Errorf("not connected to server")
	}

	f, err := m.sftpClient.Open(remotePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(f)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (m *SSHManager) FileExists(remotePath string) bool {
	if m.sftpClient == nil {
		return false
	}
	_, err := m.sftpClient.Stat(remotePath)
	return err == nil
}
