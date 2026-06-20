package bot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/database"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/managers"
	"github.com/PRVTPRO/Amnezia-Web-Panel/internal/models"
	tele "gopkg.in/telebot.v3"
)

func generateVpnLink(config string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(config))
	return fmt.Sprintf("vpn://%s", b64)
}

func findUser(tgID string) (*models.UserConnectionData, string) {
	tgIDClean := strings.TrimPrefix(tgID, "@")
	users, _ := database.Query.GetUsers(context.Background())
	for _, u := range users {
		var ud map[string]interface{}
		json.Unmarshal([]byte(u.Data), &ud)
		stored := ""
		if t, ok := ud["telegramId"].(string); ok {
			stored = strings.TrimPrefix(t, "@")
		}
		if stored != "" && stored == tgIDClean {
			return nil, u.ID // just returning user ID
		}
	}
	return nil, ""
}

func buildConnectionsKeyboard(userID string) (*tele.ReplyMarkup, error) {
	conns, _ := database.Query.GetUserConnections(context.Background(), userID)
	servers, _ := database.Query.GetServers(context.Background())
	serverMap := make(map[int64]models.ServerData)
	for _, s := range servers {
		var sd models.ServerData
		json.Unmarshal([]byte(s.Data), &sd)
		serverMap[s.ID] = sd
	}

	menu := &tele.ReplyMarkup{}
	var rows []tele.Row

	for _, cStr := range conns {
		var c models.UserConnectionData
		json.Unmarshal([]byte(cStr), &c)
		serverName := "Unknown"
		if s, ok := serverMap[c.ServerID]; ok {
			if s.Name != "" {
				serverName = s.Name
			} else {
				serverName = s.Host
			}
		}
		label := fmt.Sprintf("🔐 %s · %s · %s", c.Name, strings.ToUpper(c.Protocol), serverName)
		btn := menu.Data(label, "cfg", c.ID)
		rows = append(rows, menu.Row(btn))
	}
	refreshBtn := menu.Data("🔄 Обновить список", "refresh")
	rows = append(rows, menu.Row(refreshBtn))
	menu.Inline(rows...)
	return menu, nil
}

func handleStart(c tele.Context) error {
	tgID := strconv.FormatInt(c.Sender().ID, 10)
	_, userID := findUser(tgID)

	if userID == "" {
		return c.Send(fmt.Sprintf("👋 Hi, <b>%s</b>!\n\nYour Telegram account is not linked to any panel user.\nPlease contact your administrator — they need to add your Telegram ID to your profile.\n\nYour Telegram ID: <code>%s</code>", c.Sender().FirstName, tgID), tele.ModeHTML)
	}

	users, _ := database.Query.GetUsers(context.Background())
	username := "User"
	for _, u := range users {
		if u.ID == userID {
			var ud map[string]interface{}
			json.Unmarshal([]byte(u.Data), &ud)
			username, _ = ud["username"].(string)
		}
	}

	conns, _ := database.Query.GetUserConnections(context.Background(), userID)
	if len(conns) == 0 {
		return c.Send(fmt.Sprintf("👋 Hi, <b>%s</b>!\n\nYou are registered as <b>%s</b>.\n\nYou have no connections yet. Please contact your administrator.", c.Sender().FirstName, username), tele.ModeHTML)
	}

	menu, _ := buildConnectionsKeyboard(userID)
	return c.Send(fmt.Sprintf("👋 Hi, <b>%s</b>!\n\nYou are registered as <b>%s</b>.\n\n<b>Your connections</b> (%d) — tap to get config:", c.Sender().FirstName, username, len(conns)), menu, tele.ModeHTML)
}

func handleCallback(c tele.Context) error {
	data := c.Callback().Data
	data = strings.TrimSpace(data)

	tgID := strconv.FormatInt(c.Sender().ID, 10)
	_, userID := findUser(tgID)
	if userID == "" {
		c.Respond(&tele.CallbackResponse{Text: "Access denied"})
		return nil
	}

	if data == "refresh" || data == "\frefresh" {
		c.Respond(&tele.CallbackResponse{Text: "Updated!"})
		conns, _ := database.Query.GetUserConnections(context.Background(), userID)
		if len(conns) == 0 {
			c.Edit("You have no connections.")
			return nil
		}
		menu, _ := buildConnectionsKeyboard(userID)
		c.Edit(fmt.Sprintf("<b>Your connections</b> (%d) — tap to get config:", len(conns)), menu, tele.ModeHTML)
		return nil
	}

	if strings.HasPrefix(data, "cfg|") || strings.HasPrefix(data, "\fcfg|") {
		connID := strings.TrimPrefix(data, "cfg|")
		connID = strings.TrimPrefix(connID, "\fcfg|")
		c.Respond(&tele.CallbackResponse{Text: "Fetching config..."})

		// Find connection
		var conn models.UserConnectionData
		conns, _ := database.Query.GetUserConnections(context.Background(), userID)
		found := false
		for _, cStr := range conns {
			json.Unmarshal([]byte(cStr), &conn)
			if conn.ID == connID {
				found = true
				break
			}
		}

		if !found {
			c.Send("❌ Connection not found.")
			return nil
		}

		msg, _ := c.Bot().Send(c.Sender(), fmt.Sprintf("⏳ Fetching config for <b>%s</b>...", conn.Name), tele.ModeHTML)

		dataStr, err := database.Query.GetServer(context.Background(), conn.ServerID)
		if err != nil {
			c.Bot().Edit(msg, "❌ Server not found.")
			return nil
		}
		var serverData models.ServerData
		json.Unmarshal([]byte(dataStr), &serverData)

		ssh := managers.NewSSHManager(serverData.Host, serverData.SSHPort, serverData.Username, serverData.Password, serverData.PrivateKey)
		ssh.Connect()
		defer ssh.Disconnect()

		var config string
		switch conn.Protocol {
		case "wireguard":
			config = managers.NewWireGuardManager(ssh).GetClientConfig(conn.ClientID, serverData.Host)
		case "telemt":
			port := "443"
			if p, ok := serverData.Protocols["telemt"].(map[string]interface{}); ok {
				if pt, ok2 := p["port"].(string); ok2 {
					port = pt
				}
			}
			config = managers.NewTelemtManager(ssh).GetClientConfig(conn.ClientID, serverData.Host, port)
		case "awg2":
			port := "55424"
			if p, ok := serverData.Protocols["awg2"].(map[string]interface{}); ok {
				if pt, ok2 := p["port"].(string); ok2 {
					port = pt
				}
			}
			config = managers.NewAWGManager(ssh).GetClientConfig(conn.Protocol, conn.ClientID, serverData.Host, port)
		}

		c.Bot().Delete(msg)

		if config == "" || config == "Not found" {
			c.Send("❌ Failed to retrieve configuration.")
			return nil
		}

		serverName := serverData.Name
		if serverName == "" {
			serverName = serverData.Host
		}

		c.Send(fmt.Sprintf("✅ <b>%s</b>\n🌐 Server: <b>%s</b>\n🔌 Protocol: <b>%s</b>", conn.Name, serverName, strings.ToUpper(conn.Protocol)), tele.ModeHTML)

		if conn.Protocol == "telemt" || conn.Protocol == "xray" {
			c.Send(fmt.Sprintf("🔗 <b>Connection link</b> (tap to copy):\n<code>%s</code>", config), tele.ModeHTML)
		} else {
			if len(config) <= 4000 {
				c.Send(fmt.Sprintf("<b>📄 Configuration:</b>\n<pre>%s</pre>", config), tele.ModeHTML)
			} else {
				c.Send("<b>📄 Configuration:</b> (too long to display inline)", tele.ModeHTML)
			}

			vpnLink := generateVpnLink(config)
			c.Send(fmt.Sprintf("🔗 <b>VPN Link</b> (tap to copy):\n<code>%s</code>", vpnLink), tele.ModeHTML)

			// Send config as file
			f, _ := os.CreateTemp("", "*.conf")
			f.WriteString(config)
			f.Close()
			defer os.Remove(f.Name())

			doc := &tele.Document{File: tele.FromDisk(f.Name()), FileName: fmt.Sprintf("%s.conf", strings.ReplaceAll(conn.Name, " ", "_"))}
			doc.Caption = fmt.Sprintf("📁 Config file: %s", conn.Name)
			c.Send(doc)
		}

		return nil
	}

	return nil
}

func Start() {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		cfgStr, err := database.Query.GetSetting(context.Background(), "telegram")
		if err == nil {
			var cfg map[string]interface{}
			if json.Unmarshal([]byte(cfgStr), &cfg) == nil {
				if t, ok := cfg["token"].(string); ok && t != "" {
					token = t
				}
			}
		}
	}
	if token == "" {
		log.Println("Telegram bot token not found, bot will not start")
		return
	}

	pref := tele.Settings{
		Token:  token,
		Poller: &tele.LongPoller{Timeout: 10 * time.Second},
	}

	b, err := tele.NewBot(pref)
	if err != nil {
		log.Println("Failed to start bot:", err)
		return
	}

	b.Handle("/start", handleStart)
	b.Handle("/connections", handleStart)
	b.Handle(tele.OnCallback, handleCallback)

	go b.Start()
	log.Println("Telegram bot started")
}
