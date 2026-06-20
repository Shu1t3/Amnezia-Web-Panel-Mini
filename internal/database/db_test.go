package database

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	if err := InitDB(dbPath); err != nil {
		t.Fatalf("failed to init test DB: %v", err)
	}

	t.Cleanup(func() {
		CloseDB()
		os.Remove(dbPath)
	})
}

func TestInitDB(t *testing.T) {
	setupTestDB(t)

	if DB == nil {
		t.Fatal("DB should be initialized")
	}
	if Query == nil {
		t.Fatal("Query should be initialized")
	}

	if err := DB.Ping(); err != nil {
		t.Fatalf("DB should be pingable: %v", err)
	}
}

func TestCloseDB(t *testing.T) {
	setupTestDB(t)
	CloseDB()

	if err := DB.Ping(); err == nil {
		t.Error("DB should not be pingable after close")
	}
}

func TestSetSetting(t *testing.T) {
	setupTestDB(t)

	err := Query.SetSetting(context.Background(), SetSettingParams{
		Key:   "test_key",
		Value: "test_value",
	})
	if err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}
}

func TestGetSetting(t *testing.T) {
	setupTestDB(t)

	Query.SetSetting(context.Background(), SetSettingParams{
		Key:   "my_key",
		Value: "my_value",
	})

	val, err := Query.GetSetting(context.Background(), "my_key")
	if err != nil {
		t.Fatalf("GetSetting failed: %v", err)
	}
	if val != "my_value" {
		t.Errorf("expected 'my_value', got '%s'", val)
	}
}

func TestGetSetting_NotFound(t *testing.T) {
	setupTestDB(t)

	_, err := Query.GetSetting(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestSetSetting_Overwrite(t *testing.T) {
	setupTestDB(t)

	Query.SetSetting(context.Background(), SetSettingParams{Key: "k", Value: "v1"})
	Query.SetSetting(context.Background(), SetSettingParams{Key: "k", Value: "v2"})

	val, _ := Query.GetSetting(context.Background(), "k")
	if val != "v2" {
		t.Errorf("expected 'v2' after overwrite, got '%s'", val)
	}
}

func TestGetAllSettings(t *testing.T) {
	setupTestDB(t)

	Query.SetSetting(context.Background(), SetSettingParams{Key: "a", Value: "1"})
	Query.SetSetting(context.Background(), SetSettingParams{Key: "b", Value: "2"})

	kvs, err := Query.GetAllSettings(context.Background())
	if err != nil {
		t.Fatalf("GetAllSettings failed: %v", err)
	}
	if len(kvs) < 2 {
		t.Errorf("expected at least 2 settings, got %d", len(kvs))
	}
}

func TestAddServer(t *testing.T) {
	setupTestDB(t)

	serverData := map[string]interface{}{
		"name":     "Test Server",
		"host":     "192.168.1.1",
		"ssh_port": 22,
		"username": "root",
	}
	dataBytes, _ := json.Marshal(serverData)

	id, err := Query.AddServer(context.Background(), string(dataBytes))
	if err != nil {
		t.Fatalf("AddServer failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive server ID, got %d", id)
	}
}

func TestGetServer(t *testing.T) {
	setupTestDB(t)

	serverData := `{"name":"My Server","host":"10.0.0.1"}`
	id, _ := Query.AddServer(context.Background(), serverData)

	got, err := Query.GetServer(context.Background(), id)
	if err != nil {
		t.Fatalf("GetServer failed: %v", err)
	}
	if got != serverData {
		t.Errorf("expected %s, got %s", serverData, got)
	}
}

func TestGetServer_NotFound(t *testing.T) {
	setupTestDB(t)

	_, err := Query.GetServer(context.Background(), 99999)
	if err == nil {
		t.Error("expected error for nonexistent server")
	}
}

func TestUpdateServer(t *testing.T) {
	setupTestDB(t)

	id, _ := Query.AddServer(context.Background(), `{"name":"old"}`)

	newData := `{"name":"new"}`
	err := Query.UpdateServer(context.Background(), UpdateServerParams{
		Data: newData,
		ID:   id,
	})
	if err != nil {
		t.Fatalf("UpdateServer failed: %v", err)
	}

	got, _ := Query.GetServer(context.Background(), id)
	if got != newData {
		t.Errorf("expected %s, got %s", newData, got)
	}
}

func TestDeleteServer(t *testing.T) {
	setupTestDB(t)

	id, _ := Query.AddServer(context.Background(), `{"name":"to_delete"}`)

	err := Query.DeleteServer(context.Background(), id)
	if err != nil {
		t.Fatalf("DeleteServer failed: %v", err)
	}

	_, err = Query.GetServer(context.Background(), id)
	if err == nil {
		t.Error("expected error after deleting server")
	}
}

func TestGetServers(t *testing.T) {
	setupTestDB(t)

	Query.AddServer(context.Background(), `{"name":"s1"}`)
	Query.AddServer(context.Background(), `{"name":"s2"}`)

	servers, err := Query.GetServers(context.Background())
	if err != nil {
		t.Fatalf("GetServers failed: %v", err)
	}
	if len(servers) < 2 {
		t.Errorf("expected at least 2 servers, got %d", len(servers))
	}
}

func TestAddUser(t *testing.T) {
	setupTestDB(t)

	userData := `{"username":"admin","role":"admin"}`
	err := Query.AddUser(context.Background(), AddUserParams{
		ID:   "user-1",
		Data: userData,
	})
	if err != nil {
		t.Fatalf("AddUser failed: %v", err)
	}
}

func TestGetUser(t *testing.T) {
	setupTestDB(t)

	userData := `{"username":"testuser"}`
	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: userData})

	got, err := Query.GetUser(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if got != userData {
		t.Errorf("expected %s, got %s", userData, got)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	setupTestDB(t)

	_, err := Query.GetUser(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
}

func TestUpdateUser(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{"name":"old"}`})

	newData := `{"name":"new"}`
	err := Query.UpdateUser(context.Background(), UpdateUserParams{
		Data: newData,
		ID:   "u1",
	})
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	got, _ := Query.GetUser(context.Background(), "u1")
	if got != newData {
		t.Errorf("expected %s, got %s", newData, got)
	}
}

func TestDeleteUser(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})

	err := Query.DeleteUser(context.Background(), "u1")
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	_, err = Query.GetUser(context.Background(), "u1")
	if err == nil {
		t.Error("expected error after deleting user")
	}
}

func TestGetUsers(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{"username":"a"}`})
	Query.AddUser(context.Background(), AddUserParams{ID: "u2", Data: `{"username":"b"}`})

	users, err := Query.GetUsers(context.Background())
	if err != nil {
		t.Fatalf("GetUsers failed: %v", err)
	}
	if len(users) < 2 {
		t.Errorf("expected at least 2 users, got %d", len(users))
	}
}

func TestGetUserByUsername(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{
		ID:   "u1",
		Data: `{"username":"findme","password_hash":"abc"}`,
	})

	got, err := Query.GetUserByUsername(context.Background(), "findme")
	if err != nil {
		t.Fatalf("GetUserByUsername failed: %v", err)
	}

	var ud map[string]interface{}
	json.Unmarshal([]byte(got), &ud)
	if ud["username"] != "findme" {
		t.Errorf("expected username 'findme', got '%v'", ud["username"])
	}
}

func TestGetUserByUsername_NotFound(t *testing.T) {
	setupTestDB(t)

	_, err := Query.GetUserByUsername(context.Background(), "nobody")
	if err == nil {
		t.Error("expected error for nonexistent username")
	}
}

func TestHasUsers(t *testing.T) {
	setupTestDB(t)

	count, _ := Query.HasUsers(context.Background())
	if count != 0 {
		t.Errorf("expected 0 users initially, got %d", count)
	}

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	count, _ = Query.HasUsers(context.Background())
	if count != 1 {
		t.Errorf("expected 1 user, got %d", count)
	}
}

func TestAddConnection(t *testing.T) {
	setupTestDB(t)

	connData := `{"user_id":"u1","server_id":1,"protocol":"wireguard"}`
	err := Query.AddConnection(context.Background(), AddConnectionParams{
		ID:       "conn-1",
		UserID:   "u1",
		ServerID: 1,
		Protocol: "wireguard",
		ClientID: "client-key-1",
		Data:     connData,
	})
	if err != nil {
		t.Fatalf("AddConnection failed: %v", err)
	}
}

func TestGetUserConnections(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{}`,
	})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c2", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k2", Data: `{}`,
	})

	conns, err := Query.GetUserConnections(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GetUserConnections failed: %v", err)
	}
	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
}

func TestDeleteConnection(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{}`,
	})

	err := Query.DeleteConnection(context.Background(), "c1")
	if err != nil {
		t.Fatalf("DeleteConnection failed: %v", err)
	}

	conns, _ := Query.GetUserConnections(context.Background(), "u1")
	if len(conns) != 0 {
		t.Errorf("expected 0 connections after delete, got %d", len(conns))
	}
}

func TestDeleteUserConnections(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{}`,
	})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c2", UserID: "u1", ServerID: 2, Protocol: "wg", ClientID: "k2", Data: `{}`,
	})

	err := Query.DeleteUserConnections(context.Background(), "u1")
	if err != nil {
		t.Fatalf("DeleteUserConnections failed: %v", err)
	}

	conns, _ := Query.GetUserConnections(context.Background(), "u1")
	if len(conns) != 0 {
		t.Errorf("expected 0 connections after delete, got %d", len(conns))
	}
}

func TestDeleteServerConnections(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{}`,
	})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c2", UserID: "u1", ServerID: 2, Protocol: "wg", ClientID: "k2", Data: `{}`,
	})

	err := Query.DeleteServerConnections(context.Background(), 1)
	if err != nil {
		t.Fatalf("DeleteServerConnections failed: %v", err)
	}

	conns1, _ := Query.GetServerConnections(context.Background(), 1)
	conns2, _ := Query.GetServerConnections(context.Background(), 2)

	if len(conns1) != 0 {
		t.Errorf("expected 0 connections for server 1, got %d", len(conns1))
	}
	if len(conns2) != 1 {
		t.Errorf("expected 1 connection for server 2, got %d", len(conns2))
	}
}

func TestGetServerConnections(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{}`,
	})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c2", UserID: "u1", ServerID: 1, Protocol: "awg", ClientID: "k2", Data: `{}`,
	})

	conns, err := Query.GetServerConnections(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetServerConnections failed: %v", err)
	}
	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
}

func TestGetServerConnectionsByProtocol(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{}`,
	})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c2", UserID: "u1", ServerID: 1, Protocol: "awg", ClientID: "k2", Data: `{}`,
	})

	conns, err := Query.GetServerConnectionsByProtocol(context.Background(), GetServerConnectionsByProtocolParams{
		ServerID: 1,
		Protocol: "wg",
	})
	if err != nil {
		t.Fatalf("GetServerConnectionsByProtocol failed: %v", err)
	}
	if len(conns) != 1 {
		t.Errorf("expected 1 wg connection, got %d", len(conns))
	}
}

func TestGetConnectionByClient(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "mykey", Data: `{"name":"test"}`,
	})

	data, err := Query.GetConnectionByClient(context.Background(), GetConnectionByClientParams{
		ServerID: 1,
		Protocol: "wg",
		ClientID: "mykey",
	})
	if err != nil {
		t.Fatalf("GetConnectionByClient failed: %v", err)
	}
	if data != `{"name":"test"}` {
		t.Errorf("unexpected data: %s", data)
	}
}

func TestUpdateConnection(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{"old":"data"}`,
	})

	err := Query.UpdateConnection(context.Background(), UpdateConnectionParams{
		Data: `{"new":"data"}`,
		ID:   "c1",
	})
	if err != nil {
		t.Fatalf("UpdateConnection failed: %v", err)
	}

	conns, _ := Query.GetUserConnections(context.Background(), "u1")
	if len(conns) != 1 || conns[0] != `{"new":"data"}` {
		t.Errorf("connection not updated correctly: %v", conns)
	}
}

func TestAdjustConnectionServerIDs(t *testing.T) {
	setupTestDB(t)

	Query.AddUser(context.Background(), AddUserParams{ID: "u1", Data: `{}`})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c1", UserID: "u1", ServerID: 1, Protocol: "wg", ClientID: "k1", Data: `{}`,
	})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c2", UserID: "u1", ServerID: 2, Protocol: "wg", ClientID: "k2", Data: `{}`,
	})
	Query.AddConnection(context.Background(), AddConnectionParams{
		ID: "c3", UserID: "u1", ServerID: 3, Protocol: "wg", ClientID: "k3", Data: `{}`,
	})

	err := Query.AdjustConnectionServerIDs(context.Background(), 2)
	if err != nil {
		t.Fatalf("AdjustConnectionServerIDs failed: %v", err)
	}
}
