-- name: GetSetting :one
SELECT value FROM kv WHERE key = ? LIMIT 1;

-- name: SetSetting :exec
INSERT INTO kv (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value;

-- name: GetAllSettings :many
SELECT key, value FROM kv;

-- name: GetServers :many
SELECT id, data FROM servers ORDER BY id;

-- name: GetServer :one
SELECT data FROM servers WHERE id = ? LIMIT 1;

-- name: AddServer :one
INSERT INTO servers (data) VALUES (?) RETURNING id;

-- name: UpdateServer :exec
UPDATE servers SET data = ? WHERE id = ?;

-- name: DeleteServer :exec
DELETE FROM servers WHERE id = ?;

-- name: ReorderServersUpdateIDTemp :exec
UPDATE servers SET id = ? WHERE id = ?;

-- name: ReorderUserConnectionsUpdateServerIDTemp :exec
UPDATE user_connections SET server_id = ? WHERE server_id = ?;

-- name: ReorderUserConnectionsNegative :exec
UPDATE user_connections SET server_id = -server_id - 1;

-- name: AdjustConnectionServerIDs :exec
UPDATE user_connections SET server_id = server_id - 1 WHERE server_id > ?;

-- name: DeleteServerConnections :exec
DELETE FROM user_connections WHERE server_id = ?;

-- name: GetUsers :many
SELECT id, data FROM users;

-- name: GetUser :one
SELECT data FROM users WHERE id = ? LIMIT 1;

-- name: GetUserByUsername :one
SELECT data FROM users WHERE json_extract(data, '$.username') = ? LIMIT 1;

-- name: AddUser :exec
INSERT INTO users (id, data) VALUES (?, ?)
ON CONFLICT(id) DO UPDATE SET data = excluded.data;

-- name: UpdateUser :exec
UPDATE users SET data = ? WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;

-- name: HasUsers :one
SELECT COUNT(*) FROM users;

-- name: DeleteUserConnections :exec
DELETE FROM user_connections WHERE user_id = ?;

-- name: GetUserConnections :many
SELECT data FROM user_connections WHERE user_id = ?;

-- name: GetAllUserConnections :many
SELECT data FROM user_connections;

-- name: GetServerConnections :many
SELECT data FROM user_connections WHERE server_id = ?;

-- name: GetServerConnectionsByProtocol :many
SELECT data FROM user_connections WHERE server_id = ? AND protocol = ?;

-- name: GetConnectionByClient :one
SELECT data FROM user_connections WHERE server_id = ? AND protocol = ? AND client_id = ? LIMIT 1;

-- name: AddConnection :exec
INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, data) 
VALUES (?, ?, ?, ?, ?, ?);

-- name: UpdateConnection :exec
UPDATE user_connections SET data = ? WHERE id = ?;

-- name: DeleteConnection :exec
DELETE FROM user_connections WHERE id = ?;
