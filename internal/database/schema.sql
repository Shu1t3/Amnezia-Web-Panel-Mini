CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_connections (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    server_id INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    client_id TEXT NOT NULL,
    data TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_uc_user ON user_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_uc_server ON user_connections(server_id);
CREATE INDEX IF NOT EXISTS idx_uc_server_proto ON user_connections(server_id, protocol);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(json_extract(data, '$.username'));
