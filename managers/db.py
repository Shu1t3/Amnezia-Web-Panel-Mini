"""
Async SQLite storage layer for Amnezia Web Panel.
Replaces the single-file JSON approach with a proper database.
"""

import json
import logging
import aiosqlite

logger = logging.getLogger(__name__)

_DB_PATH = None
_db: aiosqlite.Connection | None = None


async def init_db(db_path: str):
    """Initialize the database connection and create tables if needed."""
    global _db, _DB_PATH
    _DB_PATH = db_path
    _db = await aiosqlite.connect(db_path)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA foreign_keys=ON")

    await _db.executescript("""
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
    """)
    await _db.commit()


async def close_db():
    global _db
    if _db:
        await _db.close()
        _db = None


def _row_to_dict(row) -> dict:
    return json.loads(row["data"])


async def get_setting(key: str, default=None):
    async with _db.execute("SELECT value FROM kv WHERE key=?", (key,)) as cur:
        row = await cur.fetchone()
        if row:
            return json.loads(row["value"])
        return default


async def set_setting(key: str, value):
    await _db.execute(
        "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
        (key, json.dumps(value, ensure_ascii=False)),
    )
    await _db.commit()


async def get_all_settings() -> dict:
    """Return the full settings dict, creating defaults if the DB is fresh."""
    result = {}
    async with _db.execute("SELECT key, value FROM kv") as cur:
        async for row in cur:
            result[row["key"]] = json.loads(row["value"])

    defaults = {
        "appearance": {"title": "Amnezia", "logo": "❤️", "subtitle": "Web Panel"},
        "sync": {},
        "captcha": {"enabled": False},
        "telegram": {"enabled": False, "token": ""},
        "ssl": {
            "enabled": False, "domain": "", "cert_path": "", "key_path": "",
            "cert_text": "", "key_text": "", "panel_port": 8000,
        },
    }
    for k, v in defaults.items():
        if k not in result:
            result[k] = v
    return result


async def set_all_settings(settings: dict):
    for k, v in settings.items():
        await set_setting(k, v)


# ── Servers ──────────────────────────────────────────────────

async def get_servers() -> list:
    async with _db.execute("SELECT id, data FROM servers ORDER BY id") as cur:
        rows = await cur.fetchall()
    return [{"server_id": row["id"], **json.loads(row["data"])} for row in rows]


async def get_server(server_id: int) -> dict | None:
    async with _db.execute("SELECT data FROM servers WHERE id=?", (server_id,)) as cur:
        row = await cur.fetchone()
        if row:
            return {"server_id": server_id, **json.loads(row["data"])}
        return None


async def add_server(server: dict) -> int:
    cur = await _db.execute(
        "INSERT INTO servers (data) VALUES (?)",
        (json.dumps(server, ensure_ascii=False),),
    )
    await _db.commit()
    return cur.lastrowid


async def update_server(server_id: int, server: dict):
    await _db.execute(
        "UPDATE servers SET data=? WHERE id=?",
        (json.dumps(server, ensure_ascii=False), server_id),
    )
    await _db.commit()


async def delete_server(server_id: int):
    await _db.execute("DELETE FROM servers WHERE id=?", (server_id,))
    await _db.execute(
        "DELETE FROM user_connections WHERE server_id=?", (server_id,)
    )
    await _db.commit()


async def reorder_servers(order: list[int]):
    """Reorder servers by rewriting IDs and remapping user_connections.
    Uses temporary negative IDs to avoid unique constraint conflicts."""
    async with _db.execute("SELECT id FROM servers ORDER BY id") as cur:
        rows = await cur.fetchall()
    old_ids = [row["id"] for row in rows]
    if len(order) != len(old_ids):
        return

    # Phase 1: set all IDs to negative temporaries
    for i, old_id in enumerate(old_ids):
        await _db.execute("UPDATE servers SET id=? WHERE id=?", (-(i + 1), old_id))
    await _db.execute("UPDATE user_connections SET server_id = -server_id - 1")
    await _db.commit()

    # Phase 2: map old negative IDs to new positive IDs
    for new_pos, old_id in enumerate(order):
        temp_id = -(old_ids.index(old_id) + 1)
        new_id = new_pos
        await _db.execute("UPDATE servers SET id=? WHERE id=?", (new_id, temp_id))
        old_temp = -(old_id + 1)
        await _db.execute(
            "UPDATE user_connections SET server_id=? WHERE server_id=?",
            (new_id, old_temp),
        )
    await _db.commit()


async def adjust_connection_server_ids(deleted_id: int):
    """After deleting a server, decrement all server_id > deleted_id."""
    await _db.execute(
        "UPDATE user_connections SET server_id = server_id - 1 WHERE server_id > ?",
        (deleted_id,),
    )
    await _db.execute(
        "DELETE FROM user_connections WHERE server_id=?", (deleted_id,)
    )
    await _db.commit()


# ── Users ────────────────────────────────────────────────────

async def get_users() -> list:
    async with _db.execute("SELECT id, data FROM users") as cur:
        rows = await cur.fetchall()
    return [_row_to_dict(row) for row in rows]


async def get_user(user_id: str) -> dict | None:
    async with _db.execute("SELECT data FROM users WHERE id=?", (user_id,)) as cur:
        row = await cur.fetchone()
        if row:
            return json.loads(row["data"])
        return None


async def get_user_by_username(username: str) -> dict | None:
    async with _db.execute("SELECT data FROM users") as cur:
        async for row in cur:
            user = json.loads(row["data"])
            if user.get("username") == username:
                return user
    return None


async def add_user(user: dict):
    await _db.execute(
        "INSERT OR REPLACE INTO users (id, data) VALUES (?, ?)",
        (user["id"], json.dumps(user, ensure_ascii=False)),
    )
    await _db.commit()


async def update_user(user: dict):
    await _db.execute(
        "UPDATE users SET data=? WHERE id=?",
        (json.dumps(user, ensure_ascii=False), user["id"]),
    )
    await _db.commit()


async def delete_user(user_id: str):
    await _db.execute("DELETE FROM users WHERE id=?", (user_id,))
    await _db.execute(
        "DELETE FROM user_connections WHERE user_id=?", (user_id,)
    )
    await _db.commit()


async def has_users() -> bool:
    async with _db.execute("SELECT COUNT(*) as cnt FROM users") as cur:
        row = await cur.fetchone()
        return row["cnt"] > 0


# ── User connections ─────────────────────────────────────────

async def get_user_connections(user_id: str = None) -> list:
    if user_id:
        async with _db.execute(
            "SELECT data FROM user_connections WHERE user_id=?", (user_id,)
        ) as cur:
            rows = await cur.fetchall()
    else:
        async with _db.execute("SELECT data FROM user_connections") as cur:
            rows = await cur.fetchall()
    return [_row_to_dict(row) for row in rows]


async def get_server_connections(server_id: int, protocol: str = None) -> list:
    if protocol:
        async with _db.execute(
            "SELECT data FROM user_connections WHERE server_id=? AND protocol=?",
            (server_id, protocol),
        ) as cur:
            rows = await cur.fetchall()
    else:
        async with _db.execute(
            "SELECT data FROM user_connections WHERE server_id=?", (server_id,)
        ) as cur:
            rows = await cur.fetchall()
    return [_row_to_dict(row) for row in rows]


async def get_connection_by_client(server_id: int, protocol: str, client_id: str) -> dict | None:
    async with _db.execute(
        "SELECT data FROM user_connections WHERE server_id=? AND protocol=? AND client_id=?",
        (server_id, protocol, client_id),
    ) as cur:
        row = await cur.fetchone()
        if row:
            return json.loads(row["data"])
        return None


async def add_connection(conn: dict):
    await _db.execute(
        "INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, data) VALUES (?, ?, ?, ?, ?, ?)",
        (conn["id"], conn["user_id"], conn["server_id"], conn["protocol"],
         conn["client_id"], json.dumps(conn, ensure_ascii=False)),
    )
    await _db.commit()


async def update_connection(conn: dict):
    await _db.execute(
        "UPDATE user_connections SET data=? WHERE id=?",
        (json.dumps(conn, ensure_ascii=False), conn["id"]),
    )
    await _db.commit()


async def delete_connection(conn_id: str):
    await _db.execute("DELETE FROM user_connections WHERE id=?", (conn_id,))
    await _db.commit()


async def delete_connections_for_user(user_id: str):
    await _db.execute(
        "DELETE FROM user_connections WHERE user_id=?", (user_id,)
    )
    await _db.commit()


# ── API tokens ───────────────────────────────────────────────

async def get_api_tokens() -> list:
    async with _db.execute("SELECT value FROM kv WHERE key='api_tokens'") as cur:
        row = await cur.fetchone()
        if row:
            return json.loads(row["value"])
    return []


async def set_api_tokens(tokens: list):
    await set_setting("api_tokens", tokens)


# ── Bulk operations ──────────────────────────────────────────

async def get_all_connections_grouped_by_server() -> dict:
    """Return {server_id: [conn, ...]} for all connections."""
    conns = await get_user_connections()
    grouped = {}
    for c in conns:
        grouped.setdefault(c["server_id"], []).append(c)
    return grouped


async def delete_users(user_ids: list[str]):
    """Delete multiple users and their connections."""
    placeholders = ",".join("?" * len(user_ids))
    await _db.execute(f"DELETE FROM users WHERE id IN ({placeholders})", user_ids)
    await _db.execute(
        f"DELETE FROM user_connections WHERE user_id IN ({placeholders})", user_ids
    )
    await _db.commit()


async def update_users_bulk(updates: list[dict]):
    """Update multiple users in one commit. Each item must have 'id' key."""
    for u in updates:
        await _db.execute(
            "UPDATE users SET data=? WHERE id=?",
            (json.dumps(u, ensure_ascii=False), u["id"]),
        )
    await _db.commit()
