"""
TTL-based in-memory cache for frequently accessed data.
Reduces redundant DB reads and SSH round-trips.
"""

import time
import logging
from typing import Any

logger = logging.getLogger(__name__)


class TTLCache:
    """Simple async-compatible TTL cache with optional per-key invalidation."""

    def __init__(self, default_ttl: float = 30.0):
        self._store: dict[str, tuple[Any, float]] = {}
        self._default_ttl = default_ttl

    async def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, ts = entry
        if time.monotonic() - ts > self._default_ttl:
            del self._store[key]
            return None
        return value

    async def set(self, key: str, value: Any, ttl: float | None = None):
        self._store[key] = (value, time.monotonic())

    async def invalidate(self, key: str | None = None):
        if key is None:
            self._store.clear()
        elif key in self._store:
            del self._store[key]

    async def invalidate_prefix(self, prefix: str):
        keys_to_remove = [k for k in self._store if k.startswith(prefix)]
        for k in keys_to_remove:
            del self._store[k]


class SSHCache:
    """Cache for SSH-fetched protocol client lists.
    Keys are '{server_id}:{protocol}' — invalidated on write operations.
    Uses a shorter TTL (15 s) because SSH data should stay reasonably fresh."""

    def __init__(self, default_ttl: float = 15.0):
        self._store: dict[str, tuple[list, float]] = {}
        self._default_ttl = default_ttl

    def _key(self, server_id: int, protocol: str) -> str:
        return f"{server_id}:{protocol}"

    async def get_clients(self, server_id: int, protocol: str) -> list | None:
        k = self._key(server_id, protocol)
        entry = self._store.get(k)
        if entry is None:
            return None
        value, ts = entry
        if time.monotonic() - ts > self._default_ttl:
            del self._store[k]
            return None
        return value

    async def set_clients(self, server_id: int, protocol: str, clients: list):
        k = self._key(server_id, protocol)
        self._store[k] = (clients, time.monotonic())

    async def invalidate(self, server_id: int = None, protocol: str = None):
        if server_id is None and protocol is None:
            self._store.clear()
            return
        keys_to_remove = [
            k for k in self._store
            if (server_id is None or k.startswith(f"{server_id}:"))
            and (protocol is None or k.endswith(f":{protocol}"))
        ]
        for k in keys_to_remove:
            del self._store[k]

    async def invalidate_server(self, server_id: int):
        keys_to_remove = [k for k in self._store if k.startswith(f"{server_id}:")]
        for k in keys_to_remove:
            del self._store[k]


# Global singleton instances
settings_cache = TTLCache(default_ttl=30.0)
users_cache = TTLCache(default_ttl=30.0)
servers_cache = TTLCache(default_ttl=30.0)
ssh_cache = SSHCache(default_ttl=15.0)
