"""HermesPlugin — shared base class for Hermes dashboard plugins.

Eliminates copy-pasted auth, error handling, DB management, and health-check
code across dashboard plugins. Plugins subclass HermesPlugin and register
routes on ``self.router``; the web server mounts the router under
``/api/plugins/<name>/``.

Usage::

    class MyPlugin(HermesPlugin):
        name = "my-plugin"
        version = "1.0.0"
        db_path = str(Path.home() / ".kapy" / "my.db")

        def __init__(self):
            super().__init__()
            self.set_schema(_SCHEMA_SQL)
            self._register_routes()

        def _register_routes(self):
            self.router.add_api_route("/items", self.list_items, methods=["GET"])

        async def list_items(self, request: Request):
            rows = self.db.execute("SELECT * FROM items").fetchall()
            return [dict(r) for r in rows]

    plugin = MyPlugin()
    router = plugin.router   # web_server picks this up
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_CF_WORKER_URL = os.environ.get("KAPY_WORKER_URL", "https://api.moikapy.dev")
_CF_API_KEY = os.environ.get("KAPY_WORKER_API_KEY", "")


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class HermesPlugin:
    """Base class for Hermes dashboard plugins.

    Subclasses **must** set ``name`` and ``version`` class attributes.
    They may also set ``db_path`` to enable the SQLite context manager.
    """

    name: str = ""
    version: str = "0.0.0"
    db_path: Optional[str] = None

    def __init__(self) -> None:
        self.router = APIRouter()
        self._schema: str = ""
        self._db_conn: Optional[sqlite3.Connection] = None
        # Auto-register health + info
        self.router.add_api_route("/health", self._health, methods=["GET"])
        self.router.add_api_route("/", self._info, methods=["GET"])

    # ── Schema / DB ─────────────────────────────────────────────────────

    def set_schema(self, schema_sql: str) -> None:
        """Store the CREATE-TABLE schema; it is applied lazily on first DB open."""
        self._schema = schema_sql

    def _ensure_db(self) -> sqlite3.Connection:
        """Open (and optionally initialise) the plugin SQLite DB."""
        if self._db_conn is not None:
            return self._db_conn
        if not self.db_path:
            raise RuntimeError(f"{self.__class__.__name__}.db_path is not set")
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        if self._schema:
            conn.executescript(self._schema)
            conn.commit()
        self._db_conn = conn
        return conn

    @property
    def db(self) -> sqlite3.Connection:
        """Lazy-opened SQLite connection (row_factory=sqlite3.Row)."""
        return self._ensure_db()

    @contextmanager
    def transaction(self):
        """Context manager that commits on success, rolls back on exception."""
        conn = self._ensure_db()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close_db(self) -> None:
        """Close the underlying SQLite connection."""
        if self._db_conn is not None:
            try:
                self._db_conn.close()
            except Exception:
                pass
            self._db_conn = None

    # ── Auth / Session ────────────────────────────────────────────────────

    def _session_token(self, request: Request) -> Optional[str]:
        """Extract ``X-Hermes-Session-Token`` from the request headers."""
        return request.headers.get("X-Hermes-Session-Token")

    def _require_auth(self, request: Request) -> str:
        """Return the session token or raise 401."""
        token = self._session_token(request)
        if not token:
            raise HTTPException(status_code=401, detail="Missing X-Hermes-Session-Token")
        return token

    # ── Standard responses ──────────────────────────────────────────────

    def ok(self, data: Any = None) -> Dict[str, Any]:
        """Wrap a successful response."""
        return {"ok": True, "data": data}

    def error(self, status_code: int, detail: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build a standard error payload (raise via HTTPException yourself)."""
        payload: Dict[str, Any] = {"ok": False, "error": detail}
        if extra:
            payload.update(extra)
        raise HTTPException(status_code=status_code, detail=payload)

    # ── Auto endpoints ────────────────────────────────────────────────────

    def _health(self) -> Dict[str, Any]:
        return {"status": "ok", "plugin": self.name, "version": self.version}

    def _info(self, request: Request) -> Dict[str, Any]:
        paths = []
        for r in self.router.routes:
            p = getattr(r, "path", None)
            if p:
                paths.append(p)
        return {
            "name": self.name,
            "version": self.version,
            "endpoints": paths,
        }

    # ── Proxy helpers (Worker / external APIs) ────────────────────────────

    def proxy_get(
        self,
        path: str,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 15,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """GET an external API, injecting API key if provided."""
        url = f"{(base_url or _CF_WORKER_URL).rstrip('/')}/{path.lstrip('/')}"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", f"hermes-plugin/{self.name}")
        key = api_key or _CF_API_KEY
        if key:
            req.add_header("X-API-Key", key)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def proxy_post(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 15,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """POST JSON to an external API, injecting API key if provided."""
        url = f"{(base_url or _CF_WORKER_URL).rstrip('/')}/{path.lstrip('/')}"
        data = json.dumps(body or {}).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", f"hermes-plugin/{self.name}")
        key = api_key or _CF_API_KEY
        if key:
            req.add_header("X-API-Key", key)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def __del__(self):
        self.close_db()
