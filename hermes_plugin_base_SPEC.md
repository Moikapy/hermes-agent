# HermesPlugin Base Class — Spec

## File
`~/.hermes/hermes-agent/hermes_plugin_base.py`

## Goal
Eliminate copy-pasted auth, error handling, DB management, and health-check
code across all dashboard plugins. The CF Worker at `api.moikapy.dev` already
handles auth+CORS centrally; plugins should inherit base behaviour rather than
reimplement it.

## API

### Class attributes (subclass must set)
| attr | type | required |
|------|------|----------|
| `name` | `str` | yes |
| `version` | `str` | yes |
| `db_path` | `str \| None` | optional |

### Constructor
`HermesPlugin.__init__()` creates `self.router` (FastAPI `APIRouter`), auto-
registers `/health` and `/` (info) routes, and stores an optional schema.

### DB helpers
- `set_schema(sql: str)` — store CREATE-TABLE script applied lazily on first
  `self.db` access.
- `self.db` (property) — lazy-opened `sqlite3.Connection` with
  `row_factory=sqlite3.Row`.
- `transaction()` — context manager that commits on success, rolls back on
  exception.
- `close_db()` — close the underlying connection (called in `__del__`).

### Auth helpers
- `_session_token(request)` → `str \| None` — reads
  `X-Hermes-Session-Token` header forwarded by the gateway.
- `_require_auth(request)` → `str` — returns token or raises `401`.

### Response helpers
- `ok(data)` → `{"ok": True, "data": ...}`
- `error(status_code, detail, extra=None)` — raises `HTTPException` with
  standard `{"ok": False, "error": ...}` payload.

### Proxy helpers
- `proxy_get(path, base_url=None, api_key=None, timeout=15, headers=None)`
- `proxy_post(path, body=None, base_url=None, api_key=None, timeout=15, headers=None)`

Both default to `KAPY_WORKER_URL` / `KAPY_WORKER_API_KEY` env vars and inject
`X-API-Key` when available.

### Auto endpoints
- `GET /health` → `{"status":"ok","plugin":...,"version":...}`
- `GET /` → plugin metadata + endpoint list

## Migration checklist
- [x] Create `hermes_plugin_base.py`
- [ ] Migrate `kapy-calendar` (pilot)
- [ ] Verify `/calendar/*` routes through dashboard
- [ ] (Future) Migrate remaining plugins one at a time
