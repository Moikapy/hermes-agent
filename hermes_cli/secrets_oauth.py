"""OAuth lifecycle tracker — ``hermes secrets status`` (Phase 2).

Provides read-only visibility into OAuth credential lifecycle status,
including JWT-based expiry detection and broken-credential warnings.

This module is part of the unified secrets plan
(``~/.hermes/plans/hermes-secrets-unified-spec.md``) and implements the
``secrets_oauth.py`` file described in its Phase 2 section.  It is
**strictly read-only** — no methods write to ``auth.json``, the
credential pool, or any environment variable.  Token refresh and
re-authentication remain the user's responsibility.

Key entry points:

* :class:`OAuthCredential` — typed dataclass for a single OAuth token
* :func:`decode_jwt_exp` — parse a JWT and return its ``exp`` claim as a
  timezone-aware :class:`datetime`
* :func:`discover_oauth_providers` — walk ``auth.json``'s ``providers``
  section and return one :class:`OAuthCredential` per provider
* :func:`discover_credential_pool` — walk ``auth.json``'s
  ``credential_pool`` section (each entry is a separate credential)
* :func:`warn_if_oauth_expiring` — emit the spec-shaped startup warning
  for any token that expires within 30 minutes
"""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Profile-aware path resolution — same anchor as secrets_registry.py.
from hermes_constants import get_hermes_home


# Default warning threshold from the spec (line 161: "any token expires
# within 30 minutes, print a warning with the re-auth command").
DEFAULT_WARN_WINDOW_MINUTES = 30

# Per the spec (line 166) and the task acceptance criteria, the xAI
# special-case message is verbatim.  Kept as a module constant so tests
# and downstream callers can compare against the exact string.
XAI_ID_TOKEN_ONLY_MESSAGE = (
    "[!!] xai-oauth: only id_token stored, xAI API will reject. "
    "Run: hermes auth add xai-oauth"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class OAuthCredential:
    """A single OAuth credential discovered from ``auth.json``.

    The ``access_token`` and ``refresh_token`` fields are kept verbatim
    from the source for diagnostic value (e.g. ``***`` for masked env
    keys, or the actual JWT for live tokens).  Callers must NOT log
    these fields in plaintext — the spec at line 162 only requires
    expiry visibility, not credential value visibility.

    ``expires_at`` is the canonical field for "when does this token
    stop being valid?".  For credentials where the access token is a
    JWT, it is parsed from the ``exp`` claim.  For non-JWT tokens
    (e.g. some opaque strings), it falls back to the ``expires_at``
    field in the auth.json record itself, which some providers
    populate (nous, xai-oauth).

    ``last_auth_error`` is the structured error from the most recent
    refresh attempt (when the provider records one).  Used by
    :meth:`needs_reauth` to detect revoked refresh tokens without
    having to attempt a refresh.
    """

    provider: str
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None
    last_refresh: Optional[datetime] = None
    refresh_count: int = 0
    # Optional structured error from a recent refresh attempt; populated
    # when ``auth.json``'s ``providers[provider].last_auth_error`` exists.
    last_auth_error: Dict[str, Any] = field(default_factory=dict)
    # Free-form flags useful for diagnostic display (e.g. xAI
    # id_token-only detection, label/source for credential_pool entries).
    notes: str = ""
    # Optional: the dotted path inside auth.json where this credential
    # was found, for stable identification in registry output.
    source_path: str = ""

    def __post_init__(self) -> None:
        """Derive ``expires_at`` from the access token when not given.

        Per the spec ("expires_at (parsed from JWT exp claim)") and
        the task body ("expires_at (parsed from JWT exp claim)"), an
        ``OAuthCredential`` constructed from a JWT access token
        should have its ``expires_at`` populated automatically.
        Callers that already have a parsed ``expires_at`` (e.g. from
        auth.json's own ``expires_at`` field for non-JWT tokens) can
        pass it explicitly to override.
        """
        if self.expires_at is None and self.access_token:
            jwt_exp = decode_jwt_exp(self.access_token)
            if jwt_exp is not None:
                self.expires_at = jwt_exp

    # ----- accessors ----------------------------------------------------

    def is_expired(self) -> bool:
        """Return True if the token is past its ``expires_at`` (or never had one).

        A token with ``expires_at is None`` is treated as "unknown
        expiry, not currently expired" — we cannot say it expired, so
        we say it didn't.  Callers that need a stricter check (e.g.
        "this token has no exp claim at all") should inspect the field
        directly.
        """
        if self.expires_at is None:
            return False
        # Normalise to UTC for comparison; JWTs are always UTC.
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp

    def expires_within(self, minutes: int) -> bool:
        """Return True if the token expires within ``minutes`` from now.

        A token with no known expiry (``expires_at is None``) is
        treated as "does not expire within the window" so the
        startup warning stays quiet for opaque (non-JWT) tokens that
        we simply can't predict.
        """
        if self.expires_at is None:
            return False
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = (exp - now).total_seconds()
        return 0 <= delta <= minutes * 60

    def needs_reauth(self) -> bool:
        """Return True when the credential cannot self-recover.

        Two failure modes count as "needs re-auth":

        1. No ``refresh_token`` stored.  Once the access token expires
           the user must re-authenticate by hand.
        2. The most recent refresh attempt was rejected with a
           ``relogin_required`` flag in the auth.json error block —
           this is the canonical xAI "Refresh token has been revoked"
           case from the spec.
        """
        if not self.refresh_token:
            return True
        if self.last_auth_error.get("relogin_required") is True:
            return True
        # xAI explicitly records the error code "xai_refresh_failed"
        # alongside relogin_required; the second check is belt-and-
        # braces for error payloads that omit the flag.
        if self.last_auth_error.get("code") == "xai_refresh_failed":
            return True
        return False

    def xai_id_token_only(self) -> bool:
        """True for the xai-oauth provider when only ``id_token`` is stored.

        xAI's API requires an ``access_token``; an ``id_token`` (which
        is a JWT signed for OpenID Connect identity, not API access)
        causes every API call to 401.  This was the root cause of the
        failure that motivated the spec — see the task body and the
        spec at lines 163-167.
        """
        if self.provider != "xai-oauth":
            return False
        if not self.access_token:
            return True
        # The truncated auth.json on disk (line 9 of the snippet) shows
        # xAI stores tokens under ``tokens.id_token`` only when there's
        # no ``access_token``; when both exist, ``access_token`` wins.
        # The discoverer surfaces this as a notes flag so we don't
        # second-guess the structure here.
        if self.notes and self.notes.startswith("id_token_only"):
            return True
        return False


# ---------------------------------------------------------------------------
# JWT decoding
# ---------------------------------------------------------------------------


def decode_jwt_exp(token: str) -> Optional[datetime]:
    """Parse a JWT and return its ``exp`` claim as a UTC ``datetime``.

    Returns ``None`` if the token is not a string, is not a
    three-part JWT, the payload is not valid base64, or the ``exp``
    claim is missing or not a number.  We deliberately do not verify
    signatures — this is a read-only diagnostic tool and the goal is
    to surface the time the token *claims* to expire at, not the
    time a trusted issuer says it does.

    Matches the spec at lines 145-156: ``expires_at: datetime | None``
    parsed from the JWT ``exp`` claim.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        return None
    parts = token.split(".")
    payload_b64 = parts[1]
    # urlsafe_b64decode requires len % 4 == 0 — pad with ``=``.
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        claims = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, Exception):
        # base64.binascii.Error is the canonical error for bad-padding
        # b64decode, but we use a broad except because the underlying
        # exception class lives in the binascii module and pyright
        # can't resolve ``base64.binascii``.  The double-broad catch
        # is fine: any decode failure here means "not a valid JWT",
        # which is what we want to communicate.
        return None
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(float(exp), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# auth.json loading
# ---------------------------------------------------------------------------


def _auth_json_path() -> Path:
    """Return the absolute path to ``auth.json`` for the active profile.

    Uses :func:`hermes_constants.get_hermes_home` so profile rotation
    is transparent — a sund-profile Hermes run sees
    ``~/.hermes/profiles/sund/home/.hermes/auth.json`` and the rest of
    the auth flow still works.  No hard-coded ``~/.hermes`` strings.
    """
    return get_hermes_home() / "auth.json"


def _read_auth_json(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read ``auth.json`` and return its parsed JSON, or ``{}`` on any failure.

    The file is treated as best-effort: missing, malformed, or
    unparseable auth.json is reported as an empty dict so the
    discoverers can short-circuit cleanly.  Errors are surfaced to
    stderr by the registry/CLI layer if they want them.
    """
    if path is None:
        path = _auth_json_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_iso_optional(value: Any) -> Optional[datetime]:
    """Parse an ISO 8601 string into a ``datetime`` (UTC if naive).

    Accepts ``None`` and unparseable values by returning ``None``.
    Handles the trailing ``Z`` shorthand which :func:`datetime.fromisoformat`
    rejects on Python <3.11.
    """
    if not isinstance(value, str) or not value:
        return None
    s = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _build_credential_from_provider(
    name: str, record: Dict[str, Any], auth_path: Path
) -> Optional[OAuthCredential]:
    """Build an :class:`OAuthCredential` from one ``providers`` entry.

    Returns ``None`` for entries that don't have a recognisable access
    token (e.g. provider placeholder records) — the discoverer skips
    ``None`` results silently.

    The xAI special case (id_token only, no access_token) is detected
    here so :meth:`OAuthCredential.xai_id_token_only` and the
    startup auto-prompt can both see the same flag.
    """
    if not isinstance(record, dict):
        return None

    # xAI stores the actual tokens nested under ``tokens`` rather than
    # directly on the provider record.  Other providers (nous) put
    # ``access_token`` at the top level.
    access_token: Optional[str] = record.get("access_token")
    refresh_token: Optional[str] = record.get("refresh_token")
    notes = ""
    # Even if access_token is missing, we still want to surface xAI's
    # id_token-only case so the startup warning can fire.  Detect the
    # nested ``tokens.id_token`` *before* the empty-credential skip.
    if name == "xai-oauth":
        tokens = record.get("tokens")
        if isinstance(tokens, dict):
            id_token = tokens.get("id_token")
            if id_token and not access_token:
                # Per spec line 163-167: only id_token stored ⇒ xAI
                # API will reject.  Promote the id_token to
                # ``access_token`` so the rest of the lifecycle code
                # (is_expired, expires_within) still works, but set a
                # notes flag so the xAI special-case message gets
                # emitted.
                access_token = id_token
                notes = "id_token_only"

    if not access_token and not refresh_token:
        # Provider has nothing to track — skip.
        return None

    # Expires-at resolution: prefer the JWT ``exp`` claim (most
    # accurate), fall back to the record-level ``expires_at`` (some
    # providers compute it server-side, e.g. nous's
    # ``expires_in: 900``).
    expires_at = decode_jwt_exp(access_token) if access_token else None
    if expires_at is None:
        expires_at = _parse_iso_optional(record.get("expires_at"))

    last_refresh = _parse_iso_optional(record.get("last_refresh"))

    last_error = record.get("last_auth_error")
    if not isinstance(last_error, dict):
        last_error = {}

    return OAuthCredential(
        provider=name,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        last_refresh=last_refresh,
        refresh_count=int(record.get("refresh_count", 0) or 0),
        last_auth_error=last_error,
        notes=notes,
        source_path=f"providers.{name}",
    )


def _build_credential_from_pool_entry(
    pool_name: str,
    entry: Dict[str, Any],
    pool_path: str,
) -> Optional[OAuthCredential]:
    """Build an :class:`OAuthCredential` from one ``credential_pool`` entry.

    The pool structure is ``credential_pool.<provider>: [entries]``,
    where each entry is a flat dict with its own ``access_token``,
    ``refresh_token``, ``expires_at``, etc.  We treat the pool entry
    ``id`` (or ``label``) as a unique suffix so two pool entries for
    the same provider surface as two distinct credentials in
    ``hermes secrets status``.
    """
    if not isinstance(entry, dict):
        return None
    access_token = entry.get("access_token")
    refresh_token = entry.get("refresh_token")
    if not access_token and not refresh_token:
        return None
    # Mask sentinel — env-backed pool entries often have ``access_token: "***"``.
    # They're still useful to surface but the JWT decode will obviously
    # fail.  Pass them through anyway so the registry can flag them.
    expires_at = decode_jwt_exp(access_token) if access_token else None
    if expires_at is None:
        expires_at = _parse_iso_optional(entry.get("expires_at"))
    last_refresh = _parse_iso_optional(entry.get("last_refresh"))
    label = entry.get("label") or entry.get("id") or "?"
    return OAuthCredential(
        provider=f"{pool_name}#{label}",
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        last_refresh=last_refresh,
        refresh_count=int(entry.get("refresh_count", 0) or 0),
        notes=(
            "env-masked" if access_token == "***"
            else f"auth_type={entry.get('auth_type', '?')}"
        ),
        source_path=pool_path,
    )


# ---------------------------------------------------------------------------
# Discoverers (registry hooks)
# ---------------------------------------------------------------------------


def discover_oauth_providers(
    auth_json_path: Optional[Path] = None,
) -> List[OAuthCredential]:
    """Walk the ``providers`` section of ``auth.json``.

    Returns one :class:`OAuthCredential` per provider that has either
    an access token or a refresh token.  Providers with neither are
    skipped (they're stub records, not real credentials).

    Read-only: never writes to ``auth.json`` and never invokes the
    network.  The signature accepts an optional ``auth_json_path``
    for tests; production callers can call with no arguments.
    """
    data = _read_auth_json(auth_json_path)
    providers = data.get("providers")
    if not isinstance(providers, dict):
        return []
    path = auth_json_path or _auth_json_path()
    out: List[OAuthCredential] = []
    for name, record in providers.items():
        cred = _build_credential_from_provider(name, record, path)
        if cred is not None:
            out.append(cred)
    return out


def discover_credential_pool(
    auth_json_path: Optional[Path] = None,
) -> List[OAuthCredential]:
    """Walk the ``credential_pool`` section of ``auth.json``.

    The pool is a dict of ``provider -> [entries]``.  Every entry is
    a separate credential — the spec example (line 196) shows
    ``xai (pool cred #1-4)`` as four rows.  We achieve the same
    effect by suffixing the provider name with the entry's
    ``label``/``id``.

    Read-only: never writes to ``auth.json`` and never invokes the
    network.  The signature accepts an optional ``auth_json_path``
    for tests; production callers can call with no arguments.
    """
    data = _read_auth_json(auth_json_path)
    pool = data.get("credential_pool")
    if not isinstance(pool, dict):
        return []
    path = auth_json_path or _auth_json_path()
    out: List[OAuthCredential] = []
    for provider_name, entries in pool.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            cred = _build_credential_from_pool_entry(
                provider_name,
                entry,
                pool_path=f"credential_pool.{provider_name}",
            )
            if cred is not None:
                out.append(cred)
    return out


# ---------------------------------------------------------------------------
# Startup auto-prompt
# ---------------------------------------------------------------------------


def warn_if_oauth_expiring(
    credentials: List[OAuthCredential],
    window_minutes: int = DEFAULT_WARN_WINDOW_MINUTES,
) -> List[str]:
    """Build the list of warnings to print for tokens expiring soon.

    Returns one warning string per credential that is:

    * Expiring within ``window_minutes`` (default 30), OR
    * Already expired (so the user knows to expect a failure), OR
    * Trapped in the xAI id_token-only case (special-cased per the
      spec at lines 163-167).

    The returned list is what the caller should print to stderr.
    The function never raises — auth.json may be missing, malformed,
    or empty and the caller should still launch.

    The xAI special-case message is **verbatim** from the task
    acceptance criteria: see :data:`XAI_ID_TOKEN_ONLY_MESSAGE`.
    """
    warnings: List[str] = []
    for cred in credentials:
        if cred.xai_id_token_only():
            warnings.append(XAI_ID_TOKEN_ONLY_MESSAGE)
            continue
        if cred.is_expired():
            warnings.append(
                f"[!!] {cred.provider}: OAuth token is expired. "
                f"Run: hermes auth add {cred.provider}"
            )
            continue
        if cred.expires_within(window_minutes):
            mins = (
                int((cred.expires_at - _now_utc()).total_seconds() // 60)
                if cred.expires_at is not None
                else window_minutes
            )
            warnings.append(
                f"[!!] {cred.provider}: OAuth token expires in ~{mins}m. "
                f"Run: hermes auth add {cred.provider}"
            )
    return warnings


def print_startup_warnings(
    credentials: Optional[List[OAuthCredential]] = None,
    window_minutes: int = DEFAULT_WARN_WINDOW_MINUTES,
    stderr: Any = None,
) -> int:
    """Print the startup auto-prompt warnings to stderr (if any).

    Convenience wrapper around :func:`warn_if_oauth_expiring` that
    also handles the file I/O so :mod:`hermes_cli.main` can call it
    with one line.  Returns the number of warnings printed (0 means
    "all clear").

    If ``credentials`` is ``None`` the function runs both discoverers
    itself — fine for the startup hook, slightly wasteful for tests
    that want to control the input.
    """
    import sys
    if stderr is None:
        stderr = sys.stderr
    if credentials is None:
        credentials = discover_oauth_providers() + discover_credential_pool()
    warnings = warn_if_oauth_expiring(credentials, window_minutes=window_minutes)
    for line in warnings:
        print(line, file=stderr)
    return len(warnings)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    """Return the current UTC time as a tz-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# CLI subcommand
# ---------------------------------------------------------------------------


def register_cli(parent_parser: Any) -> None:
    """Attach a standalone ``hermes secrets oauth-status`` subcommand.

    The discoverers are normally invoked indirectly via
    :func:`secrets_registry.discover_oauth_providers` /
    :func:`secrets_registry.discover_credential_pool`, but a
    dedicated CLI entry point is useful for debugging the
    lifecycle logic in isolation (and to make the new file visible
    to anyone running ``hermes secrets --help``).

    Args:

    * ``--window MINUTES`` — override the default 30-minute warning
      window (used by both the table's "expires in" column and the
      ``xai-id-token-only`` special-case check).
    * ``--json``           — emit machine-readable JSON.
    """
    parser = parent_parser.add_parser(
        "oauth-status",
        help="Show OAuth credential lifecycle status (read-only)",
        description=(
            "Walk auth.json's providers and credential_pool sections, "
            "decode JWT exp claims, and surface tokens that are "
            "expired, expiring soon, or trapped in the xAI "
            "id_token-only case.  Read-only: never writes to "
            "auth.json and never refreshes tokens."
        ),
    )
    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WARN_WINDOW_MINUTES,
        help=(
            "Expiry-warning window in minutes "
            f"(default: {DEFAULT_WARN_WINDOW_MINUTES})"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output for machine consumption",
    )
    parser.set_defaults(func=cmd_oauth_status)


def _format_credential_row(cred: OAuthCredential) -> Dict[str, Any]:
    """Map a credential to a dict suitable for both table and JSON output."""
    now = _now_utc()
    minutes_to_expiry: Optional[int] = None
    if cred.expires_at is not None:
        exp = cred.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = (exp - now).total_seconds()
        minutes_to_expiry = int(delta // 60)
    return {
        "provider": cred.provider,
        "expires_at": (
            cred.expires_at.isoformat() if cred.expires_at else None
        ),
        "expires_in_minutes": minutes_to_expiry,
        "is_expired": cred.is_expired(),
        "expires_within_window": cred.expires_within(
            DEFAULT_WARN_WINDOW_MINUTES
        ),
        "needs_reauth": cred.needs_reauth(),
        "xai_id_token_only": cred.xai_id_token_only(),
        "has_refresh_token": bool(cred.refresh_token),
        "last_refresh": (
            cred.last_refresh.isoformat() if cred.last_refresh else None
        ),
        "source_path": cred.source_path,
        "notes": cred.notes,
    }


def cmd_oauth_status(args: argparse.Namespace) -> int:
    """``hermes secrets oauth-status`` — entry point."""
    creds = discover_oauth_providers() + discover_credential_pool()
    rows = [_format_credential_row(c) for c in creds]

    if getattr(args, "json", False):
        print(json.dumps({"count": len(rows), "entries": rows}, indent=2))
        return 0

    # Pretty table via the same Rich console the registry uses; the
    # Rich import is lazy so tests that only need the data model
    # don't pay the cost.
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # pragma: no cover
        # Fallback to a hand-rolled text table.
        for r in rows:
            print(
                f"{r['provider']:32s} "
                f"expires={r['expires_at'] or 'never':>32s} "
                f"needs_reauth={r['needs_reauth']} "
                f"xai_id_only={r['xai_id_token_only']}"
            )
        return 0

    console = Console()
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("PROVIDER", style="cyan", no_wrap=True, min_width=20)
    table.add_column("EXPIRES", justify="right", min_width=24)
    table.add_column("IN (min)", justify="right", min_width=8)
    table.add_column("STATUS", min_width=12)
    table.add_column("NEEDS REAUTH", min_width=12)
    for r in rows:
        if r["xai_id_token_only"]:
            status = "[red]id_token_only[/red]"
        elif r["is_expired"]:
            status = "[red]expired[/red]"
        elif r["expires_within_window"]:
            status = "[yellow]expiring[/yellow]"
        else:
            status = "[green]ok[/green]"
        table.add_row(
            r["provider"],
            r["expires_at"] or "never",
            str(r["expires_in_minutes"] or "-"),
            status,
            "[red]yes[/red]" if r["needs_reauth"] else "[green]no[/green]",
        )
    console.print(table)
    if rows:
        console.print(f"\n  Total: {len(rows)} OAuth credential(s)")
    else:
        console.print("\n  [dim]No OAuth credentials discovered.[/dim]")
    return 0
