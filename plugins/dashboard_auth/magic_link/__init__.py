"""MagicLinkAuthProvider — email magic-link authentication for the Hermes dashboard.

Implements the DashboardAuthProvider protocol using the SQLite sessions table
managed by ``hermes_cli.user_auth``. This provider is NOT an OAuth provider;
magic links are initiated via ``POST /api/auth/magic-link`` and verified via
``POST /api/auth/verify`` (handled by the dashboard_auth route layer, not this
provider).

Provider flow:

  1. **start_login / complete_login** — NotImplemented. Magic link uses a
     different flow (POST request, not OAuth redirect). The dashboard auth
     route layer calls ``create_magic_link(email)`` directly, then emails
     the token to the user.
  2. **verify_session** — The primary method. Called on every request to
     validate the ``hermes_session`` cookie. The cookie value is a session_id
     that maps to a row in the SQLite sessions table via
     ``get_session_user(session_id)``. Returns a ``Session`` on success or
     ``None`` on expiry/invalidity.
  3. **refresh_session** — Always raises ``RefreshExpiredError``. Magic link
     sessions are long-lived (7 days by default) and do not refresh; when
     they expire, the user gets a new magic link.
  4. **revoke_session** — Best-effort delete from SQLite via
     ``delete_session()``. Must not raise.

Configuration:

  The plugin auto-activates when the ``HERMES_DASHBOARD_MAGIC_LINK_ENABLED``
  environment variable is set to ``1`` or ``true`` (case-insensitive after
  stripping). When not set or set to any other value, the plugin skips
  registration and writes a human-readable reason to ``LAST_SKIP_REASON``.

  This env var gates activation because magic link auth is intended for
  deployments where OAuth is not available (local, offline, or air-gapped
  environments) and the simpler email-based flow is preferred.

Skip reasons:

  When the plugin skips registration, ``LAST_SKIP_REASON`` is set so the
  dashboard's fail-closed branch can surface a specific message like
  "Set HERMES_DASHBOARD_MAGIC_LINK_ENABLED=1 to enable email magic link auth"
  instead of a bare "no providers registered" error.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from typing import Optional

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    InvalidCodeError,
    LoginStart,
    ProviderError,
    RefreshExpiredError,
    Session,
)
from hermes_cli.user_auth import (
    DASHBOARD_PROFILE_DIR,
    SESSION_TTL_SECONDS,
    delete_session,
    get_session_user,
    get_user_by_id,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Skip-reason channel for operator-friendly error messages
# ---------------------------------------------------------------------------

LAST_SKIP_REASON: str = ""


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class MagicLinkAuthProvider(DashboardAuthProvider):
    """Magic link email authentication using SQLite sessions.

    This provider verifies sessions by looking up the session_id (stored in
    the ``hermes_session`` cookie) in the SQLite sessions table. It does NOT
    handle the magic link creation or verification endpoints — those are
    managed by the dashboard_auth route layer using ``hermes_cli.user_auth``
    functions directly.

    The OAuth flow methods (``start_login``, ``complete_login``) raise
    ``NotImplementedError`` because magic link auth uses a different flow:
    POST to /api/auth/magic-link to initiate, POST to /api/auth/verify to
    complete.
    """

    name = "magic_link"
    display_name = "Email (Magic Link)"

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        """Not implemented — magic link uses POST /api/auth/magic-link, not OAuth redirect."""
        raise NotImplementedError(
            "magic link uses POST /api/auth/magic-link, not OAuth redirect"
        )

    def complete_login(
        self,
        *,
        code: str,
        state: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> Session:
        """Not implemented — magic link uses /api/auth/verify, not OAuth callback."""
        raise NotImplementedError(
            "magic link uses /api/auth/verify, not OAuth callback"
        )

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        """Verify a session by looking up the session_id in SQLite.

        The ``access_token`` parameter is actually a session_id (the value
        stored in the ``hermes_session`` cookie). This is an intentional
        repurposing of the provider protocol's access_token field for
        magic link's simpler session model.

        Returns a ``Session`` if the session is valid and not expired, or
        ``None`` if the session is invalid/expired (middleware then forces
        re-login via the magic link flow).

        Raises ``ProviderError`` if the SQLite database is unreachable.
        """
        session_id = access_token  # access_token field carries session_id

        try:
            user = get_session_user(session_id)
        except Exception as exc:
            # SQLite unreachable — bubble up so middleware emits 503
            raise ProviderError(
                f"magic_link: failed to query sessions DB: {exc}"
            ) from exc

        if user is None:
            # Session not found or expired — middleware redirects to login
            logger.debug("magic_link: session %s not found or expired", session_id[:8])
            return None

        # Compute session expiry. get_session_user already checks expires_at > now,
        # so if we're here, the session is valid. We compute a rough expires_at
        # by adding SESSION_TTL_SECONDS to the current time since we don't have
        # the exact row. This is used for the Session.expires_at field which
        # the middleware uses for cookie max-age, not for actual expiry checking.
        import time
        expires_at = int(time.time()) + SESSION_TTL_SECONDS

        return Session(
            user_id=user.id,
            email=user.email,
            display_name=user.name,
            org_id="",
            provider=self.name,
            expires_at=expires_at,
            access_token=session_id,
            refresh_token="",
        )

    def refresh_session(self, *, refresh_token: str) -> Session:
        """Magic link sessions do not refresh — force re-login when expired.

        Sessions last 7 days (SESSION_TTL_SECONDS). When they expire, the
        user requests a new magic link rather than refreshing a token.
        """
        raise RefreshExpiredError(
            "magic link sessions do not refresh; request a new magic link via "
            "POST /api/auth/magic-link"
        )

    def revoke_session(self, *, refresh_token: str) -> None:
        """Best-effort session deletion from SQLite.

        The ``refresh_token`` parameter is actually a session_id for magic
        link auth, since we store the session_id in both the access_token and
        (empty) refresh_token fields of the Session dataclass. This is a
        best-effort operation that must not raise.
        """
        session_id = refresh_token  # refresh_token field carries session_id
        try:
            delete_session(session_id)
            logger.debug("magic_link: revoked session %s", session_id[:8])
        except Exception as exc:
            # Best-effort — must not raise per provider contract
            logger.warning("magic_link: failed to revoke session: %s", exc)

    def create_session(
        self,
        *,
        user_id: str,
        email: str,
        display_name: str = "",
        role: str = "user",
        ttl_seconds: int = 86400,
    ) -> Session:
        """Create a new session in SQLite and return a ``Session`` dataclass.

        Called by the ``/api/auth/verify`` route when a magic link token is
        successfully validated, and potentially by other auth flows that
        need to create a dashboard session programmatically.

        Generates a fresh session_id using :func:`secrets.token_urlsafe`,
        inserts a row into the ``sessions`` table, and returns a fully
        populated :class:`Session` with the generated access token.

        Args:
            user_id: Stable user identifier (e.g. UUID or email hash).
            email: User's email address, stored in the Session for claims.
            display_name: Human-readable name used by the UI.
            role: RBAC role string (``root``, ``admin``, ``fam``, ``user``).
            ttl_seconds: Session lifetime in seconds (default: 86400 = 24h).

        Returns:
            A populated :class:`Session` with the generated ``access_token``
            (which doubles as the session_id in the cookie).
        """
        import secrets
        import time

        session_id = secrets.token_urlsafe(32)
        now = int(time.time())
        expires_at = now + ttl_seconds

        conn = sqlite3.connect(str(DASHBOARD_PROFILE_DIR / "users.db"))
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute(
                "INSERT INTO sessions (session_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (session_id, user_id, now, expires_at),
            )
            conn.commit()
        finally:
            conn.close()

        return Session(
            user_id=user_id,
            email=email,
            display_name=display_name,
            org_id="",
            provider=self.name,
            expires_at=expires_at,
            access_token=session_id,
            refresh_token="",
        )


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------


def register(ctx) -> None:
    """Plugin entry — called by the plugin loader at startup.

    Registers ``MagicLinkAuthProvider`` only when
    ``HERMES_DASHBOARD_MAGIC_LINK_ENABLED`` is set to ``1`` or ``true``.
    When not set or set to any other value, writes a skip reason to
    ``LAST_SKIP_REASON`` so the dashboard can surface a helpful error
    instead of "no providers registered".
    """
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""

    env = os.environ.get("HERMES_DASHBOARD_MAGIC_LINK_ENABLED", "").strip().lower()

    if env not in ("1", "true"):
        LAST_SKIP_REASON = (
            "HERMES_DASHBOARD_MAGIC_LINK_ENABLED is not set. Set it to '1' "
            "or 'true' to enable email magic link authentication for the "
            "dashboard. Magic link auth uses SQLite-backed sessions and "
            "does not require an external OAuth provider."
        )
        logger.debug("dashboard-auth-magic_link: %s", LAST_SKIP_REASON)
        return

    # Ensure user DB is initialized so sessions table exists
    from hermes_cli.user_auth import init_user_db
    try:
        init_user_db()
    except Exception as exc:
        LAST_SKIP_REASON = f"magic_link: failed to initialize user DB: {exc}"
        logger.warning("dashboard-auth-magic_link: %s", LAST_SKIP_REASON)
        return

    provider = MagicLinkAuthProvider()
    ctx.register_dashboard_auth_provider(provider)
    logger.info(
        "dashboard-auth-magic_link: registered provider (name=%s, display=%s)",
        provider.name,
        provider.display_name,
    )