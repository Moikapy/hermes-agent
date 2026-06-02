"""GitHubDashboardAuthProvider — GitHub OAuth 2.0 (authorization-code + PKCE).

Auto-loads when HERMES_DASHBOARD_GITHUB_CLIENT_ID is set.

Configuration:
  HERMES_DASHBOARD_GITHUB_CLIENT_ID     — GitHub OAuth App client ID (required)
  HERMES_DASHBOARD_GITHUB_CLIENT_SECRET — GitHub OAuth App client secret (required)
  HERMES_DASHBOARD_ALLOWED_EMAILS       — Comma-separated allowlist (optional; empty = open to all GitHub users)

GitHub OAuth docs: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time
import urllib.parse
from typing import Optional

import httpx

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    InvalidCodeError,
    LoginStart,
    ProviderError,
    RefreshExpiredError,
    Session,
)

logger = logging.getLogger(__name__)

LAST_SKIP_REASON: str = ""


class GitHubDashboardAuthProvider(DashboardAuthProvider):
    """Authenticate dashboard users via GitHub OAuth."""

    name = "github"
    display_name = "GitHub"
    flow_type = "oauth"

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        allowed_emails: tuple[str, ...] = (),
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._allowed_emails = allowed_emails
        self._jwks_cache: dict | None = None
        self._jwks_at: float = 0

    # ── OAuth round-trip ──────────────────────────────────────────

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(48)
        code_challenge = _s256(code_verifier)

        params = {
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        redirect_url = f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"

        pkce = f"provider=github;state={state};verifier={code_verifier}"
        return LoginStart(redirect_url=redirect_url, cookie_payload={"hermes_session_pkce": pkce})

    def complete_login(
        self,
        *,
        code: str,
        state: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> Session:
        # Exchange code for access token
        resp = httpx.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={"Accept": "application/json"},
            timeout=15,
        )
        if resp.status_code != 200:
            raise ProviderError(f"GitHub token exchange failed: HTTP {resp.status_code}")
        token_data = resp.json()
        if "error" in token_data:
            raise ProviderError(f"GitHub token error: {token_data['error']}")
        access_token = token_data["access_token"]

        # Fetch user profile
        user_resp = httpx.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"},
            timeout=15,
        )
        if user_resp.status_code != 200:
            raise ProviderError(f"GitHub user fetch failed: HTTP {user_resp.status_code}")
        user_data = user_resp.json()

        email = user_data.get("email") or ""
        display_name = user_data.get("login", "")
        user_id = str(user_data.get("id", ""))

        # If primary email is private, fetch from /user/emails
        if not email:
            emails_resp = httpx.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {access_token}"},
                timeout=15,
            )
            if emails_resp.status_code == 200:
                for entry in emails_resp.json():
                    if entry.get("primary") and entry.get("verified"):
                        email = entry["email"]
                        break

        if not email:
            raise ProviderError("Could not determine user email from GitHub")

        # Check allowlist
        if self._allowed_emails and email.lower() not in self._allowed_emails:
            raise ProviderError(f"Email {email} is not in the allowed list")

        # Ensure user exists in local DB and get root role if allowed
        from plugins.dashboard_auth.magic_link.db import get_user_by_email, create_user, update_user_role

        user = get_user_by_email(email)
        if not user:
            role = "root" if not self._allowed_emails or email.lower() in self._allowed_emails else "user"
            user = create_user(email=email, role=role, name=display_name)
        elif self._allowed_emails and email.lower() in self._allowed_emails and user.role != "root":
            # Promote allowed users to root
            update_user_role(user.id, "root")

        expires_at = int(time.time()) + 3600 * 24 * 7  # 7 days

        return Session(
            user_id=user.id,
            email=user.email,
            display_name=user.name or display_name,
            org_id="",
            provider="github",
            expires_at=expires_at,
            access_token=access_token,
            refresh_token="",  # GitHub OAuth doesn't issue refresh tokens
        )

    # ── Session lifecycle ──────────────────────────────────────────

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        """Verify a GitHub access token by calling /user."""
        try:
            resp = httpx.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {access_token}"},
                timeout=15,
            )
            if resp.status_code == 401:
                return None
            if resp.status_code != 200:
                raise ProviderError(f"GitHub verify failed: HTTP {resp.status_code}")
        except httpx.HTTPError as exc:
            raise ProviderError(f"GitHub verify network error: {exc}") from exc

        user_data = resp.json()
        email = user_data.get("email") or ""

        # Look up from our local DB to get role info
        from plugins.dashboard_auth.magic_link.db import get_user_by_email

        local_user = get_user_by_email(email) if email else None
        if local_user is None:
            return None

        return Session(
            user_id=local_user.id,
            email=local_user.email,
            display_name=local_user.name or user_data.get("login", ""),
            org_id="",
            provider="github",
            expires_at=int(time.time()) + 3600 * 24 * 7,
            access_token=access_token,
            refresh_token="",
        )

    def refresh_session(self, *, refresh_token: str) -> Session:
        """GitHub OAuth doesn't issue refresh tokens."""
        raise RefreshExpiredError("GitHub OAuth does not support refresh tokens; re-login required")

    def revoke_session(self, *, refresh_token: str) -> None:
        """Best-effort: GitHub doesn't have a token revocation endpoint for OAuth apps."""
        pass


# ── PKCE helper ──────────────────────────────────────────────────────

def _s256(verifier: str) -> str:
    """Generate S256 PKCE code challenge from verifier."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# ── Plugin registration ──────────────────────────────────────────────

def register(ctx) -> None:
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""

    client_id = os.environ.get("HERMES_DASHBOARD_GITHUB_CLIENT_ID", "")
    client_secret = os.environ.get("HERMES_DASHBOARD_GITHUB_CLIENT_SECRET", "")

    if not client_id:
        LAST_SKIP_REASON = (
            "HERMES_DASHBOARD_GITHUB_CLIENT_ID is not set. "
            "Create a GitHub OAuth App at https://github.com/settings/developers "
            "and set both HERMES_DASHBOARD_GITHUB_CLIENT_ID and "
            "HERMES_DASHBOARD_GITHUB_CLIENT_SECRET."
        )
        logger.debug("dashboard-auth-github: %s", LAST_SKIP_REASON)
        return

    if not client_secret:
        LAST_SKIP_REASON = (
            "HERMES_DASHBOARD_GITHUB_CLIENT_SECRET is not set. "
            "Create it alongside your GitHub OAuth App client ID."
        )
        logger.warning("dashboard-auth-github: %s", LAST_SKIP_REASON)
        return

    allowed_str = os.environ.get("HERMES_DASHBOARD_ALLOWED_EMAILS", "")
    allowed_emails = tuple(e.strip().lower() for e in allowed_str.split(",") if e.strip()) if allowed_str else ()

    provider = GitHubDashboardAuthProvider(
        client_id=client_id,
        client_secret=client_secret,
        allowed_emails=allowed_emails,
    )
    ctx.register_dashboard_auth_provider(provider)
    logger.info(
        "dashboard-auth-github: registered provider (client_id=%s…, allowed_emails=%s)",
        client_id[:8],
        list(allowed_emails) if allowed_emails else "all",
    )