"""Forge-queue preflight hook — ``hermes secrets verify`` (Phase 3).

The unified secrets spec (``~/.hermes/plans/hermes-secrets-unified-spec.md``)
describes Phase 3 as the *forge-queue pre-run integration* layer.  This
module is the *hook* forge-queue scripts can call at startup to verify
they have every credential they need before doing any real work.

The acceptance criterion (from the task body) is::

    hermes secrets verify --name ELEVENLABS_API_KEY --script
        # returns JSON with ok/fail; exit 0/1/2/3

plus a Python API::

    from hermes_cli.secrets_verify import preflight
    preflight("forge-vhs-report.py")  # → 0 if all required creds healthy

The exit code contract is the same as ``secrets doctor``:

* ``0``  — all required credentials are healthy
* ``1``  — one or more required credentials are broken (set but invalid)
* ``2``  — one or more required credentials are missing entirely
* ``3``  — the health check itself failed (network down, exception)

This module is **read-only**: it never writes to ``auth.json``, ``.env``,
the sops file, or any environment variable.  If a credential is broken,
the fix is for the user to re-auth (``hermes auth add <provider>``) or
rotate the key.

Why a separate module from ``secrets_health`` and ``secrets_oauth``?

* **Stable contract.**  ``REQUIRED_FOR_FORGE`` is the *public* list forge
  scripts import.  It should not change when LIVE_PROBES evolves.
* **Single dependency surface.**  Forge scripts need just one import:
  ``from hermes_cli.secrets_verify import REQUIRED_FOR_FORGE, preflight``.
* **No ``argparse`` surface by default.**  ``preflight()`` runs without
  printing anything — the caller (a forge script) decides what to log.
  The CLI surface (``hermes secrets verify``) is a thin wrapper that
  prints JSON and exits.

The implementation deliberately reuses the same check functions
``secrets_health.check_env_key`` (for env-backed API keys) and
``secrets_oauth.discover_oauth_providers`` / ``discover_credential_pool``
(for OAuth / credential-pool entries like ``xai-oauth`` and ``xai``).
This means the preflight verdict can never disagree with
``hermes secrets check`` — they consult the same source of truth.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Public contract: REQUIRED_FOR_FORGE
# ---------------------------------------------------------------------------
#
# Maps each forge-queue script (by exact filename — matches the script's
# argv[0] basename) to the list of canonical credential names it depends
# on.  Names are the same strings `hermes secrets check --name` accepts
# (LIVE_PROBES keys) or the auth.json provider/credential_pool names
# (`xai-oauth`, `xai`, etc.).
#
# Why a dict-of-lists, not a dataclass?  Forge scripts want to be able to
# grep for their own name in source without parsing Python — ``grep
# "forge-vhs-report.py" REQUIRED_FOR_FORGE`` should turn up a literal
# entry.  A flat dict is the simplest shape that satisfies that.
#
# NOTE: when you add a new forge script, add its row here.  When you
# rename a credential, update the matching keys in all rows.  When a
# script retires, delete its row.
REQUIRED_FOR_FORGE: Dict[str, List[str]] = {
    # Forge VHS Report — needs ElevenLabs (TTS), xAI OAuth (LLM via OAuth),
    # and xAI direct API key (LLM via API key — pool).  This is the
    # canonical example of why the unified secrets spec exists: all
    # three must be healthy for the pipeline to ship.
    "forge-vhs-report.py":       ["ELEVENLABS_API_KEY", "xai", "xai-oauth"],
    # Forge intake processor — needs OPENROUTER (LLM routing) and GitHub
    # (issue creation + PR workflow).
    "forge-intake-processor.py": ["OPENROUTER_API_KEY", "GITHUB_TOKEN"],
    # Forge video pipeline — same model + GitHub story as the intake
    # processor (different jobs, same dependencies).
    "forge-video.py":            ["OPENROUTER_API_KEY", "GITHUB_TOKEN"],
    # Forge daily — just needs GitHub for the daily post commit.
    "forge-daily.py":            ["GITHUB_TOKEN"],
}


# ---------------------------------------------------------------------------
# Internal: route a credential name to the right check function
# ---------------------------------------------------------------------------
#
# Some names are env keys (LIVE_PROBES table in secrets_health), some are
# auth.json provider names (e.g. "xai-oauth"), and some are credential_pool
# entry names (e.g. "xai" — there are 4 pool entries all named "xai").
#
# The function below centralises that routing so preflight() and
# cmd_verify() can share it.  New credential kinds should be added here,
# not in preflight/cmd_verify directly.
#
# The routing table deliberately prefers LIVE_PROBES (most-tested) for
# known env keys, then falls back to auth.json providers, then to the
# credential pool.  This means an env-backed OPENROUTER_API_KEY is
# checked even if there's also a `openrouter` provider in auth.json —
# env wins because it's the deployment target.

def _is_env_key(name: str) -> bool:
    """True iff ``name`` is one of the env-backed LIVE_PROBES keys."""
    # Imported lazily so this module can be imported under any profile
    # without dragging in requests + dotenv for CLI discovery.
    from hermes_cli.secrets_health import LIVE_PROBES
    return name in LIVE_PROBES


def _check_single_credential(name: str) -> Dict[str, Any]:
    """Run the appropriate health check for ``name``.

    Returns a dict shaped like::

        {
            "name":     "<name>",
            "kind":     "env" | "oauth_provider" | "credential_pool",
            "ok":       True | False,
            "status":   "ok" | "broken" | "missing" | "unknown",
            "detail":   "<human-readable>",
        }

    The function NEVER raises.  Network errors and missing modules
    surface as ``ok=False, status="unknown"`` with the exception
    message in ``detail`` so the caller can still produce a useful JSON
    report.
    """
    # 1. Env-backed API keys (LIVE_PROBES in secrets_health)
    if _is_env_key(name):
        try:
            from hermes_cli.secrets_health import check_env_key
            ok, detail = check_env_key({"name": name})
        except Exception as exc:  # noqa: BLE001 — never raise from a check
            return {
                "name": name, "kind": "env",
                "ok": False, "status": "unknown",
                "detail": f"check_env_key raised: {exc}",
            }
        if not ok:
            # Distinguish "key not set anywhere" (missing) from "set but
            # masked/placeholder" (broken) using the detail string the
            # check function produced.  This is fragile-but-cheap; the
            # alternative is to refactor check_env_key to return a
            # structured result, which is out of scope for Phase 3.
            status = "missing" if "not set" in detail else "broken"
            return {"name": name, "kind": "env",
                    "ok": False, "status": status, "detail": detail}
        return {"name": name, "kind": "env",
                "ok": True, "status": "ok", "detail": detail}

    # 2. auth.json providers — usually OAuth (e.g. "xai-oauth")
    try:
        from hermes_cli.secrets_oauth import discover_oauth_providers
        providers = discover_oauth_providers()
    except Exception as exc:  # noqa: BLE001
        return {
            "name": name, "kind": "oauth_provider",
            "ok": False, "status": "unknown",
            "detail": f"discover_oauth_providers raised: {exc}",
        }
    for cred in providers:
        if cred.provider == name:
            if cred.xai_id_token_only():
                return {"name": name, "kind": "oauth_provider",
                        "ok": False, "status": "broken",
                        "detail": "xAI: only id_token stored (no access_token)"}
            if cred.needs_reauth():
                return {"name": name, "kind": "oauth_provider",
                        "ok": False, "status": "broken",
                        "detail": "refresh token gone or revoked — re-auth required"}
            if cred.is_expired():
                return {"name": name, "kind": "oauth_provider",
                        "ok": False, "status": "broken",
                        "detail": f"OAuth token expired at {cred.expires_at.isoformat() if cred.expires_at else 'unknown'}"}
            return {"name": name, "kind": "oauth_provider",
                    "ok": True, "status": "ok",
                    "detail": f"token valid (expires {cred.expires_at.isoformat() if cred.expires_at else 'unknown'})"}

    # 3. auth.json credential_pool entries (e.g. "xai")
    try:
        from hermes_cli.secrets_oauth import discover_credential_pool
        pool = discover_credential_pool()
    except Exception as exc:  # noqa: BLE001
        return {
            "name": name, "kind": "credential_pool",
            "ok": False, "status": "unknown",
            "detail": f"discover_credential_pool raised: {exc}",
        }
    matches = [c for c in pool if c.provider == name]
    if matches:
        # Pick the first non-broken one.  Pool semantics are "any
        # working credential is enough" — the model dispatcher tries
        # them in order.  For preflight purposes, "at least one works"
        # is the right granularity.
        for cred in matches:
            if cred.xai_id_token_only():
                continue
            if cred.needs_reauth():
                continue
            if cred.is_expired():
                continue
            return {"name": name, "kind": "credential_pool",
                    "ok": True, "status": "ok",
                    "detail": f"{len(matches)} pool entries, first healthy one usable"}
        return {"name": name, "kind": "credential_pool",
                "ok": False, "status": "broken",
                "detail": f"{len(matches)} pool entries, all broken/expired"}

    # 4. Unknown — name not found in any discoverer.  This is the
    # canonical "missing" case.  We deliberately do not try to invent
    # a check; a typo in REQUIRED_FOR_FORGE is a real bug and we want
    # the caller to see "missing" loud and clear.
    return {"name": name, "kind": "unknown",
            "ok": False, "status": "missing",
            "detail": f"no health check knows about {name!r} (not in LIVE_PROBES, auth.json providers, or credential_pool)"}


# ---------------------------------------------------------------------------
# Public API: preflight
# ---------------------------------------------------------------------------


def preflight(script_name: str) -> int:
    """Verify every credential ``script_name`` requires.

    ``script_name`` is matched against :data:`REQUIRED_FOR_FORGE` keys
    *with or without the path prefix* — forge scripts typically
    invoke this as ``preflight(__file__)`` or
    ``preflight(Path(__file__).name)``, both of which should work.

    Returns:

    * ``0``  — every required credential is healthy.
    * ``1``  — at least one required credential is *broken* (set but
      invalid — wrong key, expired token, masked value, etc.).
    * ``2``  — at least one required credential is *missing* (not set
      anywhere we know how to check).  This is the highest-priority
      failure for forge scripts — it means the operator hasn't
      finished setup, not that a key is stale.
    * ``3``  — the health check itself failed (e.g. an exception in
      the discoverer that wasn't caught).  This is distinct from
      "the credential is broken" — it means we *couldn't determine*
      the credential's status, which is a different operational
      problem (often a network outage or a bug in a check function).

    The function prints nothing.  Callers that want a JSON report
    should call :func:`verify_credential` per name, or use the
    ``hermes secrets verify`` CLI subcommand.
    """
    # Normalise: accept "forge-vhs-report.py", "/path/to/forge-vhs-report.py",
    # and "Forge-VHS-Report.PY" (case-insensitive on the suffix).
    script_basename = script_name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    required: Optional[List[str]] = None
    for key, deps in REQUIRED_FOR_FORGE.items():
        if key.lower() == script_basename.lower():
            required = deps
            break

    if required is None:
        # Unknown script — treat as a configuration error.  Print to
        # stderr (not raise) so the calling forge script can decide
        # whether to abort or continue.  We do this with sys.stderr
        # rather than rich.Console because forge scripts are usually
        # invoked under cron where the rich terminal isn't available.
        print(
            f"[secrets_verify] preflight: unknown script {script_name!r}; "
            f"add it to REQUIRED_FOR_FORGE in hermes_cli/secrets_verify.py",
            file=sys.stderr,
        )
        return 3  # same code as "check itself failed" — operator's fault

    # Run every required check.  We could parallelise this with
    # ThreadPoolExecutor, but the credential set is small (≤3) and
    # serial keeps the function simple + easy to test.  If a forge
    # script grows dependencies past 5, revisit.
    has_missing = False
    has_broken = False
    has_unknown = False
    for name in required:
        result = _check_single_credential(name)
        status = result.get("status")
        if status == "missing":
            has_missing = True
        elif status == "broken":
            has_broken = True
        elif status == "unknown":
            has_unknown = True

    # Priority order: missing > broken > unknown > ok.  Missing is
    # most actionable ("run hermes auth add X"), broken is
    # closeable but requires a rotate, unknown means "investigate".
    if has_missing:
        return 2
    if has_broken:
        return 1
    if has_unknown:
        return 3
    return 0


# ---------------------------------------------------------------------------
# Internal: helper for the JSON-shaped per-credential report
# ---------------------------------------------------------------------------


def _verify_one(name: str) -> Dict[str, Any]:
    """Run the check for ``name`` and attach a derived exit code.

    The single-credential ``hermes secrets verify`` command needs to
    map the structured result to a doctor-style exit code so the
    caller can rely on the same 0/1/2/3 contract as ``preflight``.
    """
    result = _check_single_credential(name)
    status = result.get("status")
    if status == "ok":
        rc = 0
    elif status == "broken":
        rc = 1
    elif status == "missing":
        rc = 2
    else:  # unknown
        rc = 3
    return {"name": name, "rc": rc, **result}


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    """``hermes secrets verify`` — entry point.

    The single-credential form per the unified secrets spec (line 242-259)::

        hermes secrets verify --name ELEVENLABS_API_KEY --script

    Returns a JSON object with ``name`` / ``rc`` / ``ok`` / ``status`` /
    ``kind`` / ``detail`` / ``elapsed_seconds`` keys, and exits with
    the doctor exit code (0/1/2/3) so the caller can rely on the
    same contract as ``hermes secrets doctor``.

    The ``--script`` flag (no argument) is the spec-defined "I'm a
    forge script, give me machine-readable output" marker.  When
    ``--script`` is set, output is *always* JSON; without it, the
    default would be a human-readable table, but for Phase 3 the
    only caller is forge scripts, so JSON is the only output shape.

    The preflight (multi-credential) form is the Python API:
    ``from hermes_cli.secrets_verify import preflight; preflight("forge-vhs-report.py")``.
    Forge scripts use that directly — not the CLI.  The CLI surface
    is for *one credential at a time* because that's the per-key
    granularity the spec example at line 247-256 shows.
    """
    started = time.monotonic()

    if not getattr(args, "name", None):
        print(
            "hermes secrets verify requires --name KEY.  "
            "Run from a forge script with: "
            "hermes secrets verify --name ELEVENLABS_API_KEY --script",
            file=sys.stderr,
        )
        return 2

    result = _verify_one(args.name)
    report = {
        "name": args.name,
        "rc": result["rc"],
        "ok": result["ok"],
        "status": result["status"],
        "kind": result["kind"],
        "detail": result["detail"],
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "script_mode": bool(getattr(args, "script", False)),
    }
    print(json.dumps(report, indent=2))
    return result["rc"]


def register_cli(parent_parser: Any) -> None:
    """Attach the ``verify`` subcommand to the ``secrets`` subparsers.

    Called from ``hermes_cli.main`` after ``secrets_subparsers`` is built,
    e.g.::

        secrets_subparsers = secrets_parser.add_subparsers(dest="secrets_command")
        from hermes_cli import secrets_verify as _secrets_verify
        _secrets_verify.register_cli(secrets_subparsers)

    The args attached to the ``verify`` subparser are:

    * ``--name X``     — credential to verify (required; the spec
                          accepts any name known to
                          ``hermes secrets check --name``: LIVE_PROBES
                          keys like ELEVENLABS_API_KEY, GITHUB_TOKEN,
                          OPENROUTER_API_KEY, etc., or auth.json
                          provider / credential_pool names like
                          'xai-oauth').
    * ``--script``     — no-argument flag: "I'm a forge script, give
                          me machine-readable JSON" (per spec line
                          259).  When set, output is JSON.  When
                          absent, output is JSON anyway in Phase 3
                          (the only caller is forge scripts).  Kept
                          for spec compatibility and Phase 4 expansion
                          (a future human-readable table mode).
    """
    verify = parent_parser.add_parser(
        "verify",
        help="Verify a single credential (Phase 3 forge-queue hook)",
        description=(
            "Verify a single credential by name.  Returns a JSON object "
            "with the credential status and exits with the doctor exit "
            "code (0=ok, 1=broken, 2=missing, 3=check itself failed).  "
            "Use --script to mark the invocation as coming from a forge "
            "script (spec line 259: machine-readable output).  "
            "For multi-credential preflight, import the Python API: "
            "from hermes_cli.secrets_verify import preflight; "
            "preflight('forge-vhs-report.py')."
        ),
    )
    verify.add_argument(
        "--name", metavar="KEY", required=True,
        help=(
            "Single credential to verify.  Accepts any name known to "
            "hermes secrets check (LIVE_PROBES keys like ELEVENLABS_API_KEY, "
            "GITHUB_TOKEN, OPENROUTER_API_KEY, etc.) or auth.json provider / "
            "credential_pool names like 'xai-oauth'."
        ),
    )
    verify.add_argument(
        "--script", action="store_true",
        help=(
            "Mark this invocation as coming from a forge script.  "
            "Currently a no-op for output shape (always JSON in Phase 3) "
            "but kept for spec compatibility and future human-readable "
            "table mode (Phase 4)."
        ),
    )
    verify.set_defaults(func=cmd_verify)
