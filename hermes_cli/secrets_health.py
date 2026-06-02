"""Health checks for Hermes secrets — ``hermes secrets check``.

Phase 1 of the unified secrets plan. Provides read-only probes that
report whether each known API key is configured and still working,
without mutating any stored credentials.

Four check functions:

* ``check_api_key_live(entry)``  — async; hits the provider's lightweight
  endpoint with the actual key.  This is the one that catches xAI-style
  "the key is set but the auth flow is broken" failures.
* ``check_env_key(entry)``       — reads the key from ``os.environ`` AND
  ``dotenv_values`` because Hermes masks env via ``os.environ`` for
  child processes and a ``***`` value is a real failure mode (see
  vhs-preflight.py / resolve_elevenlabs_key).
* ``check_sops_entry(entry)``    — runs ``sops -d`` on the secrets file
  and verifies the target key exists and decrypts cleanly.

Parallel execution of the live probes uses a thread pool capped at 8
so the full check completes within the 10s budget.

Read-only.  Never writes keys, env vars, or files.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
from dotenv import dotenv_values
from rich.console import Console
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

console = Console()

# Default Hermes env path.  Hermes profiles fake-home under
# ``~/.hermes/profiles/<p>/home`` so a naive ``Path.home()`` would point
# at the profile directory and miss the real root .env.  Use the same
# pattern as secrets_sops._real_home() to find the actual user home.
def _real_home() -> Path:
    """Return the real user home directory, bypassing profile fake homes."""
    home = os.environ.get("HOME", "")
    if home and "/.hermes/profiles/" in home:
        idx = home.find("/.hermes/profiles/")
        if idx != -1:
            return Path(home[:idx])
    return Path(home).expanduser() if home else Path("~").expanduser()


DEFAULT_ENV_PATH = _real_home() / ".hermes" / ".env"

# Per-service probe table from the unified secrets spec (Phase 1).
# (url, method, timeout_seconds)
LIVE_PROBES: Dict[str, Tuple[str, str, int]] = {
    "ELEVENLABS_API_KEY":  ("https://api.elevenlabs.io/v1/voices",      "GET", 5),
    "FAL_KEY":             ("https://fal.run/health",                   "GET", 5),
    "FIRECRAWL_API_KEY":   ("https://api.firecrawl.dev/v1/health",      "GET", 5),
    "OPENROUTER_API_KEY":  ("https://openrouter.ai/api/v1/models",      "GET", 5),
    "GITHUB_TOKEN":        ("https://api.github.com/user",              "GET", 5),
    "XAI_API_KEY":         ("https://api.x.ai/v1/api-key",              "GET", 5),
    "MCP_OBSIDIAN_API_KEY":("http://localhost:27124/",                  "GET", 5),
    "OPUS_API_KEY":        ("https://api.opus.com/v1/health",          "GET", 5),
}

# Auth scheme per service.  ``None`` means no auth header is sent
# (the endpoint is public and we're just checking reachability).
# ``"bearer"`` sends ``Authorization: Bearer <key>``.
# ``"xi-api-key"`` is ElevenLabs' custom header.
_AUTH_SCHEME: Dict[str, Optional[str]] = {
    "ELEVENLABS_API_KEY":  "xi-api-key",
    "FAL_KEY":             "fal-key",       # FAL: "Key <key>" (see fal.run docs)
    "FIRECRAWL_API_KEY":   "bearer",
    "OPENROUTER_API_KEY":  "bearer",
    "GITHUB_TOKEN":        "bearer",
    "XAI_API_KEY":         "bearer",
    "MCP_OBSIDIAN_API_KEY":"bearer",
    "OPUS_API_KEY":        "bearer",
}

# Custom header builder for services that don't use plain Bearer.
def _build_auth_header(scheme: Optional[str], key: str) -> Dict[str, str]:
    if not scheme:
        return {}
    if scheme == "bearer":
        return {"Authorization": f"Bearer {key}"}
    if scheme == "xi-api-key":
        return {"xi-api-key": key}
    if scheme == "fal-key":
        return {"Authorization": f"Key {key}"}
    return {}


# ---------------------------------------------------------------------------
# Env-path discovery (Hermes-aware)
# ---------------------------------------------------------------------------

def _env_paths() -> List[Path]:
    """Return candidate .env files in priority order.

    Hermes profiles fake-home under ``~/.hermes/profiles/<p>/home``, so
    the real root .env is the one to consult for credentials that any
    profile may rely on.
    """
    candidates: List[Path] = []
    explicit = os.environ.get("HERMES_ENV_PATH")
    if explicit:
        candidates.append(Path(explicit))
    # Profile-specific .env (when invoked under a profile)
    real = _real_home()
    profile_env = real / ".env"
    candidates.append(profile_env)
    # The default location
    candidates.append(DEFAULT_ENV_PATH)
    # Dedupe, preserve order, drop missing
    seen: set = set()
    out: List[Path] = []
    for p in candidates:
        rp = p.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        if p.exists():
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_env_key(entry: Dict[str, Any]) -> Tuple[bool, str]:
    """Read the key from ``os.environ`` AND ``dotenv_values``.

    Hermes masks env vars for child processes (returns ``***``), so a
    key that exists in ``~/.hermes/.env`` may appear as ``***`` to
    anything that goes through ``os.environ`` — but ``dotenv_values``
    bypasses the mask and returns the real value.  We check both and
    flag the masked case as a failure because it's a known source of
    silent breakage (see vhs-preflight.py).

    Returns ``(ok, detail)``.  ``ok`` is True iff the key resolves to a
    non-empty, non-masked value.
    """
    name = entry.get("name", "")
    if not name:
        return False, "entry missing 'name'"

    # 1. dotenv_values — bypasses Hermes env masking
    dotenv_val: Optional[str] = None
    dotenv_source: Optional[str] = None
    for env_path in _env_paths():
        values = dotenv_values(env_path) or {}
        if name in values:
            dotenv_val = values.get(name)
            dotenv_source = str(env_path)
            break

    # 2. os.environ — what child processes actually see
    env_val = os.environ.get(name)

    # Prefer the dotenv value (the source of truth); if absent, fall
    # back to whatever os.environ has.
    val = dotenv_val if dotenv_val is not None else env_val
    source = dotenv_source or ("os.environ" if env_val is not None else "<missing>")

    if val is None or val == "":
        return False, f"{name} not set in any of: dotenv, os.environ"
    if val.startswith("***"):
        return False, (
            f"{name} is masked ('{val}') — Hermes env masking is in effect; "
            f"key may exist in {source} but is hidden to subprocesses"
        )
    # Hermes sometimes replaces masked values with named placeholders
    # (e.g. 'xai-PLACEHOLDER').  These pass the explicit *** check
    # but won't actually authenticate — flag them too.
    if any(s in val.upper() for s in ("PLACEHOLDER", "MASKED", "REDACTED", "XXXXX")):
        return False, (
            f"{name} is a placeholder value ('{val}') — not a real key"
        )
    return True, f"{name} loaded from {source} ({len(val)} chars)"


def check_sops_entry(entry: Dict[str, Any]) -> Tuple[bool, str]:
    """sops decrypt + verify the entry's target key exists.

    ``entry`` must have ``path`` (absolute path to the encrypted file)
    and ``key`` (dotted YAML path, e.g. ``api_keys.kapy_content_api``).

    Returns ``(ok, detail)``.  Read-only — the decrypted file is held
    in memory only, never written to disk.
    """
    path = entry.get("path")
    key = entry.get("key")
    if not path or not key:
        return False, "sops entry requires 'path' and 'key'"
    p = Path(path)
    if not p.exists():
        return False, f"sops file not found: {p}"
    # Build an env that points sops at the real home (the real age key
    # lives under ~/.config/sops/age/keys.txt — not the profile-faked
    # home).  Same pattern as hermes_cli.secrets_sops._sops_env().
    real = str(_real_home())
    sops_env = dict(os.environ)
    sops_env["HOME"] = real
    sops_env["SOPS_AGE_KEY_FILE"] = str(real) + "/.config/sops/age/keys.txt"
    try:
        result = subprocess.run(
            ["sops", "-d", "--input-type", "yaml", "--output-type", "yaml", str(p)],
            capture_output=True, text=True, timeout=15, env=sops_env,
        )
    except FileNotFoundError:
        return False, "sops binary not on PATH (install: https://github.com/getsops/sops)"
    except subprocess.TimeoutExpired:
        return False, f"sops decrypt timed out after 15s for {p}"
    if result.returncode != 0:
        return False, f"sops decrypt failed: {(result.stderr or '').strip()[:200]}"

    try:
        data = yaml.safe_load(result.stdout) or {}
    except yaml.YAMLError as exc:
        return False, f"decrypted YAML is invalid: {exc}"

    # dotted-path navigation
    cur: Any = data
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False, f"key '{key}' not present in {p.name} (missing at '{part}')"
        cur = cur[part]
    if cur in (None, ""):
        return False, f"key '{key}' in {p.name} is empty"
    return True, f"sops entry '{key}' decrypted from {p.name}"


def check_api_key_live(entry: Dict[str, Any]) -> Tuple[bool, str]:
    """Async-ish live probe: hit the provider's lightweight endpoint.

    Synchronous on the inside (called via a thread pool).  Named
    ``_async`` in the spec docstring; we expose it as a regular function
    because ``requests`` is blocking and the parallelism comes from
    the executor, not the function itself.

    ``entry`` requires ``name`` (one of the LIVE_PROBES keys).  The
    secret value is resolved from ``dotenv_values`` first, then
    ``os.environ`` — exactly the pattern documented in the spec.

    Returns ``(ok, detail)``.  Read-only.
    """
    name = entry.get("name", "")
    if name not in LIVE_PROBES:
        return False, f"no live probe defined for {name!r}"

    url, method, timeout = LIVE_PROBES[name]

    # Resolve the secret value
    secret: Optional[str] = None
    for env_path in _env_paths():
        values = dotenv_values(env_path) or {}
        if values.get(name):
            secret = values[name]
            break
    if secret is None:
        secret = os.environ.get(name)
    if not secret:
        return False, f"{name} not set — cannot probe"
    if secret.startswith("***"):
        return False, f"{name} is masked ('{secret}') — cannot probe"

    scheme = _AUTH_SCHEME.get(name)
    headers = _build_auth_header(scheme, secret)

    try:
        resp = requests.request(method, url, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        return False, f"timeout after {timeout}s hitting {url}"
    except requests.exceptions.ConnectionError as exc:
        return False, f"connection error to {url}: {str(exc).splitlines()[0][:200]}"
    except requests.exceptions.RequestException as exc:
        return False, f"request error: {exc}"

    # Status interpretation
    if resp.status_code in (200, 204):
        # Try to surface a useful snippet
        snippet = ""
        try:
            body = resp.json()
            if isinstance(body, dict):
                if "voices" in body:
                    snippet = f", {len(body['voices'])} voices visible"
                elif "data" in body and isinstance(body["data"], list):
                    snippet = f", {len(body['data'])} items"
                elif "id" in body:
                    snippet = f", user={body.get('login') or body.get('id')}"
        except (ValueError, json.JSONDecodeError):
            pass
        return True, f"{resp.status_code} {url}{snippet}"

    if resp.status_code in (401, 403):
        return False, f"auth rejected ({resp.status_code}) by {url}"
    if resp.status_code == 404:
        return False, f"endpoint not found ({resp.status_code}) at {url}"
    if resp.status_code == 429:
        return False, f"rate limited ({resp.status_code}) at {url}"
    # 5xx — server-side problem; not a key issue, but report it
    return False, f"unexpected status {resp.status_code} from {url}: {(resp.text or '')[:120]}"


# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------

def _run_checks_parallel(
    entries: List[Dict[str, Any]],
    *,
    kind: str = "env",
    check_func=None,
    max_workers: int = 8,
) -> List[Dict[str, Any]]:
    """Run ``check_func(entry)`` for each entry in a thread pool.

    ``kind`` is the check label used in the result table; ``check_func``
    is one of the three check functions above.
    """
    if check_func is None:
        check_func = check_env_key

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(entries)))) as ex:
        future_to_entry = {ex.submit(check_func, e): e for e in entries}
        # Preserve input order in the output
        by_entry = {id(e): {"entry": e, "result": None} for e in entries}
        for fut in as_completed(future_to_entry):
            entry = future_to_entry[fut]
            try:
                ok, detail = fut.result()
            except Exception as exc:  # noqa: BLE001
                ok, detail = False, f"check raised: {exc}"
            by_entry[id(entry)]["result"] = (ok, detail)

    for e in entries:
        ok, detail = by_entry[id(e)]["result"]
        results.append({
            "name": e.get("name", "?"),
            "kind": kind,
            "ok": bool(ok),
            "detail": detail,
        })
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _discover_sops_entries(profile: Optional[str] = None) -> List[Dict[str, Any]]:
    """Walk a profile's secrets.enc.yaml and return one entry per leaf.

    Each entry has ``name=<dotted.path>``, ``path=<file>``, ``key=<dotted.path>``.
    Returns an empty list if no sops file exists (sops is opt-in per profile).
    """
    # Reuse secrets_sops's path resolver so the profile resolution is
    # consistent with `hermes secrets sops get`.
    try:
        from hermes_cli.secrets_sops import _secrets_file, _sops_env
    except ImportError:
        return []
    p = _secrets_file(profile)
    if not p.exists():
        return []
    try:
        result = subprocess.run(
            ["sops", "-d", "--input-type", "yaml", "--output-type", "yaml", str(p)],
            capture_output=True, text=True, timeout=15, env=_sops_env(),
        )
        if result.returncode != 0:
            return []
        data = yaml.safe_load(result.stdout) or {}
    except Exception:
        return []

    def walk(d, prefix=""):
        out = []
        if isinstance(d, dict):
            for k, v in d.items():
                cur = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    out.extend(walk(v, cur))
                else:
                    out.append(cur)
        return out

    leaves = walk(data)
    return [{"name": k, "path": str(p), "key": k} for k in leaves]


def _build_entries(
    name: Optional[str],
    include_sops: bool = False,
    profile: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return the list of ``entry`` dicts the checks will run against.

    ``--name X``     → single LIVE_PROBES entry
    default         → every LIVE_PROBES key
    ``--sops``       → also include one entry per leaf key in the
                      profile's secrets.enc.yaml (requires sops)
    """
    entries: List[Dict[str, Any]] = []
    if name:
        if name not in LIVE_PROBES:
            console.print(f"[red]Unknown key: {name}[/red]")
            console.print(f"  Known: {', '.join(sorted(LIVE_PROBES))}")
            sys.exit(2)
        entries.append({"name": name, "kind": "api_key_live"})
    else:
        for k in sorted(LIVE_PROBES):
            entries.append({"name": k, "kind": "api_key_live"})

    if include_sops:
        sops_entries = _discover_sops_entries(profile)
        for e in sops_entries:
            entries.append({**e, "kind": "sops"})
    return entries


def cmd_check(args: argparse.Namespace) -> int:
    """``hermes secrets check`` — entry point."""
    started = time.monotonic()
    entries = _build_entries(
        args.name,
        include_sops=bool(getattr(args, "sops", False)),
        profile=getattr(args, "profile", None),
    )

    if not entries:
        console.print("[yellow]Nothing to check.[/yellow]")
        return 0

    # Split entries by kind — env/live probes only apply to api_key_live
    # entries; sops entries go through check_sops_entry.
    api_entries = [e for e in entries if e.get("kind") != "sops"]
    sops_entries = [e for e in entries if e.get("kind") == "sops"]

    if args.offline or not api_entries:
        # Offline: env-only; sops entries are skipped in offline mode
        # (they require reading the encrypted file which is a separate
        # concern from "is the key set")
        results = _run_checks_parallel(
            api_entries, kind="env", check_func=check_env_key,
        ) if api_entries else []
        if sops_entries:
            for e in sops_entries:
                results.append({
                    "name": e.get("name", "?"), "kind": "sops",
                    "ok": True, "detail": "skipped (--offline)",
                })
    else:
        # 1. env checks (parallel)
        env_results = _run_checks_parallel(
            api_entries, kind="env", check_func=check_env_key,
        ) if api_entries else []
        # 2. live probes for keys whose env check passed
        eligible = [e for e, r in zip(api_entries, env_results) if r["ok"]]
        live_results = _run_checks_parallel(
            eligible, kind="live", check_func=check_api_key_live,
        ) if eligible else []
        # 3. merge: live result preferred when available
        live_by_name = {r["name"]: r for r in live_results}
        results = []
        for env_r in env_results:
            live_r = live_by_name.get(env_r["name"])
            results.append(live_r if live_r is not None else env_r)
        # 4. sops checks (also parallel, but separate pool)
        if sops_entries:
            sops_results = _run_checks_parallel(
                sops_entries, kind="sops", check_func=check_sops_entry,
            )
            results.extend(sops_results)
        # Preserve order: api entries first, sops entries last
        api_names = [e["name"] for e in api_entries]
        sops_names = [e["name"] for e in sops_entries]
        full_order = api_names + sops_names
        results.sort(key=lambda r: full_order.index(r["name"])
                     if r["name"] in full_order else 999)

    elapsed = time.monotonic() - started

    # Output
    if args.json:
        out = {
            "elapsed_seconds": round(elapsed, 3),
            "offline": bool(args.offline),
            "results": results,
            "summary": {
                "total": len(results),
                "ok": sum(1 for r in results if r["ok"]),
                "failed": sum(1 for r in results if not r["ok"]),
            },
        }
        print(json.dumps(out, indent=2))
    else:
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("KEY", style="cyan", no_wrap=True)
        table.add_column("KIND")
        table.add_column("STATUS")
        table.add_column("DETAIL")
        for r in results:
            mark = "[green]✓ ok[/green]" if r["ok"] else "[red]✗ fail[/red]"
            table.add_row(r["name"], r["kind"], mark, r["detail"])
        console.print(table)
        ok_n = sum(1 for r in results if r["ok"])
        fail_n = len(results) - ok_n
        console.print(
            f"\n  {ok_n}/{len(results)} ok"
            + (f", {fail_n} failed" if fail_n else "")
            + f"   ({elapsed:.2f}s)"
        )

    # Exit code: 0 if all ok, 1 if any fail.
    # NOTE: hermes_cli.main discards the return value of args.func(args),
    # so we must call sys.exit() directly here to surface the rc to the
    # shell.  The same pattern is used by other secrets commands.
    rc = 0 if all(r["ok"] for r in results) else 1
    if rc != 0:
        sys.exit(rc)
    return rc


def register_cli(parent_parser: Any) -> None:
    """Attach the ``check`` subcommand to the ``secrets`` subparsers.

    Called from ``hermes_cli.main`` after ``secrets_subparsers`` is built,
    e.g.::

        secrets_subparsers = secrets_parser.add_subparsers(dest="secrets_command")
        from hermes_cli import secrets_health as _secrets_health
        _secrets_health.register_cli(secrets_subparsers)

    The args attached to the ``check`` subparser are:

    * ``--name X``     — check a single key
    * ``--all``        — check all known API keys (default behaviour in Phase 1)
    * ``--offline``    — skip live probes; only check env presence
    * ``--json``       — emit machine-readable JSON
    """
    check = parent_parser.add_parser(
        "check",
        help="Health-check API keys (live probes + env presence)",
        description=(
            "Run read-only health checks against known API keys.  "
            "By default every key in LIVE_PROBES is checked in parallel: "
            "first we verify the key resolves in env/dotenv, then we send a "
            "lightweight authenticated probe to the provider.  "
            "Use --offline to skip the live probes."
        ),
    )
    check.add_argument(
        "--name", metavar="KEY",
        help=f"Check a single key (one of: {', '.join(sorted(LIVE_PROBES))})",
    )
    check.add_argument(
        "--all", action="store_true",
        help="Check every key in LIVE_PROBES (default in Phase 1)",
    )
    check.add_argument(
        "--offline", action="store_true",
        help="Skip live probes; only verify env presence",
    )
    check.add_argument(
        "--json", action="store_true",
        help="Emit JSON output for machine consumption",
    )
    check.add_argument(
        "--sops", action="store_true",
        help="Also verify SOPS entries in the profile's secrets.enc.yaml",
    )
    check.add_argument(
        "--profile", metavar="PROFILE",
        help="Hermes profile (default: current). Used with --sops.",
    )
    check.set_defaults(func=cmd_check)
