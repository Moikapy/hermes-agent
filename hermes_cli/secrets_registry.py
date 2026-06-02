"""Unified inventory of Hermes credentials — ``hermes secrets status``.

Phase 1 of the unified secrets plan (``~/.hermes/plans/hermes-secrets-unified-spec.md``).

Provides a typed :class:`CredentialEntry` and a :class:`CredentialRegistry`
that walks each known source (Phase 1: ``env`` + ``sops_file``) and returns
a deduped inventory.  OAuth providers, the credential pool, and wrangler
targets are out of scope for Phase 1 (see spec Phase 2/3).

Design constraints (per ``03-RESOURCES/Research/notes-Research/2026-06-01-secrets-registry-phase1.md``):

* **Profile-aware paths** — every method accepts ``profile: str = "default"``
  and resolves paths via :func:`hermes_constants.get_hermes_home` plus the
  existing :func:`hermes_cli.secrets_sops._secrets_file` helper.  No
  hard-coded ``~/.hermes`` strings.
* **Reuse, don't duplicate** — sops decrypt calls go through the existing
  ``_secrets_file`` and ``_sops_env`` helpers so profile rotation and the
  age-key file location stay correct.
* **Read-only** — the registry never writes to any credential store,
  .env, or sops file.
* **Stable fingerprint** — :func:`CredentialEntry.fingerprint` is the
  sha256 of ``name|source|path|key``, matching the spec at line 108.
* **Surgical** — does not import or modify ``secrets_health.py``.  That
  module's ad-hoc discovery is left in place for Phase 2 migration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml
from dotenv import dotenv_values
from rich.console import Console
from rich.table import Table

# Profile-aware path resolution — the single source of truth for "~/.hermes".
from hermes_constants import get_hermes_home

# Reuse the sops helpers so age-key lookup and HERMES_HOME handling are
# identical to `hermes secrets sops get`.  These are private helpers
# (leading underscore) but the research plan explicitly approved reuse.
from hermes_cli.secrets_sops import _secrets_file, _sops_env

console = Console()


# ---------------------------------------------------------------------------
# Data model (verbatim from the spec at lines 65-78)
# ---------------------------------------------------------------------------

# Literal types are kept narrow on purpose: extending the source union
# (e.g. for OAuth in Phase 2) is a one-line change and forces every
# discoverer to be reviewed.
Source = Literal[
    "env",
    "auth_json_providers",
    "auth_json_pool",
    "sops_file",
    "wrangler_toml",
    "wrangler_secret",
]

Kind = Literal["api_key", "oauth", "sops_secret", "wrangler_var"]


@dataclass
class CredentialEntry:
    """A single credential Hermes knows about.

    See spec lines 65-78.  ``required_by`` defaults to an empty list
    rather than ``None`` so the JSON dump is predictable.
    """

    name: str
    kind: Kind
    source: Source
    path: str
    key: Optional[str]
    required_by: List[str] = field(default_factory=list)
    expires_at: Optional[str] = None  # ISO 8601; None means "never"
    last_verified: Optional[str] = None
    last_health_status: str = "unknown"
    notes: str = ""

    def fingerprint(self) -> str:
        """Stable sha256 over the (name, source, path, key) tuple.

        Spec line 108: "Discovered entries get a stable fingerprint
        (sha256 of name+source+path+key) so we can track them across
        runs in a ~/.hermes/secrets-registry.json cache."  Caching is
        deferred to Phase 2, but the fingerprint is defined now so
        callers can compute it from day one.
        """
        h = hashlib.sha256()
        h.update(self.name.encode("utf-8"))
        h.update(b"|")
        h.update(self.source.encode("utf-8"))
        h.update(b"|")
        h.update(self.path.encode("utf-8"))
        h.update(b"|")
        h.update((self.key or "").encode("utf-8"))
        return h.hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class CredentialRegistry:
    """Discover every credential Hermes knows about for ``profile``.

    Phase 1 implements :meth:`discover_env_keys` and
    :meth:`discover_sops_entries`.  The other discoverers from the
    spec skeleton are deliberately omitted — they belong to Phase 2/3
    and adding stubs now would lock in signatures before the OAuth
    schema is settled.
    """

    def __init__(self, profile: str = "default") -> None:
        self.profile = profile
        self.entries: List[CredentialEntry] = []

    # ----- env discoverer ------------------------------------------------

    def discover_env_keys(self) -> List[CredentialEntry]:
        """Walk ``~/.hermes/.env`` (and profile overlay) and emit one entry per key.

        Hermes profiles fake-home under ``~/.hermes/profiles/<p>/home``,
        so :func:`get_hermes_home` is the right anchor for path resolution
        — it transparently handles HERMES_HOME and the active-profile
        fallback warning (see hermes_constants.py).

        We use :func:`dotenv.dotenv_values` rather than parsing the file
        ourselves so quoted values, comments, and ``export`` prefixes are
        handled identically to ``secrets_health.py``.
        """
        hermes_home = get_hermes_home()
        env_path = hermes_home / ".env"

        if not env_path.exists():
            return []

        try:
            values = dotenv_values(env_path) or {}
        except (OSError, UnicodeDecodeError) as exc:
            console.print(
                f"[yellow]Warning:[/yellow] could not read {env_path}: {exc}"
            )
            return []

        entries: List[CredentialEntry] = []
        for name in sorted(values.keys()):
            entries.append(
                CredentialEntry(
                    name=name,
                    kind="api_key",
                    source="env",
                    path=str(env_path),
                    key=name,
                    notes="loaded from dotenv",
                )
            )
        return entries

    # ----- sops discoverer -----------------------------------------------

    def discover_sops_entries(self) -> List[CredentialEntry]:
        """Decrypt the profile's ``secrets.enc.yaml`` and emit one entry per leaf.

        Reuses :func:`_secrets_file` so profile resolution matches every
        other sops command.  Decryption is delegated to the sops binary
        via the same subprocess shape used by :mod:`secrets_sops` and
        :mod:`secrets_health`; a failure here is reported as zero
        entries (the file is optional per-profile).
        """
        sops_path = _secrets_file(self.profile)
        if not sops_path.exists():
            return []

        try:
            result = subprocess.run(
                [
                    "sops",
                    "-d",
                    "--input-type",
                    "yaml",
                    "--output-type",
                    "yaml",
                    str(sops_path),
                ],
                capture_output=True,
                text=True,
                timeout=15,
                env=_sops_env(),
            )
        except FileNotFoundError:
            console.print(
                "[yellow]Warning:[/yellow] sops binary not on PATH; "
                "skipping sops discovery"
            )
            return []
        except subprocess.TimeoutExpired:
            console.print(
                f"[yellow]Warning:[/yellow] sops decrypt timed out for {sops_path}"
            )
            return []

        if result.returncode != 0:
            console.print(
                f"[yellow]Warning:[/yellow] sops decrypt failed for {sops_path}: "
                f"{(result.stderr or '').strip()[:200]}"
            )
            return []

        try:
            data = yaml.safe_load(result.stdout) or {}
        except yaml.YAMLError as exc:
            console.print(
                f"[yellow]Warning:[/yellow] decrypted YAML is invalid for "
                f"{sops_path}: {exc}"
            )
            return []

        entries: List[CredentialEntry] = []
        for dotted in _walk_yaml_leaves(data):
            entries.append(
                CredentialEntry(
                    name=dotted,
                    kind="sops_secret",
                    source="sops_file",
                    path=str(sops_path),
                    key=dotted,
                    notes="decrypted via sops",
                )
            )
        return entries

    # ----- aggregator ----------------------------------------------------

    def all(self) -> List[CredentialEntry]:
        """Run all Phase 1 discoverers and return the merged, deduped inventory.

        Dedup uses :meth:`CredentialEntry.fingerprint`.  For Phase 1 there
        should be no overlap (env keys and sops keys live in disjoint
        namespaces), but the dedup is in place so Phase 2 OAuth additions
        don't have to revisit the merge step.
        """
        discovered: List[CredentialEntry] = []
        discovered.extend(self.discover_env_keys())
        discovered.extend(self.discover_sops_entries())

        seen: set = set()
        merged: List[CredentialEntry] = []
        for entry in discovered:
            fp = entry.fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            merged.append(entry)
        self.entries = merged
        return merged


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _walk_yaml_leaves(data: Any, prefix: str = "") -> List[str]:
    """Return the dotted paths of every non-dict leaf under ``data``.

    Mirrors the ``walk`` closure inside ``secrets_health._discover_sops_entries``
    but lifted to a module-level function so the registry is self-contained.
    """
    leaves: List[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            cur = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                leaves.extend(_walk_yaml_leaves(v, cur))
            else:
                leaves.append(cur)
    return leaves


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _format_status(entry: CredentialEntry) -> str:
    """Map an entry to the ``STATUS`` column string used by the spec example.

    Phase 1 has no live probes in the registry, so every discovered entry
    starts as ``"unknown"`` (matching the xAI / ollama-cloud rows in the
    spec example at line 191-194).  Sops entries that decrypted cleanly
    get ``"ok"`` because that is a strong signal the value is reachable.
    Env keys whose value masks (``***``) get ``"masked"``, matching
    ``secrets_health.check_env_key`` semantics.
    """
    if entry.source == "sops_file":
        return "[green]ok[/green]"
    if entry.source == "env" and entry.key:
        # Best-effort: peek at the dotenv value (without exposing it)
        # and surface the known Hermes-mask failure mode.
        try:
            values = dotenv_values(entry.path) or {}
        except (OSError, UnicodeDecodeError):
            values = {}
        v = values.get(entry.key, "")
        if v is None or v == "":
            return "[red]missing[/red]"
        if isinstance(v, str) and v.startswith("***"):
            return "[yellow]masked[/yellow]"
        return "[green]ok[/green]"
    return "[dim]unknown[/dim]"


def _format_expires(entry: CredentialEntry) -> str:
    """Map ``expires_at`` to the table column.  Phase 1 has no OAuth, so it's always ``never``/``-``."""
    if entry.expires_at:
        return entry.expires_at
    if entry.source == "sops_file":
        return "-"
    return "never"


def _format_last_checked(entry: CredentialEntry) -> str:
    return entry.last_verified or "never"


def _render_table(entries: List[CredentialEntry], profile: str) -> None:
    """Print the spec-shaped table (lines 176-199)."""
    # Column widths sized to fit the spec example (lines 176-199) without
    # Rich's default truncation.  NAME is the widest column because env
    # keys can be long (e.g. SIGNAL_HOME_CHANNEL_THREAD_ID is 31 chars).
    # KIND is 12 wide so the ``sops_secret`` literal isn't truncated.
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("NAME", style="cyan", no_wrap=True, min_width=24)
    table.add_column("KIND", min_width=12)
    table.add_column("SOURCE", min_width=10)
    table.add_column("STATUS", min_width=10)
    table.add_column("EXPIRES", justify="right", min_width=10)
    table.add_column("LAST_CHECKED", justify="right", min_width=10)
    for e in entries:
        table.add_row(
            e.name,
            e.kind,
            e.source,
            _format_status(e),
            _format_expires(e),
            _format_last_checked(e),
        )
    console.print(table)
    n = len(entries)
    if n == 0:
        console.print(f"\n  [dim]No credentials discovered for profile {profile!r}.[/dim]")
    else:
        console.print(
            f"\n  Total: {n} credential{'s' if n != 1 else ''} for profile {profile!r}"
        )


def _render_json(entries: List[CredentialEntry], profile: str, elapsed: float) -> None:
    """Print machine-readable JSON; matches the spec's --json contract."""
    payload = {
        "profile": profile,
        "elapsed_seconds": round(elapsed, 3),
        "count": len(entries),
        "entries": [e.to_dict() for e in entries],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def _effective_profile(args: argparse.Namespace) -> str:
    """Resolve the profile name to display, in priority order.

    The top-level ``--profile`` is consumed by ``_apply_profile_override``
    *before* argparse sees it (see hermes_cli/main.py around line 256), so
    our subparser's ``args.profile`` is always ``None`` when the user
    passed the top-level flag.  The top-level override sets
    ``HERMES_HOME`` to a profile-specific path, which we use to derive
    the display name.

    Priority:

    1. ``args.profile`` — if the user passed the subparser flag (rarely
       useful, but supported for spec consistency)
    2. The trailing path component of ``HERMES_HOME`` when it points to
       a profile directory (e.g. ``.../profiles/sund``)
    3. The active profile from ``<root>/active_profile`` if non-default
    4. The literal string ``"default"``
    """
    explicit = getattr(args, "profile", None)
    if explicit:
        return explicit
    # HERMES_HOME profile detection
    hermes_home = os.environ.get("HERMES_HOME", "")
    if hermes_home:
        p = Path(hermes_home)
        if p.parent.name == "profiles" and p.name:
            return p.name
    # active_profile file fallback
    try:
        from hermes_constants import get_default_hermes_root
        active_path = get_default_hermes_root() / "active_profile"
        if active_path.exists():
            name = active_path.read_text().strip()
            if name:
                return name
    except (OSError, UnicodeDecodeError):
        pass
    return "default"


def cmd_status(args: argparse.Namespace) -> int:
    """``hermes secrets status`` — entry point.  Read-only inventory."""
    started = time.monotonic()
    profile = _effective_profile(args)
    registry = CredentialRegistry(profile=profile)
    entries = registry.all()
    elapsed = time.monotonic() - started

    if getattr(args, "json", False):
        _render_json(entries, profile, elapsed)
    else:
        _render_table(entries, profile)

    return 0


def register_cli(parent_parser: Any) -> None:
    """Attach the ``status`` subcommand to the ``secrets`` subparsers.

    Mirrors :func:`secrets_health.register_cli`: called from
    :mod:`hermes_cli.main` after ``secrets_subparsers`` is built.

    Args:

    * ``--profile PROFILE``  — profile to inspect (default: ``default``)
    * ``--json``             — emit machine-readable JSON
    """
    status = parent_parser.add_parser(
        "status",
        help="Unified credential inventory (read-only)",
        description=(
            "Inventory every credential Hermes knows about for the "
            "given profile: env keys, sops entries, and (in later "
            "phases) OAuth providers, credential pool entries, and "
            "wrangler targets.  Read-only — never writes to any "
            "credential store."
        ),
    )
    status.add_argument(
        "--profile",
        metavar="PROFILE",
        help="Hermes profile to inspect (default: 'default')",
    )
    status.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output for machine consumption",
    )
    status.set_defaults(func=cmd_status)
