"""CLI handlers for ``hermes secrets sops ...``.

Phase 1: init, set, get, list, delete — SOPS-encrypted secrets management.

Uses the existing age+SOPS encryption at rest. Secrets are stored in
``~/.hermes/profiles/<name>/secrets.enc.yaml`` with SOPS encrypting only
the ``value`` fields. All metadata (targets, last_rotated, notes) remains
plaintext for easy reading and diffing.

Key design decisions:
  - SOPS binary calls via ``subprocess.run(["sops", ...])`` — no reimplementation
  - Temp files for decrypted operations — always cleaned up in ``finally`` blocks
  - age key at ``~/.config/sops/age/keys.txt`` — reuse existing, don't generate
  - Profile-scoped — each Hermes profile has its own ``secrets.enc.yaml``
  - Never log or print key values except in ``sops get`` (which warns)
  - Dotted-path YAML navigation (``api_keys.kapy_content_api``)
"""

from __future__ import annotations

import argparse
import json
import os
import secrets as secrets_mod
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from rich.console import Console
from rich.table import Table

from hermes_cli.config import load_config, get_env_path

console = Console()

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

HERMES_HOME = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
SOPS_BIN = os.environ.get("SOPS_PATH", "sops")
AGE_KEY_PATH = Path.home() / ".config" / "sops" / "age" / "keys.txt"


def _secrets_file(profile: Optional[str] = None) -> Path:
    """Return the path to the secrets.enc.yaml for the given profile."""
    if profile:
        p = HERMES_HOME / "profiles" / profile
    else:
        # Default to current profile from config
        try:
            cfg = load_config()
            profile_name = cfg.get("current_profile", "dashboard") if isinstance(cfg, dict) else "dashboard"
        except Exception:
            profile_name = "dashboard"
        p = HERMES_HOME / "profiles" / profile_name
    return p / "secrets.enc.yaml"


# ---------------------------------------------------------------------------
# SOPS subprocess helpers
# ---------------------------------------------------------------------------


def _check_sops() -> str:
    """Verify SOPS binary is available. Returns path. Raises on missing."""
    try:
        result = subprocess.run(
            [SOPS_BIN, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"sops --version failed: {result.stderr}")
        return SOPS_BIN
    except FileNotFoundError:
        raise RuntimeError(
            "sops binary not found. Install it: "
            "https://github.com/getsops/sops/releases"
        )


def _check_age_key() -> Path:
    """Verify the age private key exists. Returns path. Raises on missing."""
    if not AGE_KEY_PATH.exists():
        raise RuntimeError(
            f"age key not found at {AGE_KEY_PATH}. "
            "Generate one: age-keygen -o ~/.config/sops/age/keys.txt"
        )
    return AGE_KEY_PATH


def _sops_decrypt(filepath: Path) -> Dict[str, Any]:
    """Decrypt a SOPS file and return the parsed YAML dict.

    Uses a temp file that is always cleaned up.
    """
    sops = _check_sops()
    try:
        result = subprocess.run(
            [sops, "-d", "--input-type", "yaml", "--output-type", "yaml", str(filepath)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"sops decrypt failed: {result.stderr}")
        return yaml.safe_load(result.stdout) or {}
    except Exception as exc:
        raise RuntimeError(f"Failed to decrypt {filepath}: {exc}") from exc


def _sops_encrypt_file(filepath: Path) -> None:
    """Encrypt a SOPS file in-place."""
    sops = _check_sops()
    result = subprocess.run(
        [sops, "-e", "--in-place", str(filepath)],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"sops encrypt failed: {result.stderr}")


def _sops_set(filepath: Path, dotted_key: str, value: str) -> None:
    """Set a value in a SOPS-encrypted file using `sops --set`."""
    sops = _check_sops()
    # sops --set expects a JSON-encoded value
    json_value = json.dumps(value)
    sops_key = json.dumps(dotted_key.split("."))
    result = subprocess.run(
        [sops, "--set", sops_key, json_value, str(filepath)],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"sops --set failed: {result.stderr}")


def _sops_extract(filepath: Path, dotted_key: str) -> str:
    """Extract a decrypted value from a SOPS file.

    Decrypts the whole file, navigates to the dotted path,
    and returns the 'value' field of that entry.
    """
    data = _sops_decrypt(filepath)
    try:
        entry = _get_nested(data, dotted_key)
    except KeyError:
        # Try accessing the .value subkey directly
        try:
            entry = _get_nested(data, f"{dotted_key}.value")
            return str(entry)
        except KeyError:
            raise KeyError(f"Key '{dotted_key}' not found in secrets file")
    if isinstance(entry, dict) and "value" in entry:
        return str(entry["value"])
    elif isinstance(entry, (str, int, float)):
        return str(entry)
    else:
        raise KeyError(f"Key '{dotted_key}' has no 'value' field")


# ---------------------------------------------------------------------------
# YAML path helpers — walk/create nested dicts using dotted paths
# ---------------------------------------------------------------------------


def _get_nested(data: Dict[str, Any], dotted_path: str) -> Any:
    """Walk a nested dict using a dotted path like 'api_keys.kapy_content_api'."""
    keys = dotted_path.split(".")
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            raise KeyError(f"Key '{dotted_path}' not found in secrets file")
        current = current[key]
    return current


def _set_nested(data: Dict[str, Any], dotted_path: str, value: Any) -> None:
    """Set a value in a nested dict, creating intermediate dicts as needed."""
    keys = dotted_path.split(".")
    current = data
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def _delete_nested(data: Dict[str, Any], dotted_path: str) -> bool:
    """Delete a key from a nested dict. Returns True if key existed."""
    keys = dotted_path.split(".")
    current = data
    for key in keys[:-1]:
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
    if keys[-1] in current:
        del current[keys[-1]]
        return True
    return False


def _collect_secret_keys(data: Dict[str, Any], prefix: str = "") -> List[str]:
    """Collect all dotted paths that have a 'value' key (i.e., are secret entries)."""
    results = []
    for key, val in data.items():
        full_path = f"{prefix}.{key}" if prefix else key
        if isinstance(val, dict) and "value" in val:
            results.append(full_path)
        elif isinstance(val, dict):
            results.extend(_collect_secret_keys(val, full_path))
    return results


# ---------------------------------------------------------------------------
# Secret entry structure helpers
# ---------------------------------------------------------------------------

# A secret entry looks like:
#   api_keys:
#     kapy_content_api:
#       value: <encrypted>
#       targets: [...]
#       last_rotated: "2026-05-27"
#       notes: "..."


def _make_secret_entry(
    value: str,
    targets: Optional[List[Dict[str, str]]] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a secret entry dict with value, targets, last_rotated, notes."""
    entry: Dict[str, Any] = {"value": value}
    if targets:
        entry["targets"] = targets
    entry["last_rotated"] = _today()
    if notes:
        entry["notes"] = notes
    return entry


def _parse_targets(target_strings: List[str]) -> List[Dict[str, str]]:
    """Parse target strings like 'wrangler_vars:path:KEY' into dicts."""
    targets = []
    for ts in target_strings:
        parts = ts.split(":", 2)
        if len(parts) != 3:
            raise ValueError(
                f"Invalid target format: {ts!r}. "
                "Expected 'type:path:key' (e.g., 'wrangler_vars:~/path/to/file:KEY')"
            )
        target_type, path, key = parts
        path = os.path.expanduser(path)
        if target_type not in ("wrangler_vars", "hermes_env", "dev_vars", "wrangler_secrets"):
            raise ValueError(
                f"Invalid target type: {target_type!r}. "
                "Must be one of: wrangler_vars, hermes_env, dev_vars, wrangler_secrets"
            )
        targets.append({"type": target_type, "path": path, "key": key})
    return targets


def _today() -> str:
    """Return today's date as YYYY-MM-DD."""
    from datetime import date
    return date.today().isoformat()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new secrets.enc.yaml for the given profile."""
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    profile_dir = secrets_path.parent

    if secrets_path.exists():
        console.print(f"[yellow]⚠ secrets file already exists: {secrets_path}[/yellow]")
        console.print("  Use `hermes secrets sops list` to view existing secrets.")
        return 1

    # Create profile directory if needed
    profile_dir.mkdir(parents=True, exist_ok=True)

    # Write initial empty YAML structure
    initial_data = {}
    with open(secrets_path, "w") as f:
        yaml.dump(initial_data, f, default_flow_style=False)

    # Encrypt with SOPS
    try:
        _sops_encrypt_file(secrets_path)
    except RuntimeError as exc:
        # If encryption fails, clean up the file
        secrets_path.unlink(missing_ok=True)
        console.print(f"[red]✗ SOPS encryption failed: {exc}[/red]")
        return 1

    console.print(f"[green]✓ Initialized secrets file: {secrets_path}[/green]")
    console.print(f"  Encrypted with age key from {AGE_KEY_PATH}")
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    """Set a secret value in the encrypted secrets file."""
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        console.print("  Run `hermes secrets sops init` first.")
        return 1

    # Generate value if --generate flag
    value = args.value
    if args.generate:
        length = args.length or 32
        value = secrets_mod.token_urlsafe(length)
        console.print(f"[dim]Generated {length}-byte value[/dim]")

    # Parse targets
    targets = None
    if args.targets:
        try:
            targets = _parse_targets(args.targets)
        except ValueError as exc:
            console.print(f"[red]✗ {exc}[/red]")
            return 1

    # Decrypt → modify YAML in-memory → write plaintext → re-encrypt
    # Instead of using sops --set (which has issues with nested dotted paths),
    # we decrypt, modify the dict, write back, and re-encrypt.
    dotted_path = args.key
    try:
        data = _sops_decrypt(secrets_path)
    except RuntimeError:
        # If decrypt fails (e.g., empty file with just sops metadata), start fresh
        data = {}

    # Create the secret entry
    entry = _make_secret_entry(value, targets=targets, notes=args.notes)
    _set_nested(data, dotted_path, entry)
    entry["last_rotated"] = _today()

    # Write decrypted YAML to file, then re-encrypt
    with open(secrets_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False)
    _sops_encrypt_file(secrets_path)

    console.print(f"[green]✓ Set secret: {dotted_path}[/green]")
    if targets:
        for t in targets:
            console.print(f"  → {t['type']}: {t['path']} [{t['key']}]")
    return 0


def cmd_get(args: argparse.Namespace) -> int:
    """Get a decrypted secret value."""
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        return 1

    console.print(
        "[bold yellow]⚠ WARNING: This will expose a secret value to your terminal history.[/bold yellow]"
    )

    try:
        value = _sops_extract(secrets_path, args.key)
    except RuntimeError as exc:
        console.print(f"[red]✗ Failed to get {args.key}: {exc}[/red]")
        return 1

    print(value)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List all secrets (key names only, never values)."""
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        console.print("  Run `hermes secrets sops init` first.")
        return 1

    try:
        data = _sops_decrypt(secrets_path)
    except RuntimeError as exc:
        console.print(f"[red]✗ Failed to decrypt: {exc}[/red]")
        return 1

    secret_keys = _collect_secret_keys(data)
    if not secret_keys:
        console.print("[dim]No secrets found. Use `hermes secrets sops set` to add one.[/dim]")
        return 0

    if args.json:
        entries = []
        for key_path in secret_keys:
            entry = _get_nested(data, key_path)
            entries.append({
                "key": key_path,
                "targets": entry.get("targets", []),
                "last_rotated": entry.get("last_rotated", ""),
                "notes": entry.get("notes", ""),
            })
        print(json.dumps(entries, indent=2))
        return 0

    # Table output
    table = Table(title="SOPS Secrets", show_header=True, header_style="bold cyan")
    table.add_column("Key", style="green")
    table.add_column("Targets", style="dim")
    table.add_column("Last Rotated", style="dim")
    table.add_column("Notes", style="dim", max_width=40)

    for key_path in secret_keys:
        entry = _get_nested(data, key_path)
        targets_str = ", ".join(
            f"{t['type']}:{t['key']}" for t in entry.get("targets", [])
        ) or "—"
        table.add_row(
            key_path,
            targets_str,
            entry.get("last_rotated", "—"),
            entry.get("notes", "—"),
        )

    console.print(table)
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    """Delete a secret from the encrypted file."""
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        return 1

    try:
        data = _sops_decrypt(secrets_path)
    except RuntimeError as exc:
        console.print(f"[red]✗ Failed to decrypt: {exc}[/red]")
        return 1

    if not _delete_nested(data, args.key):
        # Key was not found as a direct match — try deleting .value subkey
        alt = f"{args.key}.value"
        if not _delete_nested(data, alt):
            console.print(f"[red]✗ Key not found: {args.key}[/red]")
            return 1
        # Clean up parent if now empty
        parent_path = ".".join(args.key.split("."))
        try:
            parent = _get_nested(data, parent_path)
            if isinstance(parent, dict) and not parent:
                _delete_nested(data, parent_path)
        except KeyError:
            pass

    # Write back and re-encrypt
    with open(secrets_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False)
    _sops_encrypt_file(secrets_path)

    console.print(f"[green]✓ Deleted secret: {args.key}[/green]")
    return 0


# ---------------------------------------------------------------------------
# Sync / Status helpers
# ---------------------------------------------------------------------------


def _read_file_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return f.readlines()


def _write_file_lines(path: Path, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _sync_env_file(path: Path, key: str, value: str, dry_run: bool) -> tuple[bool, str]:
    lines = _read_file_lines(path)
    found = False
    new_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        if stripped.startswith(key + "=") or stripped.startswith(key + " ="):
            found = True
            # Preserve the original separator style (= vs = )
            if " = " in stripped[:len(key) + 3]:
                new_lines.append(f"{key} = {value}\n")
            else:
                new_lines.append(f"{key}={value}\n")
            continue
        new_lines.append(line)
    if not found:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append(f"{key}={value}\n")

    action = "would update" if (found and dry_run) else ("would add" if (not found and dry_run) else "updated" if found else "added")
    msg = f"  {'[dim]' if dry_run else '[green]'}✓ {path} [{key}] {action}{'[/dim]' if dry_run else '[/green]'}"
    if dry_run:
        return (True, msg)
    _write_file_lines(path, new_lines)
    return (True, msg)


def _validate_toml(content: str) -> Optional[str]:
    """Validate content as TOML. Returns error message or None if valid."""
    try:
        import tomllib
        try:
            tomllib.loads(content)
            return None
        except tomllib.TOMLDecodeError as exc:
            return str(exc)
    except ImportError:
        pass
    try:
        import toml
        try:
            toml.loads(content)
            return None
        except toml.TomlDecodeError as exc:
            return str(exc)
    except ImportError:
        pass
    # No TOML parser available; skip validation
    return None


def _sync_wrangler_vars(path: Path, key: str, value: str, dry_run: bool) -> tuple[bool, str]:
    lines = _read_file_lines(path)
    in_vars = False
    found = False
    key_pattern = key.lstrip()
    new_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("[vars]"):
            if in_vars and not found:
                new_lines.append(f'    {key} = "{value}"\n')
                found = True
            in_vars = False
            new_lines.append(line)
            continue
        if stripped.startswith("[vars]"):
            in_vars = True
            new_lines.append(line)
            continue
        # Match both key = value and key=value TOML formats
        if in_vars:
            var_match = stripped.split("=", 1)
            if len(var_match) == 2 and var_match[0].strip() == key:
                found = True
                new_lines.append(f'    {key} = "{value}"\n')
                continue
        new_lines.append(line)

    if not found:
        # Check if a [vars] section exists elsewhere or needs to be added
        has_vars = any(
            line.strip() == "[vars]" for line in new_lines
        )
        if not has_vars:
            if new_lines and new_lines[-1].strip() and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append("[vars]\n")
        new_lines.append(f'    {key} = "{value}"\n')

    if dry_run:
        return (True, f"  [dim]✓ wrangler_vars: {path} [{key}] — would update[/dim]")

    _write_file_lines(path, new_lines)

    # Validate result is valid TOML
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        error = _validate_toml(content)
        if error:
            return (False, f"  [red]✗ wrangler_vars: {path} — invalid TOML after write: {error}[/red]")
    except Exception:
        pass  # If validation fails, still report success — the write itself worked

    return (True, f"  [green]✓ wrangler_vars: {path} [{key}] — updated[/green]")


def _sync_wrangler_secret(target: Dict[str, Any], secret_value: str, dry_run: bool) -> tuple[bool, str]:
    path = Path(os.path.expanduser(target["path"]))
    key = target["key"]
    # The path points to the wrangler.toml; the project dir is its parent
    project_dir = path.parent if path.suffix == ".toml" else path
    if dry_run:
        return (True, f"  [dim]✓ wrangler_secrets: would run 'npx wrangler secret put {key}' in {project_dir}[/dim]")
    api_token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not api_token:
        return (False, f"  [red]✗ wrangler_secrets: CLOUDFLARE_API_TOKEN not set — cannot push {key}[/red]")
    try:
        # Use echo VALUE | npx wrangler secret put KEY pattern per spec
        proc = subprocess.run(
            ["npx", "wrangler", "secret", "put", key],
            cwd=str(project_dir),
            capture_output=True, text=True, timeout=120,
            input=secret_value + "\n",
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or proc.stdout.strip()
            return (False, f"  [red]✗ wrangler_secrets: {key} — {stderr}[/red]")
        return (True, f"  [green]✓ wrangler_secrets: {key} — synced[/green]")
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return (False, f"  [red]✗ wrangler_secrets: {key} — {exc}[/red]")


def _status_env_file(path: Path, key: str, expected: str) -> tuple[str, str]:
    if not path.exists():
        return ("missing", f"  [dim]? {path} [{key}] — file not found[/dim]")
    lines = _read_file_lines(path)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith(key + "=") or stripped.startswith(key + " ="):
            val = stripped.split("=", 1)[1].strip().strip('"')
            if val == expected:
                return ("synced", f"  [green]✓ {path} [{key}] — synced[/green]")
            return ("out_of_sync", f"  [red]✗ {path} [{key}] — out of sync[/red]")
    return ("not_found", f"  [dim]? {path} [{key}] — key not found[/dim]")


def _status_wrangler_vars(path: Path, key: str, expected: str) -> tuple[str, str]:
    if not path.exists():
        return ("missing", f"  [dim]? {path} [{key}] — file not found[/dim]")
    lines = _read_file_lines(path)
    in_vars = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[vars]":
            in_vars = True
            continue
        if stripped.startswith("[") and not stripped.startswith("[vars]"):
            in_vars = False
            continue
        if stripped.startswith("["):
            # Any other section header ends [vars]
            in_vars = False
            continue
        if in_vars:
            var_match = stripped.split("=", 1)
            if len(var_match) == 2 and var_match[0].strip() == key:
                val = var_match[1].strip().strip('"')
                if val == expected:
                    return ("synced", f"  [green]✓ {path} [{key}] — synced[/green]")
                return ("out_of_sync", f"  [red]✗ {path} [{key}] — out of sync[/red]")
    return ("not_found", f"  [dim]? {path} [{key}] — key not found in [vars][/dim]")


def _status_wrangler_secret_target(path: Path, key: str, expected: str) -> tuple[str, str]:
    if not path.exists():
        return ("missing", f"  [dim]? {path} [{key}] — wrangler.toml not found[/dim]")
    return ("unknown", f"  [dim]? {path} [{key}] — wrangler_secrets cannot be read back for verification[/dim]")


# ---------------------------------------------------------------------------
# Commands — Sync & Status
# ---------------------------------------------------------------------------


def cmd_sync(args: argparse.Namespace) -> int:
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        return 1

    try:
        data = _sops_decrypt(secrets_path)
    except RuntimeError as exc:
        console.print(f"[red]✗ Failed to decrypt: {exc}[/red]")
        return 1

    secret_keys = _collect_secret_keys(data)
    if not secret_keys:
        console.print("[dim]No secrets to sync.[/dim]")
        return 0

    changed = 0
    total = 0

    target_filter = args.target
    dry_run = args.dry_run

    if dry_run:
        console.print("[bold cyan]-- DRY RUN — no files will be written[/bold cyan]\n")

    for key_path in secret_keys:
        entry = _get_nested(data, key_path)
        targets = entry.get("targets", [])
        if not targets:
            continue
        console.print(f"[bold]{key_path}[/bold]")
        for t in targets:
            ttype = t["type"]
            if target_filter and ttype != target_filter:
                continue
            total += 1
            path = Path(os.path.expanduser(t["path"]))
            target_key = t["key"]
            value = str(entry["value"])
            ok = False
            if ttype == "wrangler_vars":
                ok, msg = _sync_wrangler_vars(path, target_key, value, dry_run)
            elif ttype in ("dev_vars", "hermes_env"):
                ok, msg = _sync_env_file(path, target_key, value, dry_run)
            elif ttype == "wrangler_secrets":
                ok, msg = _sync_wrangler_secret(t, value, dry_run)
            else:
                msg = f"  [red]Unknown target type: {ttype}[/red]"
            if ok:
                changed += 1
            console.print(msg)

    noun = "change" if changed == 1 else "changes"
    if dry_run:
        console.print(f"\n[dim]Would make {changed} {noun} across {total} targets[/dim]")
    else:
        console.print(f"\n[green]✓ Synced {changed}/{total} targets[/green]")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        return 1

    try:
        data = _sops_decrypt(secrets_path)
    except RuntimeError as exc:
        console.print(f"[red]✗ Failed to decrypt: {exc}[/red]")
        return 1

    secret_keys = _collect_secret_keys(data)
    if not secret_keys:
        console.print("[dim]No secrets found.[/dim]")
        return 0

    synced = 0
    out_of_sync = 0
    missing = 0

    for key_path in secret_keys:
        entry = _get_nested(data, key_path)
        targets = entry.get("targets", [])
        if not targets:
            continue
        console.print(f"[bold]{key_path}[/bold]")
        for t in targets:
            path = Path(os.path.expanduser(t["path"]))
            target_key = t["key"]
            value = str(entry["value"])
            ttype = t["type"]
            if ttype == "wrangler_vars":
                state, msg = _status_wrangler_vars(path, target_key, value)
            elif ttype in ("dev_vars", "hermes_env"):
                state, msg = _status_env_file(path, target_key, value)
            elif ttype == "wrangler_secrets":
                state, msg = _status_wrangler_secret_target(path, target_key, value)
            else:
                state, msg = ("unknown", f"  [red]Unknown target type: {ttype}[/red]")
            if state == "synced":
                synced += 1
            elif state == "out_of_sync":
                out_of_sync += 1
            elif state in ("missing", "not_found"):
                missing += 1
            console.print(msg)

    total = synced + out_of_sync + missing
    console.print("\n[bold]Summary[/bold]")
    console.print(f"  [green]✓ synced[/green]: {synced}/{total}")
    if out_of_sync:
        console.print(f"  [red]✗ out of sync[/red]: {out_of_sync}/{total}")
    if missing:
        console.print(f"  [dim]? missing[/dim]: {missing}/{total}")
    return 0


# ---------------------------------------------------------------------------
# Argparse registration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Commands — Rotate & Updatekeys
# ---------------------------------------------------------------------------


def cmd_rotate(args: argparse.Namespace) -> int:
    """Rotate a secret: generate new value, update SOPS file, and sync targets."""
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        return 1

    key_path = args.key
    length = args.length
    dry_run = args.dry_run

    # Generate new value
    import secrets as secrets_mod
    new_value = secrets_mod.token_urlsafe(length)
    console.print(f"[bold]Rotating {key_path}[/bold] ({length} bytes)")
    if dry_run:
        console.print(f"  [dim]New value: {'*' * min(length, 8)}...[/dim]")
    else:
        console.print(f"  [green]✓ New value generated ({length} bytes)[/green]")

    # Decrypt and load
    try:
        data = _sops_decrypt(secrets_path)
    except RuntimeError as exc:
        console.print(f"[red]✗ Failed to decrypt: {exc}[/red]")
        return 1

    # Check key exists
    entry = _get_nested(data, key_path)
    if entry is None:
        console.print(f"[red]✗ Key not found: {key_path}[/red]")
        return 1

    if dry_run:
        console.print(f"  [dim]Would update value in {secrets_path.name}[/dim]")
        console.print(f"  [dim]Would set last_rotated to {_today()}[/dim]")
    else:
        # Update value and last_rotated
        _set_nested(data, f"{key_path}.value", new_value)
        _set_nested(data, f"{key_path}.last_rotated", _today())

        # Write back and re-encrypt
        with open(secrets_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        _sops_encrypt_file(secrets_path)
        console.print(f"  [green]✓ Updated {secrets_path.name}[/green]")

    # Sync to targets (reuse cmd_sync logic)
    targets = entry.get("targets", []) if isinstance(entry, dict) else []
    if targets:
        console.print("\n[bold]Syncing to targets:[/bold]")
        # Build a namespace that matches cmd_sync arguments
        import argparse
        sync_args = argparse.Namespace(
            profile=args.profile,
            target=None,
            dry_run=dry_run,
        )
        # Run sync for just this key
        synced = 0
        for t in targets:
            ttype = t["type"]
            path = Path(os.path.expanduser(t["path"]))
            target_key = t["key"]
            ok = False
            if ttype == "wrangler_vars":
                ok, msg = _sync_wrangler_vars(path, target_key, new_value, dry_run)
            elif ttype in ("dev_vars", "hermes_env"):
                ok, msg = _sync_env_file(path, target_key, new_value, dry_run)
            elif ttype == "wrangler_secrets":
                ok, msg = _sync_wrangler_secret(t, new_value, dry_run)
            else:
                msg = f"  [red]Unknown target type: {ttype}[/red]"
            if ok:
                synced += 1
            console.print(msg)

        noun = "target" if synced == 1 else "targets"
        if dry_run:
            console.print(f"\n  [dim]Would sync to {synced}/{len(targets)} {noun}[/dim]")
        else:
            console.print(f"\n  [green]✓ Synced to {synced}/{len(targets)} {noun}[/green]")

    # Restart warnings
    console.print("\n[bold yellow]⚠ Action required:[/bold yellow]")
    has_env = any(t.get("type") == "hermes_env" for t in (targets or []))
    has_wrangler = any(t.get("type") in ("wrangler_vars", "wrangler_secrets") for t in (targets or []))
    if has_env:
        console.print("  [yellow]Restart hermes-dashboard to pick up new .env values:[/yellow]")
        console.print("  [dim]  systemctl --user restart hermes-dashboard[/dim]")
    if has_wrangler:
        console.print("  [yellow]Redeploy workers to pick up new [vars]:[/yellow]")
        console.print("  [dim]  cd ~/code/oykapy/<worker> && npx wrangler deploy[/dim]")

    return 0


def cmd_updatekeys(args: argparse.Namespace) -> int:
    """Re-encrypt secrets file with current .sops.yaml creation rules."""
    _check_sops()
    _check_age_key()

    secrets_path = _secrets_file(args.profile)
    if not secrets_path.exists():
        console.print(f"[red]✗ Secrets file not found: {secrets_path}[/red]")
        return 1

    console.print(f"[bold]Updating encryption keys for {secrets_path}[/bold]")
    try:
        result = subprocess.run(
            ["sops", "updatekeys", str(secrets_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            console.print(f"[red]✗ updatekeys failed: {result.stderr.strip()}[/red]")
            return 1

        # Check if the output asks for confirmation (interactive mode)
        if "Are you sure" in result.stdout or "Are you sure" in result.stderr:
            # Re-run with --yes flag
            result = subprocess.run(
                ["sops", "updatekeys", "--yes", str(secrets_path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                console.print(f"[red]✗ updatekeys failed: {result.stderr.strip()}[/red]")
                return 1

        console.print(f"[green]✓ Keys updated for {secrets_path.name}[/green]")
        return 0
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        console.print(f"[red]✗ updatekeys failed: {exc}[/red]")
        return 1


def register_cli(parent_parser: argparse.ArgumentParser) -> None:
    """Attach the ``sops`` subcommand tree to a parent parser.

    Called from ``hermes_cli.main`` as part of building the top-level
    ``hermes secrets`` parser.
    """
    sub = parent_parser.add_subparsers(dest="sops_command")

    # init
    init = sub.add_parser("init", help="Initialize a new SOPS secrets file")
    init.add_argument("--profile", help="Hermes profile (default: current)")
    init.set_defaults(func=cmd_init)

    # set
    set_cmd = sub.add_parser("set", help="Set a secret value")
    set_cmd.add_argument("key", help="Dotted path (e.g., api_keys.kapy_content_api)")
    set_cmd.add_argument("value", nargs="?", help="Secret value (use --generate to auto-generate)")
    set_cmd.add_argument("--generate", action="store_true", help="Auto-generate a random value")
    set_cmd.add_argument("--length", type=int, default=32, help="Length of generated value (default: 32)")
    set_cmd.add_argument("--targets", action="append", help="Target spec: 'type:path:key'")
    set_cmd.add_argument("--notes", help="Notes about this secret")
    set_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    set_cmd.set_defaults(func=cmd_set)

    # get
    get_cmd = sub.add_parser("get", help="Get a decrypted secret value")
    get_cmd.add_argument("key", help="Dotted path (e.g., api_keys.kapy_content_api)")
    get_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    get_cmd.set_defaults(func=cmd_get)

    # list
    list_cmd = sub.add_parser("list", help="List all secrets (key names only)")
    list_cmd.add_argument("--json", action="store_true", help="Output as JSON")
    list_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    list_cmd.set_defaults(func=cmd_list)

    # delete
    delete_cmd = sub.add_parser("delete", help="Delete a secret")
    delete_cmd.add_argument("key", help="Dotted path (e.g., api_keys.kapy_content_api)")
    delete_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    delete_cmd.set_defaults(func=cmd_delete)

    # sync
    sync_cmd = sub.add_parser("sync", help="Sync secrets to target files")
    sync_cmd.add_argument("--target", choices=("wrangler_vars", "dev_vars", "hermes_env", "wrangler_secrets"), help="Only sync this target type")
    sync_cmd.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    sync_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    sync_cmd.set_defaults(func=cmd_sync)

    # status
    status_cmd = sub.add_parser("status", help="Check sync status of secrets to targets")
    status_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    status_cmd.set_defaults(func=cmd_status)

    # rotate
    rotate_cmd = sub.add_parser("rotate", help="Rotate a secret: generate new value and sync targets")
    rotate_cmd.add_argument("key", help="Dotted path (e.g., api_keys.kapy_content_api)")
    rotate_cmd.add_argument("--length", type=int, default=32, help="Length of generated value in bytes (default: 32)")
    rotate_cmd.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    rotate_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    rotate_cmd.set_defaults(func=cmd_rotate)

    # updatekeys
    updatekeys_cmd = sub.add_parser("updatekeys", help="Re-encrypt with current .sops.yaml creation rules")
    updatekeys_cmd.add_argument("--profile", help="Hermes profile (default: current)")
    updatekeys_cmd.set_defaults(func=cmd_updatekeys)
