"""Regression tests for assignee-vs-task-type validation on kanban create/reassign.

Tracks the division-of-labor enforcement added on 2026-06-02 (task
``t_5c55e3c4``).  The validation cross-references the ``--assignee``
profile against the canonical owner of the body's ``**Type:**`` field
and either warns or hard-errors on mismatch.  The matrix lives in
``kanban.py:TASK_TYPE_ASSIGNEE_MATRIX`` and is sourced from the
``division-of-labor`` skill.

The two failure modes this guards against:

* ``hermes kanban create`` lands with the wrong assignee (operator
  error, stale muscle memory, copy-pasted body) and the dispatcher
  burns iterations on a self-routing cycle.
* ``hermes kanban migrate-assignee`` rewrites tasks to a profile
  that isn't the type's owner — the post-rotation recovery path that
  moved the original ``t_1e4d4996`` sund task to davinci.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from hermes_cli import kanban as kc
from hermes_cli import kanban_db as kb

# Path to the hermes-agent worktree (the parent of this test file's
# ``tests/`` dir).  Pinned into PYTHONPATH for the subprocess-based
# end-to-end CLI tests so they always run against the in-tree code,
# not a stale install.  Mirrors the pattern in
# ``test_kanban_boards.py:_cli``.
_WORKTREE = Path(__file__).resolve().parents[2]


def _cli(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run ``hermes kanban …`` end-to-end via ``python -m hermes_cli.main``.

    Used by the exit-code regression tests below.  Captures both
    stdout and stderr so a non-zero exit is unambiguous — a process
    can crash and still print something useful, and we want the
    assertion to fail loudly if the shell sees ``returncode != 2``
    for a strict-mode error.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_WORKTREE)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "hermes_cli.main", "kanban"] + args,
        env=env,
        capture_output=True,
        text=True,
        cwd=str(_WORKTREE),
        timeout=30,
    )


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    """Isolated HERMES_HOME per test.  Local copy of the fixture that
    lives in ``test_kanban_cli.py`` — duplicated here to keep the
    test files self-contained (the conftest.py only carries the
    autouse concurrent-hermes guard)."""
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_DB", str(home / "kanban.db"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


# ---------------------------------------------------------------------
# Pure helper tests (no DB) — fast, deterministic, exercise the matrix
# ---------------------------------------------------------------------

class TestParseTaskType:
    """``parse_task_type`` should accept the three common Type header layouts."""

    def test_canonical_double_star_bold_colon(self):
        assert kc.parse_task_type("**Type:** coding\n**Goal:** x") == "coding"

    def test_plain_colon(self):
        assert kc.parse_task_type("**Type: research**\nMore text") == "research"

    def test_open_bold_colon(self):
        assert kc.parse_task_type("**Type**:   design-decision   \n") == "design-decision"

    def test_none_when_type_header_missing(self):
        assert kc.parse_task_type("just some prose, no type header") is None

    def test_none_when_body_empty(self):
        assert kc.parse_task_type("") is None
        assert kc.parse_task_type(None) is None

    def test_case_insensitive(self):
        assert kc.parse_task_type("**type:** coding") == "coding"
        assert kc.parse_task_type("**TYPE:** coding") == "coding"

    def test_value_lowercased(self):
        # The matrix keys are lowercased; the parser must normalize the
        # input so a header like "**Type:** CODING" still matches.
        assert kc.parse_task_type("**Type:** CODING") == "coding"

    def test_first_type_wins(self):
        # If a body has two Type headers (unusual but possible from
        # copy-paste), the FIRST one is what the validator reads.
        assert kc.parse_task_type("**Type:** coding\n**Type:** research") == "coding"

    def test_literal_backslash_n_as_line_terminator(self):
        # Operator-written --body strings pass through shlex as
        # single-quoted args, so a literal two-char ``\\n`` may show
        # up where the operator meant a real newline.  The parser
        # normalizes that to a real newline so the Type header still
        # resolves.
        assert kc.parse_task_type("**Type:** coding\\nfoo") == "coding"
        assert kc.parse_task_type("**Type:** research\\n") == "research"
        # And a body that genuinely has ``coding\\nfoo`` and no other
        # formatting (e.g. JSON-encoded) still resolves correctly.
        assert kc.parse_task_type("**Type:** config\\n\\nbody text") == "config"


class TestCheckAssigneeMatchesType:
    """``check_assignee_matches_type`` returns warnings or raises in strict mode."""

    def test_matching_assignee_returns_none(self):
        assert kc.check_assignee_matches_type(
            "sund", "**Type:** coding\nfoo", strict=False,
        ) is None

    def test_mismatched_assignee_returns_warning(self):
        w = kc.check_assignee_matches_type(
            "davinci", "**Type:** coding\nfoo", strict=False,
        )
        assert w is not None
        assert "coding" in w
        assert "sund" in w

    def test_strict_mode_raises_on_mismatch(self):
        with pytest.raises(ValueError) as exc_info:
            kc.check_assignee_matches_type(
                "davinci", "**Type:** coding", strict=True,
            )
        assert "coding" in str(exc_info.value)
        assert "sund" in str(exc_info.value)

    def test_strict_mode_passes_silently_on_match(self):
        # Must not raise when the assignee matches the type's owner.
        kc.check_assignee_matches_type(
            "sund", "**Type:** coding", strict=True,
        )

    def test_unassigned_skips_check(self):
        # Operator chose to leave the task unassigned — opt out of
        # the cross-check rather than complaining about the absence.
        assert kc.check_assignee_matches_type(
            None, "**Type:** coding", strict=False,
        ) is None
        assert kc.check_assignee_matches_type(
            None, "**Type:** coding", strict=True,
        ) is None

    def test_no_type_header_skips_check(self):
        # Tasks without a Type header are not subject to the matrix.
        assert kc.check_assignee_matches_type(
            "davinci", "no type header at all", strict=False,
        ) is None

    def test_type_with_no_owner_skips_check(self):
        # ``creation`` has multiple possible owners (coding or visual),
        # so the matrix entry is None and any assignee is acceptable.
        for assignee in ("sund", "davinci", "dabu", "orchestrator"):
            assert kc.check_assignee_matches_type(
                assignee, "**Type:** creation", strict=False,
            ) is None

    def test_research_owned_by_davinci(self):
        # The davinci research-only constraint is the original
        # t_1e4d4996 bug — coding task being routed to davinci.
        # Reverse case: a research task routed to sund is also wrong.
        w = kc.check_assignee_matches_type(
            "sund", "**Type:** research", strict=False,
        )
        assert w is not None and "davinci" in w


# ---------------------------------------------------------------------
# CLI integration tests (via run_slash, isolated DB via the kanban_home
# fixture in conftest.py)
# ---------------------------------------------------------------------

def _task_id_from_create_output(out: str) -> str:
    """Pull the t_xxxx id out of a 'Created t_xxxx  (status, ...)' line."""
    m = re.search(r"(t_[a-f0-9]+)", out)
    assert m, f"could not parse task id from: {out!r}"
    return m.group(1)


def _get_assignee(tid: str):
    """Look up the current assignee for *tid* via the DB.

    Returns the assignee string (may be None for unassigned tasks).
    Asserts the task exists — tests that expect a missing task should
    check the listing instead.  This keeps the assertion in one place
    so Pyright can see that ``assignee`` access is safe.
    """
    with kb.connect() as conn:
        task = kb.get_task(conn, tid)
    assert task is not None, f"task {tid} disappeared between create and lookup"
    return task.assignee


def test_create_warns_on_type_mismatch(kanban_home):
    """`hermes kanban create 'x' --body '**Type:** coding' --assignee davinci` warns + creates.

    Regression for t_5ba46f30 (config task created as orchestrator) and
    t_1e4d4996 (sund coding task migrated to davinci).  Both should
    have produced an immediate warning at create time.
    """
    out = kc.run_slash(
        "create 'coding task' "
        "--body '**Type:** coding\\nfoo' "
        "--assignee davinci"
    )

    # Task was created despite the mismatch (warning is advisory).
    tid = _task_id_from_create_output(out)
    assert "Created" in out
    assert tid

    # Warning is in the output (stdout + stderr both go to the run_slash
    # return value via redirect_stdout/stderr in the implementation).
    assert "type 'coding' is owned by 'sund'" in out
    assert "davinci" in out  # mentions the wrong assignee

    # And the task really is in the DB with the requested assignee.
    assert _get_assignee(tid) == "davinci"


def test_create_strict_errors_on_type_mismatch(kanban_home):
    """`--strict` hard-errors on mismatch and does NOT create the task.

    The whole point of --strict is to fail closed so the operator
    can't accidentally land a coding task on davinci in a CI pipeline
    or scripted batch.  The error message must name the canonical
    owner so the operator knows what to fix.
    """
    out = kc.run_slash(
        "create 'coding task 2' "
        "--body '**Type:** coding\\nfoo' "
        "--assignee davinci --strict"
    )

    # The error names the canonical owner and the requested assignee.
    assert "kanban:" in out
    assert "type 'coding' is owned by 'sund'" in out
    assert "davinci" in out

    # CRITICAL: no task was created. Verify by listing and confirming
    # the title isn't there.
    listing = kc.run_slash("list")
    assert "coding task 2" not in listing


def test_reassign_warns_on_type_mismatch(kanban_home):
    """Reassigning a coding task from sund to davinci warns at reassign time.

    This is the t_1e4d4996 scenario: a task that was correct at
    creation (coding + sund) gets routed to the wrong profile via
    reassign.  The validator catches it at the reassign boundary.
    """
    # Create a task with matching assignee so it lands cleanly.
    out = kc.run_slash(
        "create 'will be misrouted' "
        "--body '**Type:** coding\\nfoo' "
        "--assignee sund"
    )
    tid = _task_id_from_create_output(out)

    # Reassign to davinci — should warn but still proceed.
    reassign_out = kc.run_slash(f"reassign {tid} davinci")
    assert "Reassigned" in reassign_out
    assert "type 'coding' is owned by 'sund'" in reassign_out

    # Verify the reassign really happened (warning is advisory).
    assert _get_assignee(tid) == "davinci"

    # --strict variant: must block.
    # First reassign back to sund to get a known-good baseline.
    kc.run_slash(f"reassign {tid} sund")
    strict_out = kc.run_slash(f"reassign {tid} davinci --strict")
    assert "kanban:" in strict_out
    assert "type 'coding' is owned by 'sund'" in strict_out
    assert "Reassigned" not in strict_out  # did NOT happen

    assert _get_assignee(tid) == "sund"  # unchanged


def test_migrate_assignee_validates_destination(kanban_home):
    """`migrate-assignee` validates the destination assignee and prints ALL warnings.

    Regression for the post-rotation recovery path that produced
    t_1e4d4996: a bulk migrate-assignee sund davinci landed a coding
    task on a research-only profile.  The validator must:

    1. Show ALL warnings in one batch (so operators can see the full
       damage, not just the first hit — explicit in the task spec).
    2. Block before any rows are written when --strict is passed.
    """
    # Create three coding tasks (all sund) and one research task
    # (davinci).  The sund->davinci migration should warn about the
    # three coding tasks and migrate them anyway (warning mode).
    out_c1 = kc.run_slash("create 'c1' --body '**Type:** coding' --assignee sund")
    tid_c1 = _task_id_from_create_output(out_c1)
    out_c2 = kc.run_slash("create 'c2' --body '**Type:** coding' --assignee sund")
    tid_c2 = _task_id_from_create_output(out_c2)
    out_c3 = kc.run_slash("create 'c3' --body '**Type:** coding' --assignee sund")
    tid_c3 = _task_id_from_create_output(out_c3)
    out_r = kc.run_slash("create 'r1' --body '**Type:** research' --assignee davinci")
    tid_r = _task_id_from_create_output(out_r)

    # --- warning mode: warn + migrate ---
    mig_out = kc.run_slash("migrate-assignee sund davinci")
    assert "Migrated 3 task(s)" in mig_out
    # All three coding tasks named in the warning block.  The exact
    # order of the warning list is non-deterministic (depends on row
    # scan order), so check by substring.
    assert "type-mismatch" in mig_out
    for tid in (tid_c1, tid_c2, tid_c3):
        assert tid in mig_out, f"task {tid} missing from migrate output: {mig_out!r}"

    # --- strict mode: block before any rows are written ---
    # Reset: reassign the migrated tasks back to sund.
    for tid in (tid_c1, tid_c2, tid_c3):
        kc.run_slash(f"reassign {tid} sund")

    strict_out = kc.run_slash("migrate-assignee sund davinci --strict")
    # The strict error must surface AND identify the offending task.
    assert "kanban:" in strict_out
    assert "type 'coding' is owned by 'sund'" in strict_out
    # The "Migrated N task(s)" line MUST be absent — nothing was written.
    assert "Migrated" not in strict_out

    # Verify all three tasks are still assigned to sund.
    for tid in (tid_c1, tid_c2, tid_c3):
        assert _get_assignee(tid) == "sund", (
            f"task {tid} was rewritten despite --strict: "
            f"now assigned to {_get_assignee(tid)!r}"
        )

    # And the davinci research task was never touched (it's not even
    # in the migration candidate set since its assignee is already
    # davinci).
    assert _get_assignee(tid_r) == "davinci"


# ---------------------------------------------------------------------
# Matrix sanity check — the dictionary in kanban.py must reference
# only profiles that exist on disk.  Catches the "sund got renamed
# to the_developer" drift where the matrix is updated but the
# profile-name rotation lagged by a day.
# ---------------------------------------------------------------------

def test_matrix_only_references_known_types():
    """Every type name used in the body of a real task should appear in the matrix."""
    observed_types = {"coding", "config", "research", "verification",
                      "design-decision", "habit", "creation", "visual"}
    matrix_types = set(kc.TASK_TYPE_ASSIGNEE_MATRIX.keys())
    missing = observed_types - matrix_types
    assert not missing, (
        f"Task types observed in the wild but missing from "
        f"TASK_TYPE_ASSIGNEE_MATRIX: {missing}. Add them so the "
        f"validator doesn't opt out by accident."
    )


def test_matrix_owner_values_are_strings_or_none():
    """Every non-None owner in the matrix must be a string (profile name)."""
    for task_type, owner in kc.TASK_TYPE_ASSIGNEE_MATRIX.items():
        assert owner is None or isinstance(owner, str), (
            f"matrix entry for type {task_type!r} must be a profile "
            f"string or None, got {type(owner).__name__}: {owner!r}"
        )


# ---------------------------------------------------------------------
# End-to-end CLI exit-code tests — pin the main.py fix that propagates
# the kanban_command return value as the process exit code.  Before
# the fix, ``hermes kanban create … --strict`` printed the
# type-mismatch error to stderr but exited 0, so CI pipelines and
# cron sweeps couldn't detect the failure.  These tests run the real
# ``python -m hermes_cli.main kanban …`` via subprocess against a
# per-test HERMES_HOME so they exercise the full dispatch path.
# ---------------------------------------------------------------------


def test_cli_strict_create_exits_nonzero(tmp_path):
    """``hermes kanban create --strict`` must exit non-zero on type mismatch.

    Regression for the bug where ``_cmd_create`` returned 2 but
    ``hermes_cli.main:main`` discarded the return value of
    ``args.func(args)``, so the process always exited 0.  Without
    this test, a future refactor of the main dispatch loop could
    silently re-break the strict-mode error path.
    """
    env = {
        "HERMES_HOME": str(tmp_path / ".hermes"),
        "HERMES_KANBAN_HOME": str(tmp_path / ".hermes"),
        "HERMES_KANBAN_DB": str(tmp_path / ".hermes" / "kanban.db"),
    }
    res = _cli(
        [
            "create", "test x strict",
            "--body", "**Type:** coding",
            "--assignee", "davinci",
            "--strict",
        ],
        env_extra=env,
    )
    # The error must land on stderr so operators see it, and the
    # exit code must be non-zero (2 from _cmd_create).  Combined
    # assertion catches both: a print-to-stdout regression AND a
    # return-code regression in a single test.
    assert res.returncode != 0, (
        f"strict mode exited 0 — type-mismatch was silently swallowed. "
        f"stdout={res.stdout!r} stderr={res.stderr!r}"
    )
    assert "kanban:" in res.stderr, (
        f"strict mode error message missing from stderr. "
        f"stderr={res.stderr!r}"
    )
    assert "type 'coding' is owned by 'sund'" in res.stderr
    # And no task was created (the list command should be empty).
    list_res = _cli(["list"], env_extra=env)
    assert "test x strict" not in list_res.stdout


def test_cli_warning_create_exits_zero(tmp_path):
    """Warning mode (no --strict) creates the task and exits 0.

    Confirms the inverse: a successful create with a type-mismatch
    warning should still produce a zero exit code, so ad-hoc CLI
    invocations don't fail unexpectedly.  The warning goes to
    stderr (where operators can see it) but doesn't block.
    """
    env = {
        "HERMES_HOME": str(tmp_path / ".hermes"),
        "HERMES_KANBAN_HOME": str(tmp_path / ".hermes"),
        "HERMES_KANBAN_DB": str(tmp_path / ".hermes" / "kanban.db"),
    }
    res = _cli(
        [
            "create", "test x warning",
            "--body", "**Type:** coding",
            "--assignee", "davinci",
        ],
        env_extra=env,
    )
    assert res.returncode == 0, (
        f"warning mode unexpectedly exited non-zero: rc={res.returncode} "
        f"stdout={res.stdout!r} stderr={res.stderr!r}"
    )
    assert "type 'coding' is owned by 'sund'" in res.stderr
    assert "Created" in res.stdout
    # The task really is in the DB.
    list_res = _cli(["list"], env_extra=env)
    assert "test x warning" in list_res.stdout


def test_cli_strict_reassign_exits_nonzero(tmp_path):
    """``hermes kanban reassign --strict`` must also surface as a non-zero exit.

    Parallel to the create test — pins the reassign command's
    exit-code path.  Creates a valid sund/coding task first (must
    succeed with rc=0), then tries to misroute it via strict mode.
    """
    env = {
        "HERMES_HOME": str(tmp_path / ".hermes"),
        "HERMES_KANBAN_HOME": str(tmp_path / ".hermes"),
        "HERMES_KANBAN_DB": str(tmp_path / ".hermes" / "kanban.db"),
    }
    # Seed: matching assignee so create succeeds.
    seed = _cli(
        [
            "create", "valid task",
            "--body", "**Type:** coding",
            "--assignee", "sund",
        ],
        env_extra=env,
    )
    assert seed.returncode == 0, seed.stderr
    # Pull the task id from the create output.
    m = re.search(r"(t_[a-f0-9]+)", seed.stdout)
    assert m, f"no task id in: {seed.stdout!r}"
    tid = m.group(1)
    # Now misroute — should exit non-zero.
    res = _cli(["reassign", tid, "davinci", "--strict"], env_extra=env)
    assert res.returncode != 0, (
        f"reassign --strict exited 0 — return code regression. "
        f"stdout={res.stdout!r} stderr={res.stderr!r}"
    )
    assert "type 'coding' is owned by 'sund'" in res.stderr
    assert "Reassigned" not in res.stdout  # the reassign must NOT have happened
