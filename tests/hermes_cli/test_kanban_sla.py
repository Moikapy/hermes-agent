"""Tests for hermes_cli.kanban_sla — the shared priority→day mapping.

These are pure-function tests; no DB or fixture needed. The module is the
single source of truth for the overdue badge, so any change to the mapping
or the badge wording is a behavior change in both ``hermes kanban list`` and
the morning brief.
"""

from __future__ import annotations

import importlib

import pytest

ks = importlib.import_module("hermes_cli.kanban_sla")


# ---------------------------------------------------------------------------
# Mapping sanity
# ---------------------------------------------------------------------------

def test_priority_sla_days_table_is_complete():
    """The table must cover priorities 0..10. Otherwise the badge silently
    falls through to the DEFAULT_SLA_DAYS (14) for unmapped values, which
    would mask real regressions when we add new priorities."""
    for p in range(11):
        assert p in ks.PRIORITY_SLA_DAYS, f"priority {p} missing from SLA table"


def test_priority_sla_days_monotonic_inverse():
    """Higher priority should be a shorter SLA. The exact numbers can change,
    but the ordering must hold — the whole point of the mapping is that
    p=10 is "fix today" and p=0 is "someday"."""
    days = ks.PRIORITY_SLA_DAYS
    assert days[0] >= days[4]   # low >= high
    assert days[4] >= days[8]   # high >= critical
    assert days[8] > days[10]   # critical > fire  (fire is 0)
    assert days[10] == 0        # fire means same-day


def test_unknown_priority_falls_back_to_default():
    assert ks.sla_days(99) == ks.DEFAULT_SLA_DAYS
    assert ks.sla_days(-3) == ks.DEFAULT_SLA_DAYS


# ---------------------------------------------------------------------------
# sla_deadline
# ---------------------------------------------------------------------------

def test_sla_deadline_within_window():
    """A task created 2 days ago with a 7-day SLA has 5 days remaining."""
    now = 1_000_000_000
    created = now - 2 * 86400
    deadline, remaining = ks.sla_deadline(created, 3, now)
    assert deadline == created + 7 * 86400
    assert remaining == 5


def test_sla_deadline_just_past_due_is_one_day_overdue():
    """Day-granularity floor division: 6 hours past the deadline reports
    days_remaining == -1, not 0. The brief uses this — a 1-hour late task
    is already in the overdue section (the floor biases toward "alarm" so
    the cron can't miss a slipped task at a clock-boundary edge)."""
    now = 1_000_000_000
    created = now - (7 * 86400 + 6 * 3600)   # 7d 6h ago, 7-day SLA
    _deadline, remaining = ks.sla_deadline(created, 3, now)
    assert remaining == -1


def test_sla_deadline_overdue_is_negative():
    """A p=3 task created 10 days ago is 3 days overdue (10 - 7 = 3)."""
    now = 1_000_000_000
    created = now - 10 * 86400
    _deadline, remaining = ks.sla_deadline(created, 3, now)
    assert remaining == -3


def test_sla_deadline_fire_priority_is_immediate():
    """Priority 10 (fire) has a 0-day SLA. A task created even 1 second ago
    is already overdue. The priority is reserved for "ship today" — by
    the time we observe it, it should be in the alarm list."""
    now = 1_000_000_000
    created = now - 1   # even 1 second old fires the alarm
    _deadline, remaining = ks.sla_deadline(created, 10, now)
    assert remaining == -1
    # And the deadline itself is the creation time, so the badge will
    # surface the moment any time has elapsed.
    assert _deadline == created


# ---------------------------------------------------------------------------
# Badge formatting
# ---------------------------------------------------------------------------

def test_sla_badge_within_window():
    assert ks.sla_badge(0, 3) == "⏰ 3d"
    assert ks.sla_badge(0, 0) == "⏰ 0d"


def test_sla_badge_overdue_uses_due_format():
    """Acceptance criterion: '🚨 3d overdue' for past-SLA tasks."""
    assert ks.sla_badge(0, -3) == "🚨 3d overdue"
    assert ks.sla_badge(0, -1) == "🚨 1d overdue"
    assert ks.sla_badge(0, -14) == "🚨 14d overdue"


def test_sla_badge_does_not_say_OVERDUE():
    """Old brief output used '🚨 OVERDUE 3d'. The new module uses
    '🚨 3d overdue' — shorter, parses better in narrow terminals."""
    badge = ks.sla_badge(0, -3)
    assert "OVERDUE" not in badge


# ---------------------------------------------------------------------------
# is_overdue
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("remaining,expected", [
    (5,  False),
    (0,  False),
    (-1, True),
    (-14, True),
])
def test_is_overdue(remaining, expected):
    assert ks.is_overdue(0, remaining) is expected
