"""Kanban SLO / SLA helpers — single source of truth for priority-based deadlines.

Extracted from ``scripts/morning_brief.py`` so the live ``hermes kanban list``
output and the morning brief render the same overdue badge. Anyone who needs
"how many days does a priority-X task have before it goes red?" imports from
here.

The mapping below is the canonical contract; do not change the priority→day
table without an explicit user request (the morning brief and any cron
dashboards depend on it being stable).

Usage:

    from hermes_cli.kanban_sla import (
        PRIORITY_SLA_DAYS, sla_deadline, sla_badge, format_overdue,
    )

    deadline, days_left = sla_deadline(created_at, priority, now)
    # days_left < 0 means the task is past its SLA.

    sla_badge(deadline, days_left)           # "🚨 3d overdue" or "⏰ 5d"
    format_overdue(deadline, days_left)      # "🚨 3d overdue"
"""

from __future__ import annotations

from typing import Tuple

# Priority 0/1 = low (SLA 14 days), 2-3 = normal (7), 4-5 = high (3), 6-7 = urgent (2),
# 8-9 = critical (1), 10 = fire (same day).
# Do not change this without explicit user request — see module docstring.
PRIORITY_SLA_DAYS: dict[int, int] = {
    0: 14, 1: 14,
    2: 7,  3: 7,
    4: 3,  5: 3,
    6: 2,  7: 2,
    8: 1,  9: 1,
    10: 0,
}

# Default SLA for unknown priorities (defensive — the brief script used 14).
DEFAULT_SLA_DAYS = 14

_SECONDS_PER_DAY = 86400

# Output strings — kept here so the morning brief and ``hermes kanban list``
# always agree on the exact wording/emoji. If we ever need a locale variant
# (e.g. an "ascii" mode for log scrapers) this is the single hook.
SLA_OK_PREFIX = "⏰"          # within budget
SLA_OK_FORMAT = "{prefix} {days}d"
SLA_OVERDUE_PREFIX = "🚨"     # past SLA
SLA_OVERDUE_FORMAT = "{prefix} {days}d overdue"


def sla_days(priority: int) -> int:
    """Return the SLA window in days for *priority* (defaults to 14 for unknowns)."""
    return PRIORITY_SLA_DAYS.get(priority, DEFAULT_SLA_DAYS)


def sla_deadline(created_at: int, priority: int, now: int) -> Tuple[int, int]:
    """Return ``(deadline_unix_ts, days_remaining)``.

    ``days_remaining`` is computed with day-granularity floor division, so a
    task that is 6 hours past its SLA already reports ``days_remaining == -1``
    — the floor biases toward "alarm" so the cron can't miss a slipped task
    at a clock-boundary edge. The badges and overdue filters all use this
    same rounding.
    """
    deadline = created_at + sla_days(priority) * _SECONDS_PER_DAY
    remaining = (deadline - now) // _SECONDS_PER_DAY
    return deadline, remaining


def sla_badge(deadline: int, days_remaining: int) -> str:
    """Render the inline badge for a task row.

    >>> sla_badge(0, 3)
    '⏰ 3d'
    >>> sla_badge(0, -3)
    '🚨 3d overdue'
    """
    if days_remaining < 0:
        return SLA_OVERDUE_FORMAT.format(
            prefix=SLA_OVERDUE_PREFIX, days=abs(days_remaining)
        )
    return SLA_OK_FORMAT.format(prefix=SLA_OK_PREFIX, days=days_remaining)


def is_overdue(deadline: int, days_remaining: int) -> bool:
    """True when the task is past its priority-based SLA."""
    return days_remaining < 0
