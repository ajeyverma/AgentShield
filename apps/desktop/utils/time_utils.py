"""
AgentShield AI — Timezone & Timestamp Formatting Utilities.
Converts UTC database/API timestamps to Indian Standard Time (IST, UTC+05:30).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

# Indian Standard Time (UTC+05:30)
IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def to_ist_str(
    val: Any,
    with_tz: bool = False,
    time_only: bool = False,
    include_seconds: bool = True,
) -> str:
    """
    Convert a UTC datetime, ISO timestamp string, or epoch to an Indian Standard Time (IST) string.

    Parameters:
        val: ISO string (e.g. '2026-11-25T01:10:42Z'), datetime object, or None
        with_tz: Whether to append 'IST' suffix (e.g. '2026-11-25 06:40:42 IST')
        time_only: Only return HH:MM or HH:MM:SS
        include_seconds: Include seconds in the output
    """
    if not val:
        return "-"

    dt: datetime | None = None

    if isinstance(val, datetime):
        dt = val
    elif isinstance(val, (int, float)):
        try:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
        except Exception:
            return str(val)
    elif isinstance(val, str):
        cleaned = val.strip().replace("Z", "+00:00")
        # Try standard ISO parsing
        try:
            dt = datetime.fromisoformat(cleaned)
        except Exception:
            # Fallback parsing for common date-time strings
            for fmt in (
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M",
            ):
                try:
                    dt = datetime.strptime(cleaned[:19], fmt)
                    break
                except Exception:
                    pass

    if dt is None:
        return str(val)[:19]

    # Assume naive datetimes from DB are UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # Convert to IST
    ist_dt = dt.astimezone(IST)

    sec_fmt = ":%S" if include_seconds else ""
    if time_only:
        fmt = f"%H:%M{sec_fmt}"
    else:
        fmt = f"%Y-%m-%d %H:%M{sec_fmt}"

    res = ist_dt.strftime(fmt)
    if with_tz:
        res = f"{res} IST"
    return res


def now_ist() -> datetime:
    """Return current timezone-aware datetime in Indian Standard Time."""
    return datetime.now(IST)
