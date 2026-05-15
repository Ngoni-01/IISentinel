"""
iis_timezone.py — Africa/Harare timezone helper
================================================
Drop next to app.py. Import with:
    from iis_timezone import now_harare, to_harare, fmt_harare, TZ

Fixes the UTC+0 vs UTC+2 shift report problem.
Zimbabwe is UTC+2 year-round (no DST).
"""

from __future__ import annotations
import os
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

# Configurable via environment: TZ=Africa/Harare (default)
TZ_NAME = os.environ.get("TZ_NAME", "Africa/Harare")
TZ      = ZoneInfo(TZ_NAME)
UTC2    = timezone(timedelta(hours=2))   # fallback if zoneinfo unavailable


def now_harare() -> datetime:
    """Current datetime in Africa/Harare."""
    return datetime.now(TZ)


def to_harare(dt: datetime) -> datetime:
    """Convert any datetime to Africa/Harare."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ)


def fmt_harare(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str:
    """Format a datetime in Africa/Harare timezone."""
    return to_harare(dt).strftime(fmt)


def utc_iso_to_harare_str(utc_iso: str) -> str:
    """
    Convert a UTC ISO string (from the DB) to a human-readable Harare string.

    Example:
        utc_iso_to_harare_str("2024-06-01T04:00:00+00:00")
        → "2024-06-01 06:00:00 CAT"
    """
    try:
        dt = datetime.fromisoformat(utc_iso.replace("Z", "+00:00"))
        return fmt_harare(dt)
    except Exception:
        return utc_iso   # return as-is if parsing fails


# ─────────────────────────────────────────────────────────────────────────────
# HOW TO INTEGRATE INTO app.py
# ─────────────────────────────────────────────────────────────────────────────
# 1. At the top of app.py, add:
#        from iis_timezone import now_harare, fmt_harare, utc_iso_to_harare_str
#
# 2. Replace all datetime.now(timezone.utc).isoformat() with:
#        now_harare().isoformat()           ← stores as UTC+2 in DB
#    OR keep storing UTC in DB and display in Harare:
#        utc_iso_to_harare_str(row['created_at'])  ← in report generation
#
# 3. In shift_report generation (wherever you build PDF/HTML reports):
#    Replace:
#        datetime.now(timezone.utc).strftime(...)
#    With:
#        now_harare().strftime("%Y-%m-%d %H:%M:%S CAT")
#
# 4. For maintenance windows, when checking if "now" is inside a window:
#    Replace:
#        now = datetime.now(timezone.utc)
#    With:
#        now = now_harare()
#    (Both work as long as the stored timestamps use the same reference)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Timezone: {TZ_NAME}")
    print(f"Current time in Harare: {fmt_harare(now_harare())}")
    print(f"UTC right now:          {datetime.now(timezone.utc).isoformat()}")
    test_utc = "2024-06-01T04:00:00+00:00"
    print(f"UTC {test_utc} → Harare: {utc_iso_to_harare_str(test_utc)}")
