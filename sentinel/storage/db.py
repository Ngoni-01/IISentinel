"""
sentinel.storage.db
===================
All persistence for Sentinel. Relational only (SQLite/WAL): the device
registry, users, enrolment codes, collectors, and findings. High-frequency
time-series is deliberately NOT split into a separate store yet — see
ADR-004 in ARCHITECTURE.md; the measured ceiling is in that document.

Security-relevant tables live here and the trust boundary is enforced at
this layer:
  - admin           : one row, created on first boot with a RANDOM password
  - enrol_code      : short-lived, single-use codes minted by an admin;
                      the ONLY way to obtain a collector key
  - collector       : an enrolled sensor, scoped to one segment
  - finding         : the output of the detection engine
  - rogue_history   : persistence tracking for severity scoring
"""

from __future__ import annotations

import os
import sqlite3
import hashlib
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timezone

try:
    from werkzeug.security import generate_password_hash, check_password_hash
except Exception:  # pragma: no cover - werkzeug always present in requirements
    import hashlib

    def generate_password_hash(p):
        salt = secrets.token_hex(16)
        return "sha256$" + salt + "$" + hashlib.sha256((salt + p).encode()).hexdigest()

    def check_password_hash(h, p):
        try:
            _, salt, dig = h.split("$", 2)
            return secrets.compare_digest(
                dig, hashlib.sha256((salt + p).encode()).hexdigest())
        except Exception:
            return False


DB_PATH = os.environ.get("DB_PATH") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "sentinel.db")


def _key_lookup(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    """A short-lived connection in WAL mode. Callers use `with connect() as c`."""
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
        con.execute("PRAGMA foreign_keys=ON")
        yield con
        con.commit()
    finally:
        con.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    token         TEXT NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrol_code (
    code       TEXT PRIMARY KEY,
    segment    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    used_by    TEXT
);

CREATE TABLE IF NOT EXISTS collector (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    api_key_hash  TEXT NOT NULL,
    key_lookup    TEXT NOT NULL DEFAULT '',
    segment       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_seen     TEXT,
    scan_count    INTEGER NOT NULL DEFAULT 0,
    active        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_collector_lookup ON collector(key_lookup);

CREATE TABLE IF NOT EXISTS finding (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    segment    TEXT NOT NULL,
    collector  TEXT,
    ts         TEXT NOT NULL,
    rogue      INTEGER NOT NULL DEFAULT 0,
    severity   INTEGER NOT NULL DEFAULT 0,
    finding    TEXT
);
CREATE INDEX IF NOT EXISTS idx_finding_ts ON finding(ts DESC);
CREATE INDEX IF NOT EXISTS idx_finding_seg ON finding(segment);

CREATE TABLE IF NOT EXISTS rogue_history (
    ip         TEXT NOT NULL,
    segment    TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 1,
    mac        TEXT,
    vendor     TEXT,
    PRIMARY KEY (ip, segment)
);

CREATE TABLE IF NOT EXISTS setting (
    k TEXT PRIMARY KEY,
    v TEXT
);
"""


def init_db() -> dict:
    """
    Create the schema and ensure exactly one admin exists.

    On first boot, generates a RANDOM admin password and returns it ONCE so
    the operator can capture it. There is no default password anywhere.
    Returns {'first_boot': bool, 'password': str|None, 'token': str}.
    """
    with connect() as con:
        con.executescript(SCHEMA)
        row = con.execute("SELECT token FROM admin WHERE id = 1").fetchone()
        if row:
            return {"first_boot": False, "password": None, "token": row["token"]}

        # first boot — mint a random password and token
        password = _readable_secret()
        token = secrets.token_hex(24)
        con.execute(
            "INSERT INTO admin (id, username, password_hash, token, must_change, created_at) "
            "VALUES (1, ?, ?, ?, 1, ?)",
            ("admin", generate_password_hash(password), token, _now()))
        return {"first_boot": True, "password": password, "token": token}


def _readable_secret(words: int = 4) -> str:
    """A random but human-typable password: e.g. 'amber-mesa-7419-quill'."""
    parts = [
        "amber", "mesa", "quill", "delta", "harbor", "vector", "cobalt",
        "ember", "granite", "ionic", "jasper", "kelvin", "lumen", "nexus",
        "onyx", "pixel", "quartz", "raven", "sable", "tundra",
    ]
    pick = [secrets.choice(parts) for _ in range(words - 1)]
    pick.insert(words // 2, str(secrets.randbelow(9000) + 1000))
    return "-".join(pick)


# ── admin auth ────────────────────────────────────────────────────────

def verify_admin_password(username: str, password: str) -> str | None:
    with connect() as con:
        row = con.execute(
            "SELECT username, password_hash, token FROM admin WHERE id = 1").fetchone()
    if not row:
        return None
    if username != row["username"]:
        return None
    if not check_password_hash(row["password_hash"], password):
        return None
    return row["token"]


def valid_admin_token(token: str) -> bool:
    if not token:
        return False
    with connect() as con:
        row = con.execute("SELECT token FROM admin WHERE id = 1").fetchone()
    return bool(row) and secrets.compare_digest(token, row["token"])


def set_admin_password(new_password: str) -> str:
    """Set a new password, rotate the token, clear must_change. Returns new token."""
    token = secrets.token_hex(24)
    with connect() as con:
        con.execute(
            "UPDATE admin SET password_hash = ?, token = ?, must_change = 0 WHERE id = 1",
            (generate_password_hash(new_password), token))
    return token


def admin_must_change() -> bool:
    with connect() as con:
        row = con.execute("SELECT must_change FROM admin WHERE id = 1").fetchone()
    return bool(row) and bool(row["must_change"])


# ── enrolment codes: the only path to a collector key ─────────────────

def mint_enrol_code(segment: str, ttl_seconds: int = 900) -> dict:
    """Admin-only. Create a single-use, short-lived enrolment code for a segment."""
    code = "-".join(secrets.token_hex(2).upper() for _ in range(3))  # e.g. 3F2A-9C11-B0D4
    with connect() as con:
        con.execute(
            "INSERT INTO enrol_code (code, segment, created_at, expires_at, used) "
            "VALUES (?, ?, ?, ?, 0)",
            (code, segment[:60], _now(), time.time() + ttl_seconds))
    return {"code": code, "segment": segment[:60], "expires_in": ttl_seconds}


def redeem_enrol_code(code: str, collector_name: str) -> dict | None:
    """
    Exchange a valid, unused, unexpired enrolment code for a collector key.
    Returns {'id', 'api_key', 'segment'} or None if the code is invalid.
    The raw api_key is returned ONCE; only its hash is stored.
    """
    code = (code or "").strip().upper()
    with connect() as con:
        row = con.execute("SELECT * FROM enrol_code WHERE code = ?", (code,)).fetchone()
        if not row or row["used"] or row["expires_at"] < time.time():
            return None

        api_key = secrets.token_hex(32)
        cid = "col-" + secrets.token_hex(4)
        con.execute(
            "INSERT INTO collector (id, name, api_key_hash, key_lookup, segment, created_at, active) "
            "VALUES (?, ?, ?, ?, ?, ?, 1)",
            (cid, (collector_name or "sensor")[:60],
             generate_password_hash(api_key), _key_lookup(api_key),
             row["segment"], _now()))
        con.execute("UPDATE enrol_code SET used = 1, used_by = ? WHERE code = ?",
                    (cid, code))
        return {"id": cid, "api_key": api_key, "segment": row["segment"]}


# ── collector authentication + scoping ────────────────────────────────

def authenticate_collector(api_key: str, claimed_segment: str) -> dict | None:
    """
    Validate a collector key AND that it is scoped to the segment it claims.
    A key enrolled for 'floor-3' cannot submit findings for 'core'. Returns
    the collector row as a dict, or None on any failure.
    """
    if not api_key:
        return None
    lookup = _key_lookup(api_key)
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM collector WHERE active = 1 AND key_lookup = ?",
            (lookup,)).fetchall()
    for row in rows:  # normally 0 or 1 rows; verify the real hash regardless
        if check_password_hash(row["api_key_hash"], api_key):
            if claimed_segment and row["segment"] not in (claimed_segment, "*"):
                return None
            return dict(row)
    return None


def touch_collector(collector_id: str) -> None:
    with connect() as con:
        con.execute(
            "UPDATE collector SET last_seen = ?, scan_count = scan_count + 1 WHERE id = ?",
            (_now(), collector_id))


def list_collectors() -> list:
    with connect() as con:
        rows = con.execute(
            "SELECT id, name, segment, created_at, last_seen, scan_count, active "
            "FROM collector ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def revoke_collector(collector_id: str) -> bool:
    with connect() as con:
        cur = con.execute("UPDATE collector SET active = 0 WHERE id = ?", (collector_id,))
    return cur.rowcount > 0


# ── findings + history ────────────────────────────────────────────────

def rogue_history_for(segment: str) -> dict:
    out = {}
    with connect() as con:
        for r in con.execute(
                "SELECT ip, count, first_seen FROM rogue_history WHERE segment = ?",
                (segment,)).fetchall():
            out[r["ip"]] = {"count": r["count"], "first_seen": r["first_seen"]}
    return out


def record_finding(segment: str, collector: str, rogue: bool, severity: int,
                   finding_json: str, rogues: list) -> None:
    ts = _now()
    with connect() as con:
        con.execute(
            "INSERT INTO finding (segment, collector, ts, rogue, severity, finding) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (segment, collector, ts, 1 if rogue else 0, severity, finding_json))
        con.execute("DELETE FROM finding WHERE id NOT IN "
                    "(SELECT id FROM finding ORDER BY id DESC LIMIT 5000)")
        for r in rogues:
            con.execute(
                "INSERT INTO rogue_history (ip, segment, first_seen, last_seen, count, mac, vendor) "
                "VALUES (?, ?, ?, ?, 1, ?, ?) "
                "ON CONFLICT(ip, segment) DO UPDATE SET "
                "last_seen = excluded.last_seen, count = count + 1, "
                "mac = excluded.mac, vendor = excluded.vendor",
                (r.get("ip"), segment, ts, ts, r.get("mac", ""), r.get("vendor", "Unknown")))


def latest_findings_by_segment() -> list:
    """Most recent finding per segment — powers the dashboard."""
    with connect() as con:
        rows = con.execute(
            "SELECT f.* FROM finding f INNER JOIN "
            "(SELECT segment, MAX(id) mid FROM finding GROUP BY segment) l "
            "ON f.id = l.mid ORDER BY f.severity DESC, f.segment").fetchall()
    return [dict(r) for r in rows]


def recent_findings(limit: int = 50) -> list:
    with connect() as con:
        rows = con.execute(
            "SELECT id, segment, collector, ts, rogue, severity FROM finding "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_setting(key: str, default=None):
    with connect() as con:
        row = con.execute("SELECT v FROM setting WHERE k = ?", (key,)).fetchone()
    return row["v"] if row else default


def set_setting(key: str, value: str) -> None:
    with connect() as con:
        con.execute("INSERT OR REPLACE INTO setting (k, v) VALUES (?, ?)", (key, str(value)))
