"""
sentinel.api.app
================
The HTTP surface. Deliberately small: fourteen routes, each with a stated
trust level.

Trust levels
  PUBLIC     no credentials (health check, the web app shell)
  CODE       requires a valid, unused, unexpired admin-minted enrolment code
  COLLECTOR  requires an active collector key scoped to the claimed segment
  ADMIN      requires the admin token

There is no route that hands out credentials without one of the above.
See SECURITY.md for the trust boundaries in prose.
"""

from __future__ import annotations

import json
import os
import time
import traceback
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, g, jsonify, request, send_from_directory

from sentinel.storage import db
from sentinel.detection import net_intel
from sentinel.detection import blast_radius

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

app = Flask(__name__, static_folder=None)


# ── boot ──────────────────────────────────────────────────────────────
# The schema and the admin account are created when this module is
# imported, which covers BOTH entry points: `python3 run.py` in
# development and `gunicorn sentinel.api.app:app` in production. Doing
# this only in run.py would leave a gunicorn deployment with no tables
# and no way to sign in.
def _boot():
    boot = db.init_db()
    if boot["first_boot"]:
        # Printed to stdout so it lands in the platform log (Render, Fly,
        # journalctl). It is shown exactly once and never stored in clear.
        banner = (
            "\n" + "=" * 62 +
            "\n  FIRST BOOT - admin credentials (shown once)"
            "\n    username: admin"
            f"\n    password: {boot['password']}"
            "\n  You will be required to change this at first sign-in."
            "\n" + "=" * 62 + "\n")
        print(banner, flush=True)


_boot()


# ── observability: a request ID on every response, traced 500s ────────

@app.before_request
def _trace_start():
    g.rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:8]
    g.t0 = time.time()


@app.after_request
def _trace_end(resp):
    resp.headers["X-Request-ID"] = getattr(g, "rid", "")
    if request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.errorhandler(500)
def _traced_500(e):
    rid = getattr(g, "rid", "--------")
    print(f"[ERROR rid={rid}] {request.method} {request.path}\n{traceback.format_exc()}")
    return jsonify({"error": "internal error", "request_id": rid}), 500


# ── rate limiting: a small fixed-window counter, per IP per bucket ────

_RATE: dict = defaultdict(deque)


def rate_limit(bucket: str, limit: int, window: int):
    """Reject with 429 when an IP exceeds `limit` calls to `bucket` per `window` s."""
    def deco(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            key = f"{bucket}:{request.remote_addr}"
            now = time.time()
            q = _RATE[key]
            while q and q[0] < now - window:
                q.popleft()
            if len(q) >= limit:
                return jsonify({"error": "rate limit exceeded",
                                "retry_after": int(window - (now - q[0]))}), 429
            q.append(now)
            return fn(*a, **kw)
        return wrapped
    return deco


# ── auth decorators ───────────────────────────────────────────────────

def require_admin(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        token = (request.headers.get("X-Admin-Token")
                 or request.args.get("token", ""))
        if not db.valid_admin_token(token):
            return jsonify({"error": "unauthorised"}), 401
        return fn(*a, **kw)
    return wrapped


# ── PUBLIC ────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})


@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(WEB_DIR, filename)


# ── ADMIN: authentication ─────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
@rate_limit("login", limit=10, window=300)
def login():
    d = request.get_json(silent=True) or {}
    token = db.verify_admin_password(str(d.get("username", "")), str(d.get("password", "")))
    if not token:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": token, "must_change": db.admin_must_change()})


@app.route("/api/admin/password", methods=["POST"])
@require_admin
def change_password():
    d = request.get_json(silent=True) or {}
    new = str(d.get("password", ""))
    if len(new) < 10:
        return jsonify({"error": "password must be at least 10 characters"}), 400
    return jsonify({"token": db.set_admin_password(new)})


# ── ADMIN: sensor enrolment (the only path to a collector key) ────────

@app.route("/api/admin/enrol-code", methods=["POST"])
@require_admin
def create_enrol_code():
    d = request.get_json(silent=True) or {}
    segment = str(d.get("segment", "")).strip()
    if not segment:
        return jsonify({"error": "segment required"}), 400
    return jsonify(db.mint_enrol_code(segment))


@app.route("/api/enrol", methods=["POST"])
@rate_limit("enrol", limit=int(os.environ.get("ENROL_LIMIT", "10")), window=600)
def enrol():
    """
    CODE trust level. A sensor exchanges an admin-minted, single-use,
    segment-scoped code for its own key. Without a valid code this returns
    401 — there is no unauthenticated path to a working credential.
    """
    d = request.get_json(silent=True) or {}
    result = db.redeem_enrol_code(str(d.get("code", "")), str(d.get("name", "sensor")))
    if not result:
        return jsonify({"error": "invalid, used, or expired enrolment code"}), 401
    return jsonify({
        "id": result["id"],
        "api_key": result["api_key"],
        "segment": result["segment"],
        "note": "Store this key now. It is not shown again.",
    })


@app.route("/api/admin/collectors")
@require_admin
def admin_collectors():
    return jsonify({"collectors": db.list_collectors()})


@app.route("/api/admin/collectors/<cid>", methods=["DELETE"])
@require_admin
def admin_revoke_collector(cid):
    return jsonify({"revoked": db.revoke_collector(cid)})


# ── COLLECTOR: the ingest path ────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@rate_limit("scan", limit=int(os.environ.get("SCAN_LIMIT", "120")), window=60)
def submit_scan():
    """
    COLLECTOR trust level. A sensor submits what it heard on its segment.
    The key must be active AND scoped to the segment being claimed.
    """
    d = request.get_json(silent=True) or {}
    segment = str(d.get("segment", "")).strip()[:60]
    if not segment:
        return jsonify({"error": "segment required"}), 400

    collector = db.authenticate_collector(
        request.headers.get("X-Collector-Key", "").strip(), segment)
    if not collector:
        return jsonify({"error": "unauthorised"}), 401

    finding = net_intel.analyse({
        "segment": segment,
        "expected_dhcp": str(d.get("expected_dhcp", "")).strip(),
        "dhcp_servers": d.get("dhcp_servers") or [],
        "arp": d.get("arp") or [],
        "lldp": d.get("lldp") or {},
        "history": db.rogue_history_for(segment),
    })

    db.touch_collector(collector["id"])
    db.record_finding(segment, collector["name"], bool(finding["rogue_count"]),
                      finding["worst_severity"], json.dumps(finding), finding["rogues"])

    return jsonify({
        "ok": True,
        "segment": segment,
        "rogue": bool(finding["rogue_count"]),
        "severity": finding["worst_severity"],
        "summary": net_intel.summarise(finding),
        "rogues": finding["rogues"],
    })


# ── ADMIN: findings ───────────────────────────────────────────────────

@app.route("/api/findings")
@require_admin
def findings():
    rows = db.latest_findings_by_segment()
    out = []
    for r in rows:
        try:
            f = json.loads(r["finding"] or "{}")
        except Exception:
            f = {}
        out.append({
            "segment": r["segment"],
            "collector": r["collector"],
            "ts": r["ts"],
            "severity": r["severity"],
            "rogue": bool(r["rogue"]),
            "rogues": f.get("rogues", []),
            "devices_on_segment": f.get("devices_on_segment", 0),
            "location_hint": f.get("location_hint"),
        })
    return jsonify({
        "segments": out,
        "total_segments": len(out),
        "rogue_count": sum(1 for o in out if o["rogue"]),
        "worst_severity": max([o["severity"] for o in out] or [0]),
    })


@app.route("/api/blast-radius/<segment>")
@require_admin
def blast_radius_for(segment):
    """
    Dependency impact for one segment, built from what the sensors actually
    observed. Every node and edge traces to an observation; nothing is
    invented. See METHODOLOGY.md.
    """
    rows = db.latest_findings_by_segment()
    match = next((r for r in rows if r["segment"] == segment), None)
    if not match:
        return jsonify({"error": "no findings for that segment"}), 404
    try:
        finding = json.loads(match["finding"] or "{}")
    except Exception:
        finding = {}
    return jsonify(blast_radius.analyse(finding))


@app.route("/api/collectors/status")
@require_admin
def collectors_status():
    cols = db.list_collectors()
    return jsonify({
        "collectors": cols,
        "active": sum(1 for c in cols if c["active"]),
        "any_reporting": any(c["last_seen"] for c in cols),
    })
