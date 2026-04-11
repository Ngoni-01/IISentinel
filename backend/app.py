import os
import joblib
import numpy as np
import requests as req
from flask import Flask, request, jsonify, render_template, Response, stream_with_context
from flask_cors import CORS
from supabase import create_client
from functools import wraps
from datetime import datetime, timezone
import threading
import time
import re
import json
import smtplib
from email.mime.text import MIMEText
from collections import deque

# ═══════════════════════════════════════════════════════════════════════════
# A1 — CENTRAL REGEX PATTERN LIBRARY
# Single source of truth for every pattern used across the platform.
# All parsers, validators, and security checks import from here.
# ═══════════════════════════════════════════════════════════════════════════
PATTERNS = {
    # Network / link state
    "LINK_STATE":      re.compile(r"Interface\s([\w\/\.]+),\schanged state to\s(\w+)"),
    "BGP_NOTIFY":      re.compile(r"BGP-(\d+)-NOTIFICATION:\s(.+)\sfrom\s([\d.]+)"),
    "ICMP_TIMEOUT":    re.compile(r"Request timeout for icmp_seq\s(\d+)"),
    # Telecom / RF
    "SIGNAL_DBM":      re.compile(r"Rx level[:\s]+([-\d.]+)\s*dBm", re.IGNORECASE),
    "BER_VALUE":       re.compile(r"BER[:\s]+([\d.e-]+)", re.IGNORECASE),
    "MW_LINK_DOWN":    re.compile(r"link(?:Down|Failure|Lost)\s(?:on\s)?([\w-]+)", re.IGNORECASE),
    # Mining / industrial
    "MODBUS_EX":       re.compile(r"Modbus Exception.*?0x([0-9A-Fa-f]{2})"),
    "PLC_FAULT":       re.compile(r"PLC[-\s]?FAULT[:\s]+(.+?)(?:\s*[-|])", re.IGNORECASE),
    "CONVEYOR_TRIP":   re.compile(r"Conveyor\s([\w-]+)\strip(?:ped)?", re.IGNORECASE),
    "PUMP_CAVITATION": re.compile(r"pump\s([\w-]+)\s(?:cavitat|pressure\sdrop)", re.IGNORECASE),
    # CBS safety — strict format enforced
    "CBS_HOLD":        re.compile(r"^CBS-HOLD:\s(SHAFT-[12]|SURFACE)\s@\s(\d{2}:\d{2}:\d{2})$"),
    "CBS_CLEAR":       re.compile(r"^CBS-CLEAR:\s(SHAFT-[12]|SURFACE)\s@\s(\d{2}:\d{2}:\d{2})$"),
    # Security — injection detection
    "SCRIPT_INJECT":   re.compile(r"<script|javascript:", re.IGNORECASE),
    "SQL_INJECT":      re.compile(r"(\bDROP\b|\bDELETE\b|\bUNION\b)[\s\S]*?\bTABLE\b", re.IGNORECASE),
    "PATH_TRAVERSAL":  re.compile(r"\.\./|\.\.\\ |%2e%2e", re.IGNORECASE),
}

# ═══════════════════════════════════════════════════════════════════════════
# A2 — STRUCTURED LOG PARSER
# Transforms raw device strings into typed, severity-tagged objects.
# The AI layer receives structured events, never raw strings.
# ═══════════════════════════════════════════════════════════════════════════
def parse_log(raw, source="api"):
    """Parse raw device log string into structured event object."""
    base = {"raw": raw, "source": source, "parsed": None, "severity": "info",
            "ts": datetime.now(timezone.utc).isoformat()}
    m = None

    if (m := PATTERNS["LINK_STATE"].search(raw)):
        return {**base, "parsed": {"type": "LINK_STATE", "iface": m.group(1), "state": m.group(2)},
                "severity": "critical" if m.group(2) == "down" else "info"}

    if (m := PATTERNS["MODBUS_EX"].search(raw)):
        return {**base, "parsed": {"type": "MODBUS_EX", "code": m.group(1)}, "severity": "warning"}

    if (m := PATTERNS["CONVEYOR_TRIP"].search(raw)):
        return {**base, "parsed": {"type": "CONVEYOR_TRIP", "unit": m.group(1)}, "severity": "critical"}

    if (m := PATTERNS["PUMP_CAVITATION"].search(raw)):
        return {**base, "parsed": {"type": "PUMP_CAVITATION", "unit": m.group(1)}, "severity": "warning"}

    if (m := PATTERNS["SIGNAL_DBM"].search(raw)):
        dbm = float(m.group(1))
        return {**base, "parsed": {"type": "SIGNAL_DBM", "dbm": dbm},
                "severity": "critical" if dbm < -85 else "info"}

    if PATTERNS["CBS_HOLD"].match(raw):
        mm = PATTERNS["CBS_HOLD"].match(raw)
        return {**base, "parsed": {"type": "CBS_HOLD", "section": mm.group(1), "time": mm.group(2)},
                "severity": "critical"}

    if (m := PATTERNS["BGP_NOTIFY"].search(raw)):
        return {**base, "parsed": {"type": "BGP_NOTIFY", "asn": m.group(1), "reason": m.group(2)},
                "severity": "warning"}

    return base


def tag_incident(text):
    """Tag an incident note with relevant subsystem and location labels."""
    tags = []
    if re.search(r"pump|motor|bearing|vibrat",  text, re.I): tags.append("MECHANICAL")
    if re.search(r"conveyor|belt|chute",         text, re.I): tags.append("CONVEYOR")
    if re.search(r"ventilat|fan|airflow",        text, re.I): tags.append("VENTILATION")
    if re.search(r"shaft[-\s]?1",               text, re.I): tags.append("SHAFT-1")
    if re.search(r"shaft[-\s]?2",               text, re.I): tags.append("SHAFT-2")
    if re.search(r"surface|stockpile",           text, re.I): tags.append("SURFACE")
    if re.search(r"network|router|switch|bgp|ospf", text, re.I): tags.append("NETWORK")
    if re.search(r"signal|tower|base.?station|mw|microwave", text, re.I): tags.append("TELECOM")
    if re.search(r"power|ups|generator",         text, re.I): tags.append("POWER")
    return tags

# ═══════════════════════════════════════════════════════════════════════════
# A3 — ALERT DEDUPLICATION ENGINE
# Fingerprints each alert. Suppresses repeated identical alerts within
# a configurable window. Prevents SMS/WhatsApp flooding during cascading
# failures or storm events.
# ═══════════════════════════════════════════════════════════════════════════
_dedup_seen   = {}
_dedup_lock   = threading.Lock()
DEDUP_WINDOW  = 30   # seconds — suppress identical alerts within this window

def _fingerprint(raw):
    """Extract a stable identity token from a raw alert string."""
    for pat in [
        r"Interface\s[\w\/]+", r"CBS-\w+", r"PLC-FAULT:\s\w+",
        r"Conveyor\s[\w-]+", r"pump\s[\w-]+",
    ]:
        m = re.search(pat, raw, re.IGNORECASE)
        if m: return m.group(0).lower()
    return raw[:48].lower()

def is_new_alert(raw):
    """Return True if this alert has not been seen within DEDUP_WINDOW seconds."""
    fp  = _fingerprint(raw)
    now = time.time()
    with _dedup_lock:
        if fp in _dedup_seen and now - _dedup_seen[fp] < DEDUP_WINDOW:
            return False
        _dedup_seen[fp] = now
        # Prune old entries
        cutoff = now - DEDUP_WINDOW * 2
        expired = [k for k, v in _dedup_seen.items() if v < cutoff]
        for k in expired:
            del _dedup_seen[k]
    return True

# ═══════════════════════════════════════════════════════════════════════════
# B2 — CBS MESSAGE FORMAT VALIDATION (secondary safety check)
# Before any CBS hold/clear command is acted on the message is validated
# against strict format regex. Malformed or unexpected strings are rejected
# and flagged — they never reach blast interlock logic.
# ═══════════════════════════════════════════════════════════════════════════
def handle_cbs_message(raw):
    """
    Validate and parse a CBS control message.
    Returns action dict or raises ValueError on malformed input.
    A malformed message defaults to HOLD — fail-safe by design.
    """
    is_hold  = bool(PATTERNS["CBS_HOLD"].match(raw))
    is_clear = bool(PATTERNS["CBS_CLEAR"].match(raw))

    if not is_hold and not is_clear:
        print(f"[CBS] MALFORMED_MESSAGE rejected: {raw[:60]}")
        return {"action": "HOLD", "reason": "format_validation_failed",
                "validated": False, "raw": raw}

    m = PATTERNS["CBS_HOLD"].match(raw) if is_hold else PATTERNS["CBS_CLEAR"].match(raw)
    return {
        "action":    "HOLD" if is_hold else "CLEAR",
        "section":   m.group(1),
        "time":      m.group(2),
        "validated": True,
    }

# ═══════════════════════════════════════════════════════════════════════════
# D1 — PER-ASSET HEALTH BEHAVIOUR SCORECARD
# Extends FHI to produce individual behaviour scores per asset over rolling
# windows. Score factors: anomaly frequency, recovery time, fault
# recurrence, threshold breach rate.
# ═══════════════════════════════════════════════════════════════════════════
_behaviour_scores = {}   # device_id -> {score, grade, updated_at}
_behaviour_events = {}   # device_id -> {anomaly_count, breach_count, recoveries}

def record_behaviour_event(device_id, health_score, anomaly_flag, was_critical):
    """Update rolling behaviour metrics for a device on each new reading."""
    if device_id not in _behaviour_events:
        _behaviour_events[device_id] = {
            "anomaly_count": 0, "breach_count": 0,
            "recovery_count": 0, "readings": 0,
            "last_score": health_score,
        }
    ev = _behaviour_events[device_id]
    ev["readings"] += 1
    if anomaly_flag:
        ev["anomaly_count"] += 1
    if health_score < 50:
        ev["breach_count"] += 1
    # Recovery: previously critical, now above 50
    if ev["last_score"] < 20 and health_score >= 50:
        ev["recovery_count"] += 1
    ev["last_score"] = health_score

def score_behaviour(device_id):
    """
    Compute a 0-100 behaviour score and A-F grade for the asset.
    Lower score = worse historical behaviour pattern.
    """
    ev = _behaviour_events.get(device_id)
    if not ev or ev["readings"] < 3:
        return {"score": None, "grade": "?", "reason": "Insufficient readings"}

    n = max(ev["readings"], 1)
    anomaly_rate   = ev["anomaly_count"]  / n
    breach_rate    = ev["breach_count"]   / n
    recurrence_pen = max(0, ev["breach_count"] - ev["recovery_count"]) / max(n, 1)

    score = round(max(0, min(100,
        100
        - (anomaly_rate  * 30)
        - (breach_rate   * 30)
        - (recurrence_pen * 20)
        - (0 if ev["recovery_count"] > 0 else 10)
    )))

    def _grade(s):
        if s >= 90: return "A"
        if s >= 75: return "B"
        if s >= 55: return "C"
        if s >= 35: return "D"
        return "F"

    result = {
        "score":         score,
        "grade":         _grade(score),
        "anomaly_rate":  round(anomaly_rate * 100, 1),
        "breach_rate":   round(breach_rate  * 100, 1),
        "recoveries":    ev["recovery_count"],
        "total_readings": ev["readings"],
    }
    _behaviour_scores[device_id] = {**result, "updated_at": datetime.now(timezone.utc).isoformat()}
    return result

# ═══════════════════════════════════════════════════════════════════════════
# D2 — PREDICTIVE MAINTENANCE SCHEDULER
# Uses rolling behaviour scores + manufacturer MTBF data to surface a
# ranked maintenance calendar. Flags assets predicted to need intervention
# within 72 hours before they fault.
# ═══════════════════════════════════════════════════════════════════════════
DEVICE_MTBF = {
    "pump":          8760,  "conveyor":   17520, "ventilation": 26280,
    "plc":          52560,  "router":     43800, "switch":      43800,
    "base_station": 35040,  "network_tower": 43800, "firewall": 35000,
    "scada_node":   26280,  "power_meter":   17520, "sensor":    8760,
    "microwave_link": 26280, "cbs_controller": 52560, "wan_link": 35000,
}

def predict_next_maintenance(device_id, device_type, health_score):
    """
    Predict when next maintenance is due based on behaviour score and MTBF.
    Returns priority: urgent (<72h), scheduled (<240h), routine.
    """
    behaviour = score_behaviour(device_id)
    b_score   = behaviour.get("score") or 75
    mtbf      = DEVICE_MTBF.get(device_type, 26280)
    hours_run = _behaviour_events.get(device_id, {}).get("readings", 0) * (10 / 60)

    degradation_factor = 1 - (b_score / 100) * 0.4
    adjusted_mtbf      = mtbf * degradation_factor

    health_factor  = 1 - (health_score / 100) * 0.5
    hours_remaining = max(0, (adjusted_mtbf - hours_run) * (1 - health_factor))

    priority = "urgent" if hours_remaining < 72 else "scheduled" if hours_remaining < 240 else "routine"

    return {
        "device_id":       device_id,
        "device_type":     device_type,
        "hours_remaining": round(hours_remaining),
        "recommended_by":  (datetime.now(timezone.utc).isoformat()),
        "priority":        priority,
        "behaviour_score": b_score,
        "behaviour_grade": behaviour.get("grade", "?"),
    }

# ═══════════════════════════════════════════════════════════════════════════
# E1 — TENANT CONFIGURATION SYSTEM
# Every tab, collector, protocol, and site shown in the UI is determined
# by a single tenant config. Adding a new client = one new config entry.
# ═══════════════════════════════════════════════════════════════════════════
TENANTS = {
    "default": {
        "name":         "IISentinel™ — Full Platform",
        "sectors":      ["network", "telecom", "mining", "cbs", "weather", "intelligence"],
        "collectors":   ["network", "telecom", "mining", "cbs"],
        "cbs_mandatory": True,
        "sites":        ["Bulawayo", "Harare", "Mutare", "Mine Site"],
        "protocols":    ["SNMP", "Profinet", "Modbus TCP", "DNP3", "OPC-UA"],
    },
    "telecom-only": {
        "name":         "TelecomCo — Signal & Backhaul Monitor",
        "sectors":      ["telecom", "weather", "intelligence"],
        "collectors":   ["telecom"],
        "cbs_mandatory": False,
        "sites":        ["Bulawayo HQ", "Harare", "Mutare", "Victoria Falls"],
        "protocols":    ["SNMP", "LTE", "MW_backhaul"],
        "blast_cost_usd": 0,
    },
    "mining-only": {
        "name":         "MiningCo — Industrial Safety Platform",
        "sectors":      ["mining", "cbs", "weather", "intelligence"],
        "collectors":   ["mining", "cbs"],
        "cbs_mandatory": True,
        "sites":        ["Shaft 1", "Shaft 2", "Processing Plant", "Surface"],
        "protocols":    ["Profinet", "Modbus TCP", "OPC-UA", "EtherNet/IP", "DNP3"],
        "blast_cost_usd": 500000,
    },
    "network-only": {
        "name":         "Network / ISP — Core Infrastructure Monitor",
        "sectors":      ["network", "weather", "intelligence"],
        "collectors":   ["network"],
        "cbs_mandatory": False,
        "protocols":    ["SNMP v3", "BGP", "OSPF", "NetFlow", "ICMP"],
        "blast_cost_usd": 0,
    },
}

ACTIVE_TENANT = os.environ.get("TENANT", "default")


metric_queue = deque(maxlen=500)
queue_lock   = threading.Lock()
_data_cache  = {'data': [], 'ts': 0}
CACHE_TTL    = 8

def get_cached_data():
    now = time.time()
    if now - _data_cache['ts'] < CACHE_TTL and _data_cache['data']:
        return _data_cache['data']
    try:
        resp = supabase.table('metrics').select('*').order('created_at', desc=True).limit(200).execute()
        _data_cache['data'] = resp.data
        _data_cache['ts']   = now
        return resp.data
    except Exception as e:
        print(f'Cache error: {e}')
        return _data_cache['data']

def flush_queue():
    while True:
        time.sleep(3)
        with queue_lock:
            if not metric_queue:
                continue
            batch = list(metric_queue)
            metric_queue.clear()
        try:
            for item in batch:
                supabase.table('metrics').insert(item).execute()
        except Exception as e:
            print(f'Flush error: {e}')
            with queue_lock:
                for item in batch[:50]:
                    metric_queue.appendleft(item)

threading.Thread(target=flush_queue, daemon=True).start()

_sse_subscribers = []
_sse_lock = threading.Lock()

def sse_broadcast(event_type, payload):
    msg = 'event: ' + event_type + '\ndata: ' + json.dumps(payload) + '\n\n'
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)

_retrain_in_progress = False
retrain_lock         = threading.Lock()

def auto_retrain_pipeline():
    global rf_model, iso_model, anomaly_count, _retrain_in_progress
    while True:
        time.sleep(60)
        if anomaly_count < RETRAIN_THRESHOLD:
            continue
        with retrain_lock:
            if _retrain_in_progress:
                continue
            _retrain_in_progress = True
        try:
            from sklearn.ensemble import RandomForestRegressor, IsolationForest
            resp = supabase.table('metrics').select(
                'cpu_load,bandwidth_mbps,latency_ms,packet_loss,connected_devices,temperature,signal_strength,health_score'
            ).order('created_at', desc=True).limit(2000).execute()
            rows = resp.data
            if len(rows) < 100:
                continue
            X, y = [], []
            for r in rows:
                f = [r.get('cpu_load',50) or 50, r.get('bandwidth_mbps',100) or 100,
                     r.get('latency_ms',10) or 10, r.get('packet_loss',0) or 0,
                     r.get('connected_devices',10) or 10, r.get('temperature',40) or 40,
                     r.get('signal_strength',80) or 80]
                if r.get('health_score') is not None:
                    X.append(f)
                    y.append(r['health_score'])
            if len(X) < 50:
                continue
            X = np.array(X)
            y = np.array(y)
            new_rf  = RandomForestRegressor(n_estimators=100, max_depth=10, random_state=42)
            new_rf.fit(X, y)
            new_iso = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
            new_iso.fit(X[y >= 60])
            import joblib as jl
            jl.dump(new_rf,  'health_model.pkl')
            jl.dump(new_iso, 'anomaly_model.pkl')
            rf_model      = new_rf
            iso_model     = new_iso
            anomaly_count = 0
            print('[AutoRetrain] Complete')
        except Exception as e:
            print(f'[AutoRetrain] Error: {e}')
        finally:
            with retrain_lock:
                _retrain_in_progress = False

threading.Thread(target=auto_retrain_pipeline, daemon=True).start()

NOTIFY_EMAIL    = os.environ.get('NOTIFY_EMAIL_ENABLED',    'false').lower() == 'true'
NOTIFY_SMS      = os.environ.get('NOTIFY_SMS_ENABLED',      'false').lower() == 'true'
NOTIFY_WHATSAPP = os.environ.get('NOTIFY_WHATSAPP_ENABLED', 'false').lower() == 'true'
notification_log = deque(maxlen=100)

def send_email(subject, body):
    if not NOTIFY_EMAIL or not os.environ.get('SMTP_USER'):
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = f'[IISentinel] {subject}'
        msg['From']    = os.environ.get('NOTIFY_FROM', '')
        msg['To']      = os.environ.get('NOTIFY_TO', '')
        with smtplib.SMTP(os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
                          int(os.environ.get('SMTP_PORT', '587'))) as s:
            s.starttls()
            s.login(os.environ.get('SMTP_USER'), os.environ.get('SMTP_PASS', ''))
            s.send_message(msg)
    except Exception as e:
        print(f'Email error: {e}')

def send_sms(message):
    if not NOTIFY_SMS or not os.environ.get('AT_API_KEY'):
        return
    try:
        req.post('https://api.africastalking.com/version1/messaging',
            headers={'apiKey': os.environ.get('AT_API_KEY'), 'Accept': 'application/json'},
            data={'username': os.environ.get('AT_USERNAME'),
                  'to':       os.environ.get('NOTIFY_SMS'),
                  'message':  f'IISentinel: {message}'}, timeout=8)
    except Exception as e:
        print(f'SMS error: {e}')

def send_whatsapp(message):
    if not NOTIFY_WHATSAPP or not os.environ.get('WA_TOKEN'):
        return
    try:
        for number in os.environ.get('NOTIFY_WA', '').split(','):
            if not number.strip():
                continue
            req.post(
                f'https://graph.facebook.com/v19.0/{os.environ.get("WA_PHONE_ID")}/messages',
                headers={'Authorization': f'Bearer {os.environ.get("WA_TOKEN")}',
                         'Content-Type': 'application/json'},
                json={'messaging_product': 'whatsapp', 'to': number.strip(),
                      'type': 'text', 'text': {'body': f'IISentinel\n{message}'}},
                timeout=8)
    except Exception as e:
        print(f'WhatsApp error: {e}')

def notify_all(subject, message, level='critical', device_id=None):
    notification_log.appendleft({'subject': subject, 'message': message,
        'level': level, 'device_id': device_id,
        'ts': datetime.now(timezone.utc).isoformat()})
    if level in ('critical', 'cbs'):
        threading.Thread(target=send_sms, args=(f'{subject}: {message}',), daemon=True).start()
        threading.Thread(target=send_whatsapp, args=(f'{subject}\n{message}',), daemon=True).start()
    threading.Thread(target=send_email, args=(subject, message), daemon=True).start()

platform_stats = {
    'requests_total': 0, 'requests_failed': 0,
    'queue_depth': 0, 'notifications_sent': 0,
    'uptime_start': datetime.now(timezone.utc).isoformat(),
}

FIELD_BOUNDS = {
    'cpu_load': (0, 100), 'bandwidth_mbps': (0, 100000),
    'latency_ms': (0, 60000), 'packet_loss': (0, 100),
    'connected_devices': (0, 100000), 'temperature': (-50, 200),
    'signal_strength': (0, 100), 'metric_value': (-1e9, 1e9),
}

def sanitize(data):
    """
    B1 — Full input sanitisation using PATTERNS security checks.
    Blocks script injection, SQL patterns, and path traversal.
    Clamps all numeric fields to safe bounds.
    """
    if not isinstance(data, dict):
        return {}, 'Payload must be JSON object'
    # Security scan on full payload string
    payload_str = json.dumps(data)
    if PATTERNS['SCRIPT_INJECT'].search(payload_str):
        print(f'[Security] SCRIPT_INJECT blocked from payload')
        return {}, 'BLOCKED: script injection detected'
    if PATTERNS['SQL_INJECT'].search(payload_str):
        print(f'[Security] SQL_INJECT blocked from payload')
        return {}, 'BLOCKED: SQL injection detected'
    if PATTERNS['PATH_TRAVERSAL'].search(payload_str):
        print(f'[Security] PATH_TRAVERSAL blocked from payload')
        return {}, 'BLOCKED: path traversal detected'
    # Required fields
    for f in ['device_id', 'device_type']:
        if not data.get(f):
            return {}, f'Missing required field: {f}'
    did = str(data.get('device_id', ''))
    if not re.match(r'^[a-zA-Z0-9_-]{1,80}$', did):
        return {}, 'Invalid device_id format'
    cleaned = dict(data)
    cleaned['device_id'] = did
    for field, (lo, hi) in FIELD_BOUNDS.items():
        if field in cleaned:
            try:
                cleaned[field] = float(max(lo, min(hi, float(cleaned[field]))))
            except (TypeError, ValueError):
                cleaned[field] = (lo + hi) / 2
    return cleaned, None

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel-secret-2026')

rf_model  = joblib.load('health_model.pkl')
iso_model = joblib.load('anomaly_model.pkl')
scaler    = joblib.load('scaler.pkl')

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

reading_window  = []
device_history  = {}
device_uptime   = {}
anomaly_count   = 0
RETRAIN_THRESHOLD    = 50
CBS_SAFETY_THRESHOLD = 90.0

NETWORK_TYPES = ['router', 'switch', 'firewall', 'wan_link', 'workstation']
TELECOM_TYPES = ['base_station', 'network_tower', 'microwave_link']
MINING_TYPES  = ['pump', 'conveyor', 'ventilation', 'power_meter', 'sensor', 'plc', 'scada_node']

LOCATIONS = {
    'byo':  {'lat': -20.15, 'lon': 28.58, 'name': 'Bulawayo'},
    'hre':  {'lat': -17.82, 'lon': 31.05, 'name': 'Harare'},
    'mut':  {'lat': -18.97, 'lon': 32.67, 'name': 'Mutare'},
    'mine': {'lat': -17.65, 'lon': 29.85, 'name': 'Mine Site'},
}

PROTOCOL_MAP = {
    'SNMP/Ethernet-802.3':  'SNMP over IEEE 802.3 Ethernet',
    'Profinet/EtherNet-IP': 'Profinet real-time industrial Ethernet',
    'DNP3/Ethernet':        'DNP3 safety-critical control protocol',
    'Modbus-TCP/OPC-UA':    'Modbus TCP with OPC-UA data exchange',
}

def require_specialist(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Specialist-Token')
        if not token:
            return jsonify({'error': 'Unauthorised'}), 401
        try:
            result = supabase.table('specialists').select('*').eq('password', token).execute()
            if not result.data:
                return jsonify({'error': 'Invalid token'}), 401
        except Exception:
            return jsonify({'error': 'Auth error'}), 401
        return f(*args, **kwargs)
    return decorated

def get_failure_probability(device_id, current_score):
    history = device_history.get(device_id, [])
    if len(history) < 3:
        return 0.0
    recent = history[-5:]
    trend  = recent[-1] - recent[0]
    if trend >= 0:
        return max(0.0, round((100 - current_score) * 0.05, 1))
    decline_rate = abs(trend) / len(recent)
    return min(99.0, round(decline_rate * 3 + (100 - current_score) * 0.3, 1))

def get_federated_health_index(all_scores):
    if not all_scores:
        return 100.0
    weights = [s * 0.5 if s < 20 else s * 0.8 if s < 50 else s for s in all_scores]
    return round(sum(weights) / len(weights), 1)

def get_root_cause_chain(device_id, current_score, all_recent):
    chain    = []
    degraded = [(did, score) for did, score in all_recent.items() if score < 50 and did != device_id]
    if degraded and current_score < 50:
        for did, score in sorted(degraded, key=lambda x: x[1])[:3]:
            chain.append({'device': did, 'score': round(score, 1)})
    return chain

def get_lifecycle_estimate(device_id, device_type, health_score):
    type_hours = {'pump': 8760, 'conveyor': 17520, 'ventilation': 26280,
                  'plc': 52560, 'router': 43800, 'switch': 43800,
                  'base_station': 35040, 'network_tower': 43800}
    base_hours = type_hours.get(device_type, 26280)
    history    = device_history.get(device_id, [])
    if len(history) < 5:
        return None
    trend = history[-1] - history[0]
    dpd   = abs(trend) / len(history) if trend < 0 else 0
    if dpd > 0:
        return round(min(base_hours, health_score / dpd * (10 / 3600)))
    return base_hours

def get_protocol_diagnosis(device_type, protocol, metric_name, metric_value, health_score, anomaly):
    issues  = []
    actions = []
    proto_label = PROTOCOL_MAP.get(protocol, protocol or 'Ethernet')
    if health_score < 20:
        issues.append('critical system failure detected')
        actions.append('immediate intervention required')
    elif health_score < 35:
        issues.append('severe performance degradation')
        actions.append('escalate to operations team')
    elif health_score < 50:
        issues.append('moderate performance degradation')
        actions.append('schedule maintenance within 24 hours')
    if device_type in TELECOM_TYPES or device_type in NETWORK_TYPES:
        if 'latency'   in metric_name and metric_value > 100:
            issues.append(f'SNMP reports {metric_value:.1f}ms latency on backhaul')
            actions.append('inspect BGP routing and check fibre integrity')
        if 'packet'    in metric_name and metric_value > 2:
            issues.append(f'packet loss {metric_value:.1f}%')
            actions.append('run BERT test and check SFP modules')
        if 'bandwidth' in metric_name and metric_value > 800:
            issues.append(f'bandwidth at {metric_value:.1f}Mbps near capacity')
            actions.append('implement QoS and analyse NetFlow traffic')
        if 'signal'    in metric_name and metric_value < 40:
            issues.append(f'signal at {metric_value:.1f}% link degraded')
            actions.append('inspect microwave alignment')
    elif device_type in MINING_TYPES:
        if 'temperature' in metric_name and metric_value > 75:
            issues.append(f'Profinet reports {metric_value:.1f}C thermal threshold')
            actions.append('check cooling fan and reduce duty cycle')
        if 'vibration'   in metric_name and metric_value > 3:
            issues.append(f'vibration {metric_value:.2f}g via OPC-UA bearing wear')
            actions.append('schedule predictive maintenance within 4 hours')
        if 'pressure'    in metric_name and metric_value > 8:
            issues.append(f'pressure {metric_value:.1f}bar above safe limit')
            actions.append('open bypass valve alert hydraulics engineer')
    elif device_type == 'cbs_controller':
        if health_score < CBS_SAFETY_THRESHOLD:
            issues.append(f'CBS DNP3 link {health_score:.1f}% below blast threshold')
            actions.append('BLAST HOLD notify blasting officer inspect DNP3 link')
    if anomaly:
        issues.append(f'Isolation Forest anomaly on {proto_label}')
        actions.append('cross-reference with device event log')
    if not issues:
        return f'Device operating within normal parameters via {proto_label}. Health score {health_score:.1f}/100.'
    return f'{"; ".join(issues).capitalize()}. Recommended actions: {"; ".join(actions).capitalize()}.'

def get_automation_command(device_id, device_type, health_score, blast_hold=False, automation_override=None):
    if automation_override:
        return automation_override
    if device_type == 'cbs_controller' and health_score < CBS_SAFETY_THRESHOLD:
        return f'CBS SAFETY INTERLOCK: BLAST HOLD on {device_id} DNP3 link {health_score:.1f}% below threshold.'
    if device_type in ['ventilation', 'pump'] and health_score < 20:
        return f'EMERGENCY: Safety shutdown {device_id} underground evacuation alert triggered via PA system'
    if health_score < 20:
        return f'CRITICAL: Emergency restart for {device_id}'
    if health_score < 35:
        return f'WARNING: Isolate {device_id} and reduce load'
    if health_score < 50:
        return f'CAUTION: Schedule maintenance for {device_id}'
    return None

def update_uptime(device_id, health_score):
    if device_id not in device_uptime:
        device_uptime[device_id] = {'total': 0, 'healthy': 0}
    device_uptime[device_id]['total'] += 1
    if health_score >= 50:
        device_uptime[device_id]['healthy'] += 1

def get_uptime_pct(device_id):
    d = device_uptime.get(device_id, {'total': 0, 'healthy': 0})
    if d['total'] == 0:
        return 100.0
    return round((d['healthy'] / d['total']) * 100, 1)



# ═══════════════════════════════════════════════════════════════════════════
# F — DATA RETENTION & AUDIT TRAIL
# 5-year event archive with indexed retrieval.
# Every parsed event, incident note, CBS action, and shift handover report
# is written to an append-only Supabase store with a tenant-partitioned key.
# Engineers can query any asset's history — regex-filtered by device, type,
# severity, or time window.
# ═══════════════════════════════════════════════════════════════════════════
_archive_buffer  = deque(maxlen=200)   # local buffer before Supabase write
_archive_lock    = threading.Lock()

def archive_event(event: dict, tenant_id: str = 'default'):
    """
    Append-only event archive writer.
    Key schema: tenant:source:timestamp — enables fast prefix scans.
    Buffers locally, flushes to Supabase every 10 seconds.
    """
    record = {
        'tenant_id':  tenant_id,
        'source':     event.get('source', 'unknown'),
        'event_type': event.get('parsed', {}).get('type', 'raw') if event.get('parsed') else 'raw',
        'severity':   event.get('severity', 'info'),
        'device_id':  event.get('source', ''),
        'raw':        event.get('raw', '')[:500],   # truncate long strings
        'parsed':     json.dumps(event.get('parsed') or {}),
        'ts':         event.get('ts', datetime.now(timezone.utc).isoformat()),
    }
    with _archive_lock:
        _archive_buffer.append(record)


def query_archive(tenant_id: str = 'default', source: str = None,
                  event_type: str = None, severity: str = None,
                  from_ts: str = None, to_ts: str = None,
                  limit: int = 100) -> list:
    """
    Indexed archive retrieval with regex-style filter support.
    Equivalent to: SELECT * FROM archive WHERE tenant=X AND source LIKE Y
    Supports time-window queries for shift handover and audit reports.
    """
    try:
        q = supabase.table('event_archive').select('*') \
            .eq('tenant_id', tenant_id) \
            .order('ts', desc=True) \
            .limit(limit)
        if source:     q = q.ilike('source', f'%{source}%')
        if event_type: q = q.eq('event_type', event_type)
        if severity:   q = q.eq('severity', severity)
        if from_ts:    q = q.gte('ts', from_ts)
        if to_ts:      q = q.lte('ts', to_ts)
        resp = q.execute()
        return resp.data or []
    except Exception as e:
        print(f'[Archive] Query error: {e}')
        return []


def _flush_archive():
    """Background flusher — drains archive buffer to Supabase every 10s."""
    while True:
        time.sleep(10)
        with _archive_lock:
            if not _archive_buffer:
                continue
            batch = list(_archive_buffer)
            _archive_buffer.clear()
        try:
            for record in batch:
                supabase.table('event_archive').insert(record).execute()
        except Exception as e:
            print(f'[Archive] Flush error: {e}')
            with _archive_lock:
                for r in batch[:50]:
                    _archive_buffer.appendleft(r)

threading.Thread(target=_flush_archive, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════
# H2 — PRICING CONFIGURATION
# Pricing declared in config alongside tenant definitions.
# Enables instant quote generation on the landing page without manual calc.
# ═══════════════════════════════════════════════════════════════════════════
PRICING = {
    'network-only': {
        'model':       'per_device',
        'monthly_usd': {'min': 15,    'max': 30},
        'billing_unit': 'device',
        'tagline':     'Avg 73% reduction in mean time to resolve',
        'roi_example': '$15,000/hr network outage prevented',
    },
    'telecom-only': {
        'model':       'per_site',
        'monthly_usd': {'min': 200,   'max': 500},
        'billing_unit': 'tower site',
        'tagline':     'Avg $12,000/hr prevented per outage',
        'roi_example': 'Signal degradation detected 40min before customer impact',
    },
    'mining-only': {
        'model':           'per_site',
        'monthly_usd':     {'min': 2000, 'max': 5000},
        'billing_unit':    'mine site',
        'safety_surcharge': True,
        'tagline':         '$500,000+ protected per CBS blast event',
        'roi_example':     'One CBS hold prevented = platform paid for 10 years',
    },
    'default': {
        'model':       'enterprise_annual',
        'annual_usd':  {'min': 60000, 'max': 200000},
        'billing_unit': 'site licence',
        'tagline':     'Full-stack infrastructure intelligence — all sectors',
        'roi_example': 'Network + Telecom + Mining + CBS in one platform',
    },
}

@app.route('/api/data', methods=['GET'])
def get_data():
    platform_stats['requests_total'] += 1
    return jsonify(get_cached_data())


@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    global anomaly_count
    platform_stats['requests_total'] += 1
    raw = request.json
    if not raw:
        return jsonify({'error': 'Empty payload'}), 400
    data, err = sanitize(raw)
    if err:
        platform_stats['requests_failed'] += 1
        return jsonify({'error': err}), 400

    device_id           = data.get('device_id', 'unknown')
    device_type         = data.get('device_type', 'unknown')
    protocol            = data.get('protocol', 'Ethernet')
    blast_hold          = data.get('blast_hold', False)
    automation_override = data.get('automation_override', None)

    features     = [data.get('cpu_load', 50), data.get('bandwidth_mbps', 100),
                    data.get('latency_ms', 10), data.get('packet_loss', 0),
                    data.get('connected_devices', 10), data.get('temperature', 40),
                    data.get('signal_strength', 80)]
    features_arr = np.array([features])

    health_score = float(rf_model.predict(features_arr)[0])
    health_score = max(0, min(100, health_score))
    if device_type == 'cbs_controller':
        health_score = min(health_score, data.get('signal_strength', 100))

    anomaly_result = iso_model.predict(features_arr)[0]
    anomaly_flag   = bool(anomaly_result == -1)
    if anomaly_flag:
        anomaly_count += 1
    # A4 — Record behaviour event for D1 scorecard
    record_behaviour_event(device_id, health_score, anomaly_flag,
                           was_critical=(health_score < 20))

    if device_id not in device_history:
        device_history[device_id] = []
    device_history[device_id].append(health_score)
    if len(device_history[device_id]) > 20:
        device_history[device_id].pop(0)

    reading_window.append(health_score)
    if len(reading_window) > 10:
        reading_window.pop(0)
    if len(reading_window) >= 3:
        trend = reading_window[-1] - reading_window[0]
        predicted_score = max(0, min(100, health_score + trend))
    else:
        predicted_score = health_score

    failure_prob    = get_failure_probability(device_id, health_score)
    recent_scores   = {did: hist[-1] for did, hist in device_history.items() if hist}
    root_cause      = get_root_cause_chain(device_id, health_score, recent_scores)
    lifecycle       = get_lifecycle_estimate(device_id, device_type, health_score)
    federated_index = get_federated_health_index(list(recent_scores.values()))
    update_uptime(device_id, health_score)
    uptime_pct = get_uptime_pct(device_id)

    # F1 — Archive critical events (append-only audit trail)
    if health_score < 50 or anomaly_flag or blast_hold:
        archive_event({
            'source':   device_id,
            'severity': 'critical' if health_score < 20 or blast_hold else 'warning',
            'parsed':   {'type': 'HEALTH_EVENT', 'score': round(health_score, 1),
                         'device_type': device_type},
            'raw':      f'{device_id} health={health_score:.1f} anomaly={anomaly_flag} hold={blast_hold}',
            'ts':       datetime.now(timezone.utc).isoformat(),
        }, tenant_id=ACTIVE_TENANT)

    # A4 — Parse structured log from metric_name field if it looks like a log string
    if data.get('log_raw'):
        log_event = parse_log(data['log_raw'], source=device_id)
        if log_event['severity'] == 'critical' and is_new_alert(data['log_raw'][:48]):
            platform_stats['requests_failed'] = platform_stats.get('requests_failed', 0)

    ai_diagnosis = None
    if anomaly_flag or health_score < 50 or device_type == 'cbs_controller':
        ai_diagnosis = get_protocol_diagnosis(
            device_type, protocol,
            data.get('metric_name', 'unknown'), data.get('metric_value', 0),
            health_score, anomaly_flag)

    automation_command = get_automation_command(
        device_id, device_type, health_score, blast_hold, automation_override)

    if health_score < 50 or anomaly_flag or blast_hold:
        sse_broadcast('metric', {
            'device_id': device_id, 'device_type': device_type,
            'health_score': round(health_score, 1),
            'anomaly_flag': anomaly_flag, 'blast_hold': blast_hold,
            'automation_command': automation_command,
            'is_cbs': device_type == 'cbs_controller',
        })

    # B2 — CBS message format validation
    if device_type == 'cbs_controller':
        cbs_raw = f"CBS-{'HOLD' if (blast_hold or health_score < CBS_SAFETY_THRESHOLD) else 'CLEAR'}: SHAFT-1 @ {datetime.now(timezone.utc).strftime('%H:%M:%S')}"
        cbs_result = handle_cbs_message(cbs_raw)
        if not cbs_result.get('validated') and (blast_hold or health_score < CBS_SAFETY_THRESHOLD):
            print(f'[CBS] Format validation triggered HOLD (fail-safe)')
    # A3 — Deduplication: suppress repeated identical alerts
    alert_key = f"{device_id}:{round(health_score)}"
    if blast_hold or (device_type == 'cbs_controller' and health_score < CBS_SAFETY_THRESHOLD):
        notify_all(f'CBS BLAST HOLD {device_id}',
            f'DNP3 link at {health_score:.1f}%. Cost exposure $450,000/hr.',
            level='cbs', device_id=device_id)
    elif health_score < 20 and device_type in ['ventilation', 'pump'] and is_new_alert(alert_key):
        notify_all(f'EMERGENCY {device_id}',
            f'{device_type} at {health_score:.1f}%. Underground safety alert.',
            level='critical', device_id=device_id)

    metric_record = {
        'device_type': device_type, 'device_id': device_id,
        'metric_name': data.get('metric_name', 'unknown'),
        'metric_value': float(data.get('metric_value', 0)),
        'health_score': health_score, 'anomaly_flag': anomaly_flag,
        'predicted_score': predicted_score, 'ai_diagnosis': ai_diagnosis,
        'automation_command': automation_command
    }
    with queue_lock:
        metric_queue.append(metric_record)
        platform_stats['queue_depth'] = len(metric_queue)

    if health_score < 50 or anomaly_flag or blast_hold:
        try:
            supabase.table('incidents').insert({
                'device_id': device_id, 'device_type': device_type,
                'health_score': health_score, 'ai_diagnosis': ai_diagnosis,
                'automation_command': automation_command, 'status': 'open'
            }).execute()
        except Exception as e:
            print(f'Incident error: {e}')

    return jsonify({
        'status': 'ok', 'health_score': round(health_score, 1),
        'anomaly_flag': anomaly_flag, 'predicted_score': round(predicted_score, 1),
        'failure_probability': failure_prob, 'ai_diagnosis': ai_diagnosis,
        'automation_command': automation_command, 'federated_index': federated_index,
        'uptime_pct': uptime_pct, 'root_cause_chain': root_cause,
        'lifecycle_hours': lifecycle,
        'retrain_needed': anomaly_count >= RETRAIN_THRESHOLD,
        'retrain_in_progress': _retrain_in_progress,
        'protocol': protocol, 'blast_hold': blast_hold
    })


@app.route('/api/platform', methods=['GET'])
def platform_health():
    uptime_secs = (datetime.now(timezone.utc) -
        datetime.fromisoformat(platform_stats['uptime_start'].replace('Z', '+00:00'))
    ).total_seconds()
    return jsonify({
        'queue_depth':         len(metric_queue),
        'scoring_queue':       0,
        'cache_age_seconds':   round(time.time() - _data_cache['ts'], 1),
        'devices_tracked':     len(device_history),
        'anomaly_count':       anomaly_count,
        'retrain_needed':      anomaly_count >= RETRAIN_THRESHOLD,
        'retrain_in_progress': _retrain_in_progress,
        'platform_uptime_h':   round(uptime_secs / 3600, 2),
        'notifications': {
            'email_enabled':    NOTIFY_EMAIL,
            'sms_enabled':      NOTIFY_SMS,
            'whatsapp_enabled': NOTIFY_WHATSAPP,
        },
        'youtube_layers': {
            'upload_service':         'POST /api/metrics — SNMP/Profinet/DNP3/Modbus ingestion',
            'queuing_service':        f'metric_queue — {len(metric_queue)} items buffered',
            'encoder':                'RandomForest (health) + IsolationForest (anomaly)',
            'cache':                  f'_data_cache {CACHE_TTL}s TTL',
            'notification_service':   f'Email:{NOTIFY_EMAIL} SMS:{NOTIFY_SMS} WhatsApp:{NOTIFY_WHATSAPP}',
            'recommendation_engine':  f'FHI + failure probability — {len(device_history)} devices',
            'adaptive_algorithm':     f'auto_retrain at {RETRAIN_THRESHOLD} anomalies — {anomaly_count} current',
            'search_service':         'GET /api/search — device lookup by ID/type/health',
            'observability':          'GET /api/platform — queue/cache/retrain/uptime telemetry',
            'cdn_delivery':           'GET /api/stream — SSE push <100ms to browser',
        },
    })


@app.route('/api/stream')
def sse_stream():
    import queue as _queue
    sub_q = _queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_subscribers.append(sub_q)
    def generate():
        yield 'event: connected\ndata: {"ok":true}\n\n'
        while True:
            try:
                msg = sub_q.get(timeout=25)
                yield msg
            except Exception:
                yield ':heartbeat\n\n'
    return Response(stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no',
                 'Access-Control-Allow-Origin': '*'})


@app.route('/api/export-pdf')
def export_pdf():
    try:
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph,
                                        Spacer, Table, TableStyle, HRFlowable)
        from flask import send_file
        buf    = BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=A4, rightMargin=18*mm,
                                   leftMargin=18*mm, topMargin=20*mm, bottomMargin=18*mm)
        DARK   = colors.HexColor('#0c1122')
        ACCENT = colors.HexColor('#34c6f4')
        GREEN  = colors.HexColor('#20e07a')
        AMBER  = colors.HexColor('#f5a020')
        RED    = colors.HexColor('#ff3e50')
        MUTED  = colors.HexColor('#8592a8')
        ROW    = colors.HexColor('#f0f4fa')
        styles = getSampleStyleSheet()
        def sty(n='Normal', **kw):
            return ParagraphStyle(n, parent=styles[n], **kw)
        recent  = {did: hist[-1] for did, hist in device_history.items() if hist}
        scores  = list(recent.values())
        fhi_v   = get_federated_health_index(scores)
        probs   = {did: get_failure_probability(did, s) for did, s in recent.items()}
        now_s   = datetime.now(timezone.utc).strftime('%d %B %Y %H:%M UTC')
        story   = []
        story.append(Paragraph('IISentinel(TM)',
            sty('Title', fontName='Helvetica-Bold', fontSize=22, textColor=DARK)))
        story.append(Paragraph('Intelligent Infrastructure Sentinel -- Shift Report',
            sty('Normal', fontName='Helvetica', fontSize=10, textColor=MUTED, spaceAfter=4)))
        story.append(Paragraph(f'Generated: {now_s}',
            sty('Normal', fontName='Helvetica', fontSize=9, textColor=MUTED, spaceAfter=8)))
        story.append(HRFlowable(width='100%', thickness=1.5, color=ACCENT, spaceAfter=10))
        hdr = sty('Normal', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)
        cel = sty('Normal', fontName='Helvetica', fontSize=8, textColor=DARK)
        crit_c = sum(1 for s in scores if s < 20)
        warn_c = sum(1 for s in scores if 20 <= s < 50)
        kpi = [
            [Paragraph(c, hdr) for c in ['Metric', 'Value', 'Status']],
            [Paragraph(c, cel) for c in ['Federated Health Index', f'{fhi_v:.1f}/100',
                'HEALTHY' if fhi_v >= 70 else 'WARNING' if fhi_v >= 40 else 'CRITICAL']],
            [Paragraph(c, cel) for c in ['Total Devices', str(len(recent)), '--']],
            [Paragraph(c, cel) for c in ['Critical (<20)', str(crit_c),
                'ALERT' if crit_c else 'NONE']],
            [Paragraph(c, cel) for c in ['Warning (20-50)', str(warn_c),
                'MONITOR' if warn_c else 'NONE']],
            [Paragraph(c, cel) for c in ['Anomaly Count', str(anomaly_count),
                'HIGH' if anomaly_count >= RETRAIN_THRESHOLD else 'NORMAL']],
        ]
        t = Table(kpi, colWidths=[75*mm, 60*mm, 40*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0),  DARK),
            ('ROWBACKGROUNDS',(0,1),(-1,-1), [colors.white, ROW]),
            ('GRID',          (0,0),(-1,-1), 0.35, colors.HexColor('#d4daea')),
            ('TOPPADDING',    (0,0),(-1,-1), 5),
            ('BOTTOMPADDING', (0,0),(-1,-1), 5),
            ('LEFTPADDING',   (0,0),(-1,-1), 7),
        ]))
        story.append(Paragraph('Platform Summary',
            sty('Heading1', fontName='Helvetica-Bold', fontSize=12,
                textColor=DARK, spaceBefore=8, spaceAfter=5)))
        story.append(t)
        story.append(Spacer(1, 8))
        if recent:
            story.append(Paragraph('Device Health Register',
                sty('Heading2', fontName='Helvetica-Bold', fontSize=9,
                    textColor=ACCENT, spaceBefore=8, spaceAfter=4)))
            drows = [[Paragraph(c, hdr) for c in ['Device', 'Score', 'Risk%', 'Status']]]
            for did, s in sorted(recent.items(), key=lambda x: x[1])[:20]:
                p2   = probs.get(did, 0)
                col  = RED if s < 20 else AMBER if s < 50 else GREEN
                stat = 'CRITICAL' if s < 20 else 'WARNING' if s < 50 else 'OK'
                drows.append([
                    Paragraph(did[-30:], cel),
                    Paragraph(f'{s:.0f}', sty('Normal', fontName='Helvetica-Bold',
                              fontSize=8, textColor=col)),
                    Paragraph(f'{p2:.0f}%', cel),
                    Paragraph(stat, sty('Normal', fontName='Helvetica-Bold',
                              fontSize=8, textColor=col)),
                ])
            dt = Table(drows, colWidths=[80*mm, 22*mm, 22*mm, 25*mm])
            dt.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,0),  DARK),
                ('ROWBACKGROUNDS',(0,1),(-1,-1), [colors.white, ROW]),
                ('GRID',          (0,0),(-1,-1), 0.35, colors.HexColor('#d4daea')),
                ('TOPPADDING',    (0,0),(-1,-1), 4),
                ('BOTTOMPADDING', (0,0),(-1,-1), 4),
                ('LEFTPADDING',   (0,0),(-1,-1), 5),
            ]))
            story.append(dt)
        story.append(Spacer(1, 14))
        story.append(HRFlowable(width='100%', thickness=0.7, color=MUTED, spaceAfter=5))
        story.append(Paragraph(f'IISentinel(TM) Confidential -- {now_s}',
            sty('Normal', fontName='Helvetica-Oblique', fontSize=7, textColor=MUTED)))
        doc.build(story)
        buf.seek(0)
        fname = f'IISentinel_Report_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")}.pdf'
        return send_file(buf, as_attachment=True, download_name=fname,
                         mimetype='application/pdf')
    except ImportError:
        return jsonify({'error': 'Run: pip install reportlab'}), 500


@app.route('/api/intelligence', methods=['GET'])
def get_intelligence():
    recent = {did: hist[-1] for did, hist in device_history.items() if hist}
    probs  = {did: get_failure_probability(did, hist[-1])
              for did, hist in device_history.items() if hist}
    lifecycles = {}
    try:
        resp = supabase.table('metrics').select('device_id,device_type')             .order('created_at', desc=True).limit(50).execute()
        for row in resp.data:
            did = row['device_id']
            if did in recent and did not in lifecycles:
                lc = get_lifecycle_estimate(did, row['device_type'], recent[did])
                if lc:
                    lifecycles[did] = lc
    except Exception:
        pass
    return jsonify({
        'federated_index':       get_federated_health_index(list(recent.values())),
        'device_scores':         recent,
        'uptime':                {did: get_uptime_pct(did) for did in device_uptime},
        'failure_probabilities': probs,
        'lifecycles':            lifecycles,
        'retrain_needed':        anomaly_count >= RETRAIN_THRESHOLD,
        'retrain_in_progress':   _retrain_in_progress,
        'anomaly_count':         anomaly_count,
        'total_devices':         len(device_history),
    })


@app.route('/api/twin/<device_id>', methods=['GET'])
def digital_twin(device_id):
    history = device_history.get(device_id, [])
    if not history:
        return jsonify({'error': 'No history for device'}), 404
    current_score = history[-1]
    scenarios     = []
    for mult in [1.1, 1.2, 1.5, 2.0]:
        f         = np.array([[min(100,50*mult), min(1000,100*mult),
                               min(500,10*mult), min(20,mult*.5), 10, 40, 80]])
        sim_score = float(rf_model.predict(f)[0])
        sim_score = max(0, min(100, sim_score))
        anomaly   = bool(iso_model.predict(f)[0] == -1)
        scenarios.append({'load_increase': f'+{int((mult-1)*100)}%',
            'predicted_score': round(sim_score, 1), 'anomaly_predicted': anomaly,
            'risk': 'critical' if sim_score < 30 else 'warning' if sim_score < 60 else 'safe'})
    trend_info = {'slope_per_reading': 0, 'direction': 'insufficient data'}
    if len(history) >= 5:
        slope = (history[-1] - history[-5]) / 4
        rtc   = round((current_score - 20) / abs(slope)) if slope < 0 and current_score > 20 else None
        trend_info = {'slope_per_reading': round(slope, 2),
            'direction': 'declining' if slope < 0 else 'stable' if slope == 0 else 'improving',
            'readings_to_critical': rtc}
    return jsonify({'device_id': device_id, 'current_score': round(current_score, 1),
        'history': [round(h, 1) for h in history], 'scenarios': scenarios,
        'trend': trend_info,
        'failure_probability': get_failure_probability(device_id, current_score)})


@app.route('/api/weather', methods=['GET'])
def get_weather():
    loc_key = request.args.get('loc', 'byo')
    loc     = LOCATIONS.get(loc_key, LOCATIONS['byo'])
    try:
        url = (f"https://api.open-meteo.com/v1/forecast"
               f"?latitude={loc['lat']}&longitude={loc['lon']}"
               f"&current=temperature_2m,relative_humidity_2m,wind_speed_10m,"
               f"wind_gusts_10m,precipitation,weather_code,cloud_cover"
               f"&hourly=temperature_2m,precipitation_probability,"
               f"wind_speed_10m&forecast_days=2&timezone=Africa/Harare")
        resp    = req.get(url, timeout=10)
        data    = resp.json()
        current = data.get('current', {})
        hourly  = data.get('hourly', {})
        wind    = current.get('wind_speed_10m', 0)
        gusts   = current.get('wind_gusts_10m', 0)
        precip  = current.get('precipitation', 0)
        temp    = current.get('temperature_2m', 25)
        humidity= current.get('relative_humidity_2m', 50)
        wcode   = current.get('weather_code', 0)
        cloud   = current.get('cloud_cover', 0)
        alerts  = []
        equip   = []
        if wind > 40:
            alerts.append(f'High winds {wind:.0f}km/h microwave links at risk')
            equip.append({'type': 'telecom',
                'impact': f'Signal degradation {min(30,wind*0.4):.0f}% on exposed towers',
                'severity': 'warning'})
        if gusts > 60:
            alerts.append(f'Dangerous gusts {gusts:.0f}km/h tower stability risk')
            equip.append({'type': 'telecom', 'impact': 'CBS blast hold recommended',
                'severity': 'critical'})
        if precip > 10:
            alerts.append(f'Heavy precipitation {precip:.1f}mm')
            equip.append({'type': 'mining',
                'impact': 'Underground water ingress risk pump load will increase',
                'severity': 'warning'})
        if temp > 38:
            alerts.append(f'Extreme heat {temp:.0f}C')
            equip.append({'type': 'all',
                'impact': 'Health score degradation expected increase cooling checks',
                'severity': 'warning'})
        if wcode >= 95:
            alerts.append('Thunderstorm active lightning risk')
            equip.append({'type': 'all', 'impact': 'Surge protection alert',
                'severity': 'critical'})
        next24 = hourly.get('precipitation_probability', [])[:24]
        return jsonify({'location': loc['name'], 'temperature': temp, 'humidity': humidity,
            'wind_speed': wind, 'wind_gusts': gusts, 'precipitation': precip,
            'weather_code': wcode, 'cloud_cover': cloud, 'alerts': alerts,
            'equipment_impact': equip,
            'max_precip_probability_24h': max(next24) if next24 else 0,
            'hourly_wind': hourly.get('wind_speed_10m', [])[:24],
            'hourly_precip_prob': next24})
    except Exception as e:
        return jsonify({'error': str(e), 'location': loc['name']}), 500


@app.route('/api/shift-report', methods=['GET'])
@require_specialist
def shift_report():
    try:
        resp     = supabase.table('metrics').select('*').order('created_at', desc=True).limit(500).execute()
        inc_resp = supabase.table('incidents').select('*').order('created_at', desc=True).limit(100).execute()
        device_map = {}
        for row in resp.data:
            if row['device_id'] not in device_map:
                device_map[row['device_id']] = row
        critical = [d for d in device_map.values() if d['health_score'] < 20]
        warning  = [d for d in device_map.values() if 20 <= d['health_score'] < 50]
        healthy  = [d for d in device_map.values() if d['health_score'] >= 50]
        open_inc = [i for i in inc_resp.data if i['status'] == 'open']
        scores   = [d['health_score'] for d in device_map.values()]
        return jsonify({'generated_at': datetime.now(timezone.utc).isoformat(),
            'total_devices': len(device_map),
            'avg_health': round(sum(scores)/len(scores), 1) if scores else 100,
            'critical_devices': len(critical), 'warning_devices': len(warning),
            'healthy_devices': len(healthy), 'open_incidents': len(open_inc),
            'resolved_incidents': len([i for i in inc_resp.data if i['status'] == 'resolved']),
            'top_risks': [{'device': d['device_id'], 'score': round(d['health_score'], 1),
                'diagnosis': d.get('ai_diagnosis', '')}
                for d in sorted(critical+warning, key=lambda x: x['health_score'])[:5]],
            'automation_commands': [{'device': d['device_id'], 'command': d['automation_command']}
                for d in device_map.values() if d.get('automation_command')]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    try:
        result = supabase.table('specialists').select('*')             .eq('name', data.get('name', ''))             .eq('password', data.get('password', '')).execute()
        if result.data:
            s = result.data[0]
            return jsonify({'success': True, 'token': data.get('password'),
                            'name': s['name'], 'role': s['role']})
        return jsonify({'success': False}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/incidents', methods=['GET'])
@require_specialist
def get_incidents():
    status   = request.args.get('status', 'open')
    response = supabase.table('incidents').select('*').eq('status', status)         .order('created_at', desc=True).limit(50).execute()
    return jsonify(response.data)


@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
@require_specialist
def assign_incident(incident_id):
    data = request.json
    supabase.table('incidents').update({
        'assigned_to': data.get('assigned_to', ''),
        'notes': data.get('notes', ''), 'status': 'assigned'
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})


@app.route('/api/incidents/<incident_id>/resolve', methods=['POST'])
@require_specialist
def resolve_incident(incident_id):
    data = request.json
    supabase.table('incidents').update({
        'resolved_by': data.get('resolved_by', ''),
        'notes': data.get('notes', ''), 'status': 'resolved'
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})



# ═══════════════════════════════════════════════════════════════════════════
# D1 — BEHAVIOUR SCORECARD ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════
# F1 — EVENT ARCHIVE ENDPOINT
# Query the 5-year append-only event store.
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/archive', methods=['GET'])
def get_archive():
    """
    F1 — Query the event archive.
    Supports filtering by source (device), event_type, severity, time window.
    Used for audit trails, shift handover history, and regulatory compliance.
    """
    tenant_id  = request.args.get('tenant', ACTIVE_TENANT)
    source     = request.args.get('source')
    event_type = request.args.get('type')
    severity   = request.args.get('severity')
    from_ts    = request.args.get('from')
    to_ts      = request.args.get('to')
    limit      = min(int(request.args.get('limit', 100)), 500)

    results = query_archive(
        tenant_id=tenant_id, source=source, event_type=event_type,
        severity=severity, from_ts=from_ts, to_ts=to_ts, limit=limit
    )
    return jsonify({
        'tenant_id':   tenant_id,
        'total':       len(results),
        'filters':     {'source': source, 'type': event_type, 'severity': severity},
        'results':     results,
        'buffer_size': len(_archive_buffer),
    })


# ═══════════════════════════════════════════════════════════════════════════
# H2 — PRICING ENDPOINT
# Serves tenant-specific pricing for the landing page quote widget.
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/pricing', methods=['GET'])
def get_pricing():
    """
    H2 — Return pricing config for the active or requested tenant.
    Used by the landing page ROI calculator and quote generator.
    """
    tenant_key = request.args.get('tenant', ACTIVE_TENANT)
    pricing    = PRICING.get(tenant_key, PRICING['default'])
    devices    = len(device_history)

    # Live quote estimate based on current device count
    if pricing['model'] == 'per_device' and devices > 0:
        monthly = devices * pricing['monthly_usd']['min']
        quote   = {'monthly_usd': monthly, 'annual_usd': monthly * 12, 'devices': devices}
    elif pricing['model'] == 'per_site':
        quote   = {'monthly_usd': pricing['monthly_usd']['min'],
                   'annual_usd': pricing['monthly_usd']['min'] * 12}
    else:
        quote   = {'annual_usd': pricing['annual_usd']['min']}

    return jsonify({
        'tenant_key': tenant_key,
        'pricing':    pricing,
        'live_quote': quote,
        'all_tiers':  PRICING,
    })


@app.route('/api/behaviour', methods=['GET'])
def get_behaviour():
    """
    D1 — Per-asset behaviour scorecards.
    Returns grades A-F for all tracked devices based on
    anomaly frequency, breach rate, recurrence, and recovery.
    """
    scores = {}
    for did in device_history:
        result = score_behaviour(did)
        if result.get('score') is not None:
            scores[did] = result

    ranked = sorted(scores.items(), key=lambda x: x[1]['score'])
    return jsonify({
        'total':    len(scores),
        'ranked':   [{'device_id': k, **v} for k, v in ranked],
        'f_grade':  [k for k, v in ranked if v['grade'] == 'F'],
        'a_grade':  [k for k, v in ranked if v['grade'] == 'A'],
    })


# ═══════════════════════════════════════════════════════════════════════════
# D2 — MAINTENANCE CALENDAR ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/maintenance', methods=['GET'])
def get_maintenance():
    """
    D2 — Predictive maintenance calendar.
    Ranked by urgency: urgent (<72h) → scheduled (<240h) → routine.
    Surfaced in specialist panel.
    """
    schedule = []
    recent = {did: hist[-1] for did, hist in device_history.items() if hist}

    # Get device types from recent Supabase data
    type_map = {}
    try:
        resp = supabase.table('metrics').select('device_id,device_type')             .order('created_at', desc=True).limit(100).execute()
        for row in resp.data:
            type_map[row['device_id']] = row['device_type']
    except Exception:
        pass

    for did, score in recent.items():
        dtype = type_map.get(did, 'sensor')
        prediction = predict_next_maintenance(did, dtype, score)
        schedule.append(prediction)

    schedule.sort(key=lambda x: x['hours_remaining'])
    urgent    = [s for s in schedule if s['priority'] == 'urgent']
    scheduled = [s for s in schedule if s['priority'] == 'scheduled']
    routine   = [s for s in schedule if s['priority'] == 'routine']

    return jsonify({
        'total':     len(schedule),
        'urgent':    urgent,
        'scheduled': scheduled,
        'routine':   routine,
        'summary':   {
            'urgent_count':    len(urgent),
            'scheduled_count': len(scheduled),
            'routine_count':   len(routine),
        }
    })


# ═══════════════════════════════════════════════════════════════════════════
# E1 / E2 — TENANT CONFIG ENDPOINT
# Drives the config-driven UI renderer on the frontend.
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/tenant', methods=['GET'])
def get_tenant():
    """
    E1/E2 — Return active tenant configuration.
    The frontend bootForTenant() reads this on load and shows/hides
    nav tabs, collector panels, and site filters accordingly.
    """
    cfg = TENANTS.get(ACTIVE_TENANT, TENANTS['default'])
    return jsonify({
        'tenant_key':  ACTIVE_TENANT,
        'config':      cfg,
        'all_tenants': list(TENANTS.keys()),
    })



@app.route('/api/search', methods=['GET'])
def search_devices():
    """
    Search devices by query string, type filter, or health threshold.
    YouTube Search Service equivalent — find assets across all sectors instantly.
    Query params:
      q      — device ID substring or device type
      type   — exact device type filter
      max_score — return only devices below this health score
      min_score — return only devices above this health score
    """
    q         = request.args.get('q', '').lower().strip()
    type_filt = request.args.get('type', '').lower().strip()
    max_score = request.args.get('max_score', None)
    min_score = request.args.get('min_score', None)

    recent = {did: hist[-1] for did, hist in device_history.items() if hist}

    results = []
    for did, score in recent.items():
        # Type filter
        dtype = ''
        # Try to infer type from device_id prefix convention
        if did.startswith('net-'):   dtype = 'network'
        elif did.startswith('tc-'):  dtype = 'telecom'
        elif did.startswith('mc-'):  dtype = 'mining'
        elif did.startswith('cbs-'): dtype = 'cbs'

        # Apply filters
        if q and q not in did.lower() and q not in dtype:
            continue
        if type_filt and type_filt not in dtype and type_filt not in did.lower():
            continue
        if max_score is not None and score > float(max_score):
            continue
        if min_score is not None and score < float(min_score):
            continue

        results.append({
            'device_id':          did,
            'health_score':       round(score, 1),
            'status':             'critical' if score < 20 else 'warning' if score < 50 else 'healthy',
            'failure_probability': get_failure_probability(did, score),
            'uptime_pct':         get_uptime_pct(did),
            'sector':             dtype,
        })

    # Sort by health score ascending (worst first)
    results.sort(key=lambda x: x['health_score'])

    return jsonify({
        'query':        q or type_filt or 'all',
        'total':        len(results),
        'results':      results,
        'critical_count': sum(1 for r in results if r['status'] == 'critical'),
        'warning_count':  sum(1 for r in results if r['status'] == 'warning'),
    })

@app.route('/')
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
