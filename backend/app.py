"""
IISentinel™ v3.3 — Intelligent Infrastructure Sentinel (Flask)
===============================================================
v3.3 changes vs v3.2:
  ✓ Control Panel at /admin (Sophos-style admin console)
  ✓ Threshold management — CBS/warning/critical per device type
  ✓ Device registry — full CRUD from UI
  ✓ Maintenance windows — suppress alerts during planned work
  ✓ User management — add/remove specialists with roles
  ✓ Full audit log — every admin action timestamped
  ✓ Command dispatch — real webhook/SMS/email execution
  ✓ Database maintenance — vacuum, prune, clear resolved incidents
  ✓ System diagnostics — CPU/mem/disk via psutil (optional)
  ✓ Notification config — update channels without restart
  ✓ _refresh_maintenance() integrated into scoring pipeline

Run:     python app.py
Demo:    DEMO_MODE=true python app.py
Install: pip install flask flask-cors reportlab scikit-learn joblib \
                    numpy requests werkzeug psycopg2-binary psutil
"""
import os, re, json, time, random, threading, smtplib, sqlite3
import uuid, secrets, hashlib
from collections import deque
from datetime import datetime, timezone
from io import BytesIO
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import queue as _queue
import socket as _socket
import ipaddress as _ipaddress
import numpy as np
import joblib
import requests as req
from flask import Flask, request, jsonify, send_file, Response, stream_with_context

# ── Password hashing ──────────────────────────────────────────────────────────
try:
    from werkzeug.security import generate_password_hash, check_password_hash
    _WERKZEUG = True
except ImportError:
    _WERKZEUG = False
    def generate_password_hash(p):
        return 'sha256$' + hashlib.sha256(p.encode()).hexdigest()
    def check_password_hash(h, p):
        return h == 'sha256$' + hashlib.sha256(p.encode()).hexdigest()

# ── CORS ──────────────────────────────────────────────────────────────────────
try:
    from flask_cors import CORS as _CORS
    def _apply_cors(app): _CORS(app)
except ImportError:
    def _apply_cors(app):
        @app.after_request
        def _c(r):
            r.headers['Access-Control-Allow-Origin']  = '*'
            r.headers['Access-Control-Allow-Headers'] = \
                'Content-Type,X-Specialist-Token,X-Collector-Key,X-Api-Key'
            r.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
            return r

# ── Database ──────────────────────────────────────────────────────────────────
_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'iisentinel.db')

@contextmanager
def _db_conn():
    con = sqlite3.connect(_DB_PATH, timeout=10, check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA cache_size=-8192")
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

def _db_init():
    with _db_conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS metrics (
            id TEXT PRIMARY KEY, device_id TEXT, device_type TEXT,
            metric_name TEXT, metric_value REAL, health_score REAL,
            anomaly_flag INTEGER, predicted_score REAL,
            ai_diagnosis TEXT, automation_command TEXT, created_at TEXT);
        CREATE INDEX IF NOT EXISTS idx_metrics_dev ON metrics(device_id);
        CREATE INDEX IF NOT EXISTS idx_metrics_ts  ON metrics(created_at DESC);

        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, device_id TEXT, device_type TEXT,
            health_score REAL, ai_diagnosis TEXT, automation_command TEXT,
            status TEXT DEFAULT 'open', assigned_to TEXT, resolved_by TEXT,
            notes TEXT, created_at TEXT);

        CREATE TABLE IF NOT EXISTS specialists (
            id TEXT PRIMARY KEY, name TEXT UNIQUE,
            token TEXT, password_hash TEXT, role TEXT);

        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY, host TEXT NOT NULL,
            label TEXT, sector TEXT DEFAULT 'net', created_at TEXT);

        CREATE TABLE IF NOT EXISTS collectors (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, api_key TEXT NOT NULL,
            sector TEXT DEFAULT 'net', description TEXT,
            last_seen TEXT, reading_count INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1, created_at TEXT);

        CREATE TABLE IF NOT EXISTS cascade_topology (
            id TEXT PRIMARY KEY DEFAULT 'default',
            payload TEXT NOT NULL, updated_at TEXT);

        CREATE TABLE IF NOT EXISTS device_registry (
            id TEXT PRIMARY KEY, label TEXT, device_type TEXT,
            protocol TEXT, ip TEXT, community TEXT, sector TEXT,
            poll_interval INTEGER DEFAULT 15, enabled INTEGER DEFAULT 1,
            notes TEXT, created_at TEXT, updated_at TEXT);

        CREATE TABLE IF NOT EXISTS maintenance_windows (
            id TEXT PRIMARY KEY, label TEXT, device_ids TEXT,
            start_ts TEXT, end_ts TEXT, suppress_alerts INTEGER DEFAULT 1,
            created_by TEXT, created_at TEXT);

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, actor TEXT, action TEXT, target TEXT,
            detail TEXT, ip TEXT, result TEXT);

        CREATE TABLE IF NOT EXISTS thresholds (
            id TEXT PRIMARY KEY, device_type TEXT UNIQUE,
            critical_below REAL DEFAULT 20, warning_below REAL DEFAULT 50,
            cbs_hold_below REAL DEFAULT 90, ettf_warn_minutes INTEGER DEFAULT 120,
            ettf_crit_minutes INTEGER DEFAULT 30,
            updated_by TEXT, updated_at TEXT);

        CREATE TABLE IF NOT EXISTS dispatch_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, device_id TEXT, command_type TEXT,
            payload TEXT, result TEXT, sent_by TEXT);
        """)

        # ── Schema migrations (safe on existing DBs) ──────────────────────
        cols = {r[1] for r in con.execute("PRAGMA table_info(specialists)")}
        if 'token' not in cols:
            con.execute("ALTER TABLE specialists ADD COLUMN token TEXT")
        if 'password_hash' not in cols:
            con.execute("ALTER TABLE specialists ADD COLUMN password_hash TEXT")
        if 'password' in cols:
            for r in con.execute("SELECT id, password FROM specialists").fetchall():
                ph = generate_password_hash(r['password'] or 'changeme!')
                con.execute("UPDATE specialists SET password_hash=? WHERE id=?", (ph, r['id']))

        # ── Ensure default admin ──────────────────────────────────────────
        row = con.execute(
            "SELECT id, token, password_hash FROM specialists WHERE name='Admin'"
        ).fetchone()
        if not row:
            tok = secrets.token_hex(24)
            ph  = generate_password_hash('admin123')
            con.execute("INSERT INTO specialists VALUES (?,?,?,?,?)",
                        ('sp-001', 'Admin', tok, ph, 'admin'))
            print(f"\n  [IISentinel] Default admin created — token: {tok}\n")
        else:
            if not row['token']:
                tok = secrets.token_hex(24)
                con.execute("UPDATE specialists SET token=? WHERE id=?", (tok, row['id']))
                print(f"\n  [IISentinel] Admin token set: {tok}\n")
            if not row['password_hash']:
                con.execute(
                    "UPDATE specialists SET password_hash=? WHERE id=?",
                    (generate_password_hash('admin123'), row['id']))

_db_init()

# ── Rate limiter ──────────────────────────────────────────────────────────────
_rate_buckets: dict = {}
_rate_lock = threading.Lock()

def _rate_ok(key: str, max_calls: int = 5, window: int = 60) -> bool:
    now = time.time()
    with _rate_lock:
        bucket = [t for t in _rate_buckets.get(key, []) if now - t < window]
        if len(bucket) >= max_calls:
            return False
        bucket.append(now)
        _rate_buckets[key] = bucket
        return True

# ── ML Models ─────────────────────────────────────────────────────────────────
def _build_models():
    from sklearn.ensemble import RandomForestRegressor, IsolationForest
    print('[IISentinel] Building ML models...')
    rng = np.random.default_rng(42)
    X = rng.uniform([0,0,0,0,0,15,10],[100,1000,500,20,1000,80,100],size=(500,7))
    y = np.clip(100-(X[:,0]*.3+X[:,2]*.05+X[:,3]*2+np.maximum(0,80-X[:,6])*.5+X[:,3]*1.5),0,100)
    rf  = RandomForestRegressor(n_estimators=100,max_depth=10,random_state=42); rf.fit(X,y)
    iso = IsolationForest(n_estimators=100,contamination=0.08,random_state=42); iso.fit(X[y>=50])
    joblib.dump(rf,'health_model.pkl'); joblib.dump(iso,'anomaly_model.pkl')
    print('[IISentinel] ML models ready.'); return rf, iso

try:
    rf_model  = joblib.load('health_model.pkl')
    iso_model = joblib.load('anomaly_model.pkl')
    print('[IISentinel] ML models loaded.')
except Exception:
    rf_model, iso_model = _build_models()

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder='.', static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
_apply_cors(app)

# ── Constants ─────────────────────────────────────────────────────────────────
NETWORK_TYPES = ['router','switch','firewall','wan_link','workstation']
TELECOM_TYPES = ['base_station','network_tower','microwave_link']
MINING_TYPES  = ['pump','conveyor','ventilation','power_meter','sensor','plc','scada_node']
CBS_TYPES     = ['cbs_controller']
CBS_SAFETY_THRESHOLD = 90.0
RETRAIN_THRESHOLD    = 50
CACHE_TTL            = 2
WEATHER_CACHE_TTL    = 60

COST_RATES = {
    'pump':150000,'conveyor':120000,'ventilation':180000,'plc':80000,
    'scada_node':60000,'cbs_controller':450000,'power_meter':100000,
    'sensor':40000,'base_station':25000,'network_tower':35000,
    'microwave_link':40000,'router':15000,'switch':10000,
    'firewall':20000,'wan_link':12000,'workstation':2000
}
LOCATIONS = {
    'byo' :{'lat':-20.15,'lon':28.58,'name':'Bulawayo'},
    'hre' :{'lat':-17.82,'lon':31.05,'name':'Harare'},
    'mut' :{'lat':-18.97,'lon':32.67,'name':'Mutare'},
    'mine':{'lat':-17.65,'lon':29.85,'name':'Mine Site'}
}
FIELD_BOUNDS = {
    'cpu_load':(0,100),'bandwidth_mbps':(0,100000),'latency_ms':(0,60000),
    'packet_loss':(0,100),'connected_devices':(0,100000),
    'temperature':(-50,200),'signal_strength':(0,100),'metric_value':(-1e9,1e9)
}
READING_INTERVALS_MIN = {
    'pump':4,'conveyor':6,'ventilation':5,'cbs_controller':3,
    'router':10,'switch':10,'firewall':10,'wan_link':8,
    'base_station':8,'network_tower':10,'microwave_link':8,
    'plc':4,'scada_node':5,'sensor':3,'power_meter':6
}

# ── Global state ──────────────────────────────────────────────────────────────
metric_queue  = deque(maxlen=1000)
queue_lock    = threading.Lock()
_data_cache   = {'data': [], 'ts': 0}
_weather_cache: dict = {}

_history_lock  = threading.RLock()
device_history: dict = {}
device_uptime:  dict = {}

scoring_queue   = deque(maxlen=200)
scoring_results: dict = {}
scoring_lock    = threading.Lock()

reading_window:  list  = []
anomaly_count:   int   = 0
_retrain_lock           = threading.Lock()
_retrain_in_progress    = False
_sse_subs: list         = []
_sse_lock               = threading.Lock()
notification_log        = deque(maxlen=100)
_cbs_integrity_cache: dict = {}
_maintenance_active: dict  = {}   # device_id -> end_ts (populated by _refresh_maintenance)
_psutil_cache: dict        = {}   # refreshed every 5 s by background thread — never blocks a request

def _psutil_refresh_worker():
    """Update CPU/mem/disk in background every 5 s so admin endpoint returns instantly."""
    try:
        import psutil as _ps
    except ImportError:
        return   # psutil not installed — cache stays empty, UI shows N/A
    while True:
        try:
            mem  = _ps.virtual_memory()
            disk = _ps.disk_usage('/')
            _psutil_cache['cpu']      = _ps.cpu_percent(interval=1)   # 1-s sample inside background thread
            _psutil_cache['mem_used'] = round(mem.used  / 1024 / 1024, 1)
            _psutil_cache['mem_tot']  = round(mem.total / 1024 / 1024, 1)
            _psutil_cache['disk']     = round(disk.percent, 1)
        except Exception:
            pass
        time.sleep(5)

threading.Thread(target=_psutil_refresh_worker, daemon=True).start()

platform_stats = {
    'requests_total':0,'requests_failed':0,'cache_hits':0,'models_scored':0,
    'queue_depth':0,'last_flush':None,'last_retrain_attempt':None,
    'last_retrain_success':None,'retrain_count':0,'notifications_sent':0,
    'collector_readings':0,'uptime_start':datetime.now(timezone.utc).isoformat()
}

_DATA_API_KEY = os.environ.get('DATA_API_KEY', '')

NOTIFY = {
    'email_enabled'   : os.environ.get('NOTIFY_EMAIL_ENABLED','false').lower()=='true',
    'sms_enabled'     : bool(os.environ.get('AT_API_KEY') or os.environ.get('TWILIO_SID')),
    'whatsapp_enabled': bool(os.environ.get('WA_TOKEN')),
    'smtp_host'       : os.environ.get('SMTP_HOST','smtp.gmail.com'),
    'smtp_port'       : int(os.environ.get('SMTP_PORT','587')),
    'smtp_user'       : os.environ.get('SMTP_USER',''),
    'smtp_pass'       : os.environ.get('SMTP_PASS',''),
    'from_email'      : os.environ.get('SMTP_FROM','IISentinel <alerts@iisentinel.io>'),
    'to_emails'       : [e for e in os.environ.get('ALERT_EMAIL','').split(',') if e],
    'sms_numbers'     : [n for n in os.environ.get('ALERT_PHONE','').split(',') if n],
    'at_api_key'      : os.environ.get('AT_API_KEY',''),
    'at_username'     : os.environ.get('AT_USERNAME','sandbox'),
    'wa_token'        : os.environ.get('WA_TOKEN',''),
    'wa_phone_id'     : os.environ.get('WA_PHONE_ID',''),
    'wa_numbers'      : [n for n in os.environ.get('WA_TO','').split(',') if n],
    'sms_gateway'     : os.environ.get('SMS_GATEWAY','africastalking'),
    'twilio_sid'      : os.environ.get('TWILIO_SID',''),
    'twilio_token'    : os.environ.get('TWILIO_TOKEN',''),
    'twilio_from'     : os.environ.get('TWILIO_FROM','')
}

# ── Thread-safe history helpers ───────────────────────────────────────────────
def _history_append(did: str, score: float) -> list:
    with _history_lock:
        h = device_history.setdefault(did, [])
        h.append(score)
        if len(h) > 20: h.pop(0)
        return list(h)

def _history_get(did: str) -> list:
    with _history_lock:
        return list(device_history.get(did, []))

def _history_snapshot() -> dict:
    with _history_lock:
        return {d: h[-1] for d, h in device_history.items() if h}

# ── Maintenance window helper ─────────────────────────────────────────────────
def _refresh_maintenance():
    """Refresh in-memory maintenance window cache from DB."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT device_ids, end_ts FROM maintenance_windows "
                "WHERE start_ts <= ? AND end_ts >= ?", (now, now)
            ).fetchall()
        _maintenance_active.clear()
        for r in rows:
            for did in (r['device_ids'] or '').split(','):
                did = did.strip()
                if did:
                    _maintenance_active[did] = r['end_ts']
    except Exception:
        pass

def _in_maintenance(device_id: str) -> bool:
    """Return True if device is currently in a maintenance window."""
    if not _maintenance_active:
        return False
    if device_id in _maintenance_active:
        return True
    if 'ALL' in _maintenance_active:
        return True
    return False

# ── Notifications ─────────────────────────────────────────────────────────────
def send_sms(message: str):
    if not NOTIFY['sms_enabled']: return
    try:
        if NOTIFY['sms_gateway']=='africastalking' and NOTIFY['at_api_key']:
            req.post('https://api.africastalking.com/version1/messaging',
                headers={'apiKey':NOTIFY['at_api_key'],'Accept':'application/json'},
                data={'username':NOTIFY['at_username'],
                      'to':','.join(NOTIFY['sms_numbers']),
                      'message':f'IISentinel: {message}','from':'IISentinel'},timeout=8)
        elif NOTIFY['sms_gateway']=='twilio' and NOTIFY['twilio_sid']:
            from twilio.rest import Client
            Client(NOTIFY['twilio_sid'],NOTIFY['twilio_token']).messages.create(
                body=f'IISentinel: {message}',from_=NOTIFY['twilio_from'],
                to=NOTIFY['sms_numbers'][0] if NOTIFY['sms_numbers'] else '')
    except Exception as e: print(f'[SMS] {e}')

def send_whatsapp(message: str):
    if not NOTIFY['whatsapp_enabled'] or not NOTIFY['wa_token']: return
    try:
        for num in NOTIFY['wa_numbers']:
            req.post(f"https://graph.facebook.com/v19.0/{NOTIFY['wa_phone_id']}/messages",
                headers={'Authorization':f"Bearer {NOTIFY['wa_token']}",
                         'Content-Type':'application/json'},
                json={'messaging_product':'whatsapp','to':num,'type':'text',
                      'text':{'body':f'IISentinel\n{message}'}},timeout=8)
    except Exception as e: print(f'[WhatsApp] {e}')

def send_email(subject, body, device_id=None, health_score=None,
               diagnosis=None, automation_command=None, severity='warning'):
    if not NOTIFY['email_enabled'] or not NOTIFY['smtp_user'] or not NOTIFY['to_emails']:
        return
    C = {'critical':'#ff3e50','cbs':'#ff3e50','warning':'#f5a020','info':'#20e07a'}.get(severity,'#34c6f4')
    html = f"""<html><body style="font-family:Arial,sans-serif;background:#eef0f7;padding:32px 0">
<table width="560" style="background:#fff;border-radius:12px;margin:auto">
<tr><td style="background:{C};padding:20px 28px">
  <b style="font-size:18px;color:#fff">IISentinel&#x2122;</b>
  <span style="font-size:10px;background:rgba(255,255,255,.2);color:#fff;
        padding:2px 8px;border-radius:20px;margin-left:8px">{severity.upper()}</span>
</td></tr>
<tr><td style="padding:24px">
  <p style="font-size:16px;font-weight:700;color:#0c1122">{subject}</p>
  {f'<p style="font-size:12px;color:#8592a8">Device: <b>{device_id}</b></p>' if device_id else ''}
  {f'<p>Health: <b style="color:{C}">{health_score:.0f}/100</b></p>' if health_score is not None else ''}
  {f'<p style="font-size:11px">{diagnosis}</p>' if diagnosis else ''}
  {f'<p style="font-size:11px;color:#c07800;background:#fff4e6;padding:8px;border-left:3px solid #f5a020">{automation_command}</p>' if automation_command else ''}
</td></tr></table></body></html>"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'[IISentinel] {severity.upper()}: {subject}'
        msg['From']    = NOTIFY['from_email']
        msg['To']      = ', '.join(NOTIFY['to_emails'])
        msg.attach(MIMEText(body,'plain')); msg.attach(MIMEText(html,'html'))
        with smtplib.SMTP(NOTIFY['smtp_host'], NOTIFY['smtp_port']) as s:
            if NOTIFY['smtp_user']: s.starttls(); s.login(NOTIFY['smtp_user'], NOTIFY['smtp_pass'])
            s.send_message(msg)
    except Exception as e: print(f'[Email] {e}')

def notify_all(subject, message, level='critical', device_id=None,
               health_score=None, diagnosis=None, automation_command=None):
    notification_log.appendleft({'subject':subject,'message':message,'level':level,
        'device_id':device_id,'ts':datetime.now(timezone.utc).isoformat()})
    platform_stats['notifications_sent'] += 1
    if level in ('critical','cbs'):
        threading.Thread(target=send_sms,args=(f'{subject}: {message}',),daemon=True).start()
        threading.Thread(target=send_whatsapp,args=(f'{subject}\n{message}',),daemon=True).start()
    threading.Thread(target=send_email,
        kwargs=dict(subject=subject,body=message,device_id=device_id,
                    health_score=health_score,diagnosis=diagnosis,
                    automation_command=automation_command,severity=level),
        daemon=True).start()

# ── SSE broadcast ─────────────────────────────────────────────────────────────
def sse_broadcast(event_type: str, payload: dict):
    msg = f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_subs:
            try: q.put_nowait(msg)
            except: dead.append(q)
        for q in dead:
            try: _sse_subs.remove(q)
            except ValueError: pass

# ── Background workers ────────────────────────────────────────────────────────
def flush_worker():
    while True:
        time.sleep(1)
        with queue_lock:
            if not metric_queue: continue
            batch = list(metric_queue); metric_queue.clear()
        try:
            ts = datetime.now(timezone.utc).isoformat()
            rows = [(str(uuid.uuid4()),
                     i.get('device_id',''),i.get('device_type',''),
                     i.get('metric_name',''),float(i.get('metric_value',0)),
                     float(i.get('health_score',50)),int(i.get('anomaly_flag',0)),
                     float(i.get('predicted_score',50)),
                     i.get('ai_diagnosis'),i.get('automation_command'),ts)
                    for i in batch]
            with _db_conn() as con:
                con.executemany(
                    "INSERT OR IGNORE INTO metrics VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)
        except Exception as e: print(f'[Flush] {e}')
        platform_stats['last_flush']  = datetime.now(timezone.utc).isoformat()
        platform_stats['queue_depth'] = len(metric_queue)

def scorer_worker():
    while True:
        time.sleep(0.5)
        with scoring_lock:
            if not scoring_queue: continue
            item = scoring_queue.popleft()
        try:
            arr   = np.array([item['features']])
            score = float(np.clip(rf_model.predict(arr)[0],0,100))
            anom  = bool(iso_model.predict(arr)[0]==-1)
            scoring_results[item['device_id']] = {
                'health_score':score,'anomaly_flag':anom,'ts':time.time()}
            platform_stats['models_scored'] += 1
        except Exception as e: print(f'[Scorer] {e}')

def retrain_worker():
    global rf_model, iso_model, anomaly_count, _retrain_in_progress
    while True:
        time.sleep(60)
        if anomaly_count < RETRAIN_THRESHOLD: continue
        with _retrain_lock:
            if _retrain_in_progress: continue
            _retrain_in_progress = True
        try:
            from sklearn.ensemble import RandomForestRegressor, IsolationForest
            platform_stats['last_retrain_attempt'] = datetime.now(timezone.utc).isoformat()
            with _db_conn() as con:
                rows = [dict(r) for r in
                        con.execute("SELECT * FROM metrics ORDER BY created_at DESC LIMIT 2000")]
            if len(rows) < 50: continue
            X, y = [], []
            for r in rows:
                f = [r.get('cpu_load',50) or 50, r.get('bandwidth_mbps',100) or 100,
                     r.get('latency_ms',10) or 10, r.get('packet_loss',0) or 0,
                     r.get('connected_devices',10) or 10,
                     r.get('temperature',40) or 40, r.get('signal_strength',80) or 80]
                if None not in f and r.get('health_score') is not None:
                    X.append(f); y.append(r['health_score'])
            if len(X) < 50: continue
            X = np.array(X); y = np.array(y)
            nrf  = RandomForestRegressor(n_estimators=100,max_depth=10,random_state=42)
            nrf.fit(X,y)
            niso = IsolationForest(n_estimators=100,contamination=0.08,random_state=42)
            niso.fit(X[y>=50])
            joblib.dump(nrf,'health_model.pkl'); joblib.dump(niso,'anomaly_model.pkl')
            rf_model = nrf; iso_model = niso; anomaly_count = 0
            platform_stats['last_retrain_success'] = datetime.now(timezone.utc).isoformat()
            platform_stats['retrain_count'] = platform_stats.get('retrain_count',0)+1
            print(f'[Retrain] Done — {len(X)} samples')
        except Exception as e: print(f'[Retrain] {e}')
        finally:
            with _retrain_lock: _retrain_in_progress = False

def full_sync_worker():
    while True:
        time.sleep(30)
        try:
            data  = get_cached_data()
            snap  = _history_snapshot()
            intel = {
                'federated_index'      : get_federated_health_index(list(snap.values())),
                'failure_probabilities': {d: get_failure_probability(d, s) for d,s in snap.items()},
                'uptime'               : {d: get_uptime_pct(d) for d in device_uptime},
                'ttf_minutes'          : {d: v for d,s in snap.items()
                                          if (v := get_ettf_minutes(d, s, '')) is not None},
                'anomaly_count'        : anomaly_count,
                'total_devices'        : len(device_history),
                'retrain_needed'       : anomaly_count >= RETRAIN_THRESHOLD,
                'retrain_in_progress'  : _retrain_in_progress,
            }
            sse_broadcast('full_sync', {'data': data, 'intel': intel, 'ts': time.time()})
        except Exception as e: print(f'[FullSync] {e}')

def maintenance_refresh_worker():
    """Refresh maintenance windows every 60 s so they activate on time."""
    while True:
        time.sleep(60)
        _refresh_maintenance()

for _fn in (flush_worker, scorer_worker, retrain_worker, full_sync_worker, maintenance_refresh_worker):
    threading.Thread(target=_fn, daemon=True).start()

# ── Helpers ───────────────────────────────────────────────────────────────────
def build_features(data: dict) -> list:
    return [float(data.get('cpu_load',50) or 50),
            float(data.get('bandwidth_mbps',100) or 100),
            float(data.get('latency_ms',10) or 10),
            float(data.get('packet_loss',0) or 0),
            float(data.get('connected_devices',10) or 10),
            float(data.get('temperature',40) or 40),
            float(data.get('signal_strength',80) or 80)]

def get_failure_probability(device_id: str, score: float) -> float:
    h = _history_get(device_id)
    if len(h) < 3: return max(0.0, round((100-score)*0.05,1))
    window = h[-10:]; n = len(window)
    xm = (n-1)/2; ym = sum(window)/n
    num = sum((i-xm)*(window[i]-ym) for i in range(n))
    den = sum((i-xm)**2 for i in range(n))
    slope = num/den if den>0 else 0
    if slope >= -0.2: return max(0.0, round((100-score)*0.05,1))
    rtc = max(1,(score-20)/abs(slope)) if slope<0 and score>20 else 999
    prob = min(99.0, round(100*(1-rtc/60),1)) if rtc<60 else round((100-score)*0.08,1)
    return max(0.0, prob)

def get_ettf_minutes(device_id: str, score: float, device_type: str = ''):
    h = _history_get(device_id)
    if len(h) < 5: return None
    window = h[-10:]; n = len(window)
    if n < 3: return None
    xm = (n-1)/2; ym = sum(window)/n
    num = sum((i-xm)*(window[i]-ym) for i in range(n))
    den = sum((i-xm)**2 for i in range(n))
    slope = num/den if den>0 else 0
    if slope >= -0.3: return None
    if score <= 18.0: return 0
    readings_needed = (score-18.0)/abs(slope)
    interval = READING_INTERVALS_MIN.get(device_type, 5)
    return max(1, round(readings_needed*interval))

def get_cbs_integrity_score(device_id: str, link_health: float, metric_data: dict):
    h = _history_get(device_id)
    volatility = 0.0
    if len(h) >= 5:
        diffs = [abs(h[i]-h[i-1]) for i in range(1,len(h))]
        volatility = sum(diffs)/max(1,len(diffs))
    vib_score  = max(0.0, min(100.0, 100.0-volatility*2.8))
    temp       = float(metric_data.get('temperature',35) or 35)
    temp_score = max(0.0, min(100.0, 100.0-max(0.0,temp-45.0)*1.8))
    integrity  = link_health*0.55 + vib_score*0.30 + temp_score*0.15
    return round(min(100.0,max(0.0,integrity)),1), round(vib_score,1)

def get_federated_health_index(scores: list) -> float:
    if not scores: return 100.0
    w = [s*0.5 if s<20 else s*0.8 if s<50 else s for s in scores]
    return round(sum(w)/len(w), 1)

def get_diagnosis(dtype, protocol, mname, mval, score, anom, integrity_score=None):
    issues=[]; actions=[]
    if   score < 20: issues.append('critical failure');     actions.append('immediate intervention')
    elif score < 35: issues.append('severe degradation');   actions.append('escalate to operations')
    elif score < 50: issues.append('moderate degradation'); actions.append('schedule maintenance <24h')
    if dtype in TELECOM_TYPES+NETWORK_TYPES:
        if mval>100 and 'latency' in str(mname): issues.append(f'latency {mval:.0f}ms')
        if mval>2   and 'packet'  in str(mname): issues.append(f'packet loss {mval:.1f}%')
        if mval<40  and 'signal'  in str(mname): issues.append(f'signal {mval:.0f}%')
    elif dtype in MINING_TYPES:
        if mval>75 and 'temp' in str(mname): issues.append(f'temperature {mval:.0f}C')
    elif dtype == 'cbs_controller':
        thr = CBS_SAFETY_THRESHOLD
        if integrity_score is not None and integrity_score < thr:
            issues.append(f'CBS integrity {integrity_score:.1f}% < {thr}%')
            actions.append('BLAST HOLD — check vibration sensors and enclosure')
        elif score < thr:
            issues.append(f'CBS DNP3 link {score:.1f}% < {thr}%')
            actions.append('BLAST HOLD — notify blasting officer, inspect DNP3 cable')
    if anom: issues.append('AI anomaly detected'); actions.append('cross-reference event log')
    if not issues:
        return f'Device normal via {protocol or "Ethernet"}. Score {score:.1f}/100. Monitoring: {mname}={mval:.2f}.'
    return f'{"; ".join(issues).capitalize()}. Action: {"; ".join(actions).capitalize()}.'

def get_auto_cmd(device_id, dtype, score, blast_hold=False, integrity_score=None):
    eff_hold = blast_hold or (dtype=='cbs_controller' and (
        score < CBS_SAFETY_THRESHOLD or
        (integrity_score is not None and integrity_score < CBS_SAFETY_THRESHOLD)))
    if dtype=='cbs_controller' and eff_hold:
        integ = f'{integrity_score:.1f}' if integrity_score is not None else f'{score:.1f}'
        return (f'CBS SAFETY INTERLOCK: BLAST HOLD on {device_id} — '
                f'link {score:.1f}% / integrity {integ}%')
    if dtype in ['ventilation','pump'] and score<20:
        return f'EMERGENCY: Safety shutdown {device_id} — underground evacuation alert'
    if score < 20: return f'CRITICAL: Emergency restart for {device_id}'
    if score < 35: return f'WARNING: Isolate {device_id} — reduce load'
    if score < 50: return f'CAUTION: Schedule maintenance for {device_id}'
    return None

def update_uptime(did, score):
    device_uptime.setdefault(did,{'total':0,'healthy':0})
    device_uptime[did]['total']   += 1
    if score >= 50: device_uptime[did]['healthy'] += 1

def get_uptime_pct(did):
    d = device_uptime.get(did,{'total':0,'healthy':0})
    return 100.0 if d['total']==0 else round(d['healthy']/d['total']*100,1)

def sanitize_metric(data: dict):
    if not isinstance(data,dict): return {}, 'Payload must be JSON object'
    for f in ['device_id','device_type']:
        if not data.get(f): return {}, f'Missing: {f}'
    did = str(data['device_id'])
    if not re.match(r'^[a-zA-Z0-9_\-]{1,80}$', did): return {}, 'Invalid device_id'
    cleaned = dict(data); cleaned['device_id'] = did
    for field,(lo,hi) in FIELD_BOUNDS.items():
        if field in cleaned:
            try: cleaned[field] = float(max(lo,min(hi,float(cleaned[field]))))
            except: cleaned[field] = (lo+hi)/2
    return cleaned, None

def get_cached_data() -> list:
    now = time.time()
    if now - _data_cache['ts'] < CACHE_TTL and _data_cache['data']:
        platform_stats['cache_hits'] += 1
        return _data_cache['data']
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT * FROM (SELECT * FROM metrics ORDER BY created_at DESC LIMIT 1000) "
                "GROUP BY device_id ORDER BY created_at DESC").fetchall()
        data = [dict(r) for r in rows]
        for item in data:
            did = item.get('device_id','')
            if did in _cbs_integrity_cache:
                item.update(_cbs_integrity_cache[did])
        _data_cache['data'] = data
        _data_cache['ts']   = now
        return data
    except Exception as e:
        print(f'[Cache] {e}')
        return _data_cache['data']

def process_single_metric(data: dict) -> dict:
    global anomaly_count
    did   = data['device_id']
    dtype = data['device_type']
    proto = data.get('protocol','Ethernet')

    features = build_features(data)
    arr      = np.array([features])
    score    = float(np.clip(rf_model.predict(arr)[0], 0, 100))
    if dtype == 'cbs_controller':
        score = min(score, data.get('signal_strength', score))
    anom = bool(iso_model.predict(arr)[0] == -1)
    if anom: anomaly_count += 1

    with scoring_lock:
        scoring_queue.append({'features':features,'device_id':did})

    _history_append(did, score)
    reading_window.append(score)
    if len(reading_window) > 10: reading_window.pop(0)

    predicted   = max(0,min(100,score+(reading_window[-1]-reading_window[0]))) \
                  if len(reading_window)>=3 else score
    fail_prob   = get_failure_probability(did, score)
    ettf        = get_ettf_minutes(did, score, dtype)
    fhi         = get_federated_health_index([_history_snapshot().get(d,50)
                                               for d in device_history])
    update_uptime(did, score)
    uptime_pct  = get_uptime_pct(did)

    integrity_score = vibration_score = None
    if dtype == 'cbs_controller':
        integrity_score, vibration_score = get_cbs_integrity_score(did, score, data)
        _cbs_integrity_cache[did] = {
            'integrity_score':integrity_score,'vibration_score':vibration_score}

    eff_hold = data.get('blast_hold',False) or (dtype=='cbs_controller' and (
        score < CBS_SAFETY_THRESHOLD or
        (integrity_score is not None and integrity_score < CBS_SAFETY_THRESHOLD)))

    # ── Suppress alerts during maintenance window ─────────────────────────
    in_maint = _in_maintenance(did)

    ai_diag = auto_cmd = None
    if (anom or score < 50 or eff_hold) and not in_maint:
        ai_diag  = get_diagnosis(dtype,proto,data.get('metric_name',''),
                                 data.get('metric_value',0),score,anom,integrity_score)
        auto_cmd = get_auto_cmd(did,dtype,score,eff_hold,integrity_score)

    rec = {
        'device_id':did,'device_type':dtype,
        'metric_name':data.get('metric_name','unknown'),
        'metric_value':float(data.get('metric_value',0)),
        'health_score':score,'anomaly_flag':anom,
        'predicted_score':predicted,'ai_diagnosis':ai_diag,
        'automation_command':auto_cmd
    }
    if integrity_score is not None:
        rec['integrity_score']  = integrity_score
        rec['vibration_score']  = vibration_score

    with queue_lock: metric_queue.append(rec)

    if (score < 50 or anom) and not in_maint:
        try:
            with _db_conn() as con:
                con.execute(
                    "INSERT OR IGNORE INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()),did,dtype,score,ai_diag,auto_cmd,
                     'open',None,None,None,datetime.now(timezone.utc).isoformat()))
        except Exception: pass

    sse_payload = {
        'device_id':did,'device_type':dtype,
        'metric_name':data.get('metric_name',''),
        'metric_value':float(data.get('metric_value',0)),
        'health_score':round(score,1),'anomaly_flag':anom,
        'blast_hold':eff_hold,'is_cbs':dtype=='cbs_controller',
        'ai_diagnosis':ai_diag,'automation_command':auto_cmd,
        'failure_probability':fail_prob,'uptime_pct':uptime_pct,
        'ettf_minutes':ettf,'integrity_score':integrity_score,
        'vibration_score':vibration_score,
        'in_maintenance':in_maint,
        'created_at':datetime.now(timezone.utc).isoformat(),
    }

    if eff_hold and not in_maint:
        sse_broadcast('cbs_hold', sse_payload)
        notify_all(f'CBS BLAST HOLD — {did}',
                   f'Link {score:.1f}% / integrity {integrity_score or score:.1f}%',
                   level='cbs', device_id=did, health_score=score,
                   diagnosis=ai_diag, automation_command=auto_cmd)
    elif score<20 and dtype in ['ventilation','pump'] and not in_maint:
        notify_all(f'EMERGENCY: {did}',f'{dtype} at {score:.1f}%.',
                   level='critical', device_id=did, health_score=score,
                   diagnosis=ai_diag, automation_command=auto_cmd)

    sse_broadcast('metric', sse_payload)

    return {
        'status':'ok','health_score':round(score,1),'anomaly_flag':anom,
        'predicted_score':round(predicted,1),'failure_probability':fail_prob,
        'ai_diagnosis':ai_diag,'automation_command':auto_cmd,
        'federated_index':fhi,'uptime_pct':uptime_pct,'blast_hold':eff_hold,
        'integrity_score':integrity_score,'vibration_score':vibration_score,
        'protocol':proto,'retrain_needed':anomaly_count>=RETRAIN_THRESHOLD,
        'ettf_minutes':ettf,'in_maintenance':in_maint
    }

# ── Auth decorators ───────────────────────────────────────────────────────────
def require_specialist(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = request.headers.get('X-Specialist-Token','').strip()
        if not token: return jsonify({'error':'Unauthorised'}),401
        try:
            with _db_conn() as con:
                row = con.execute(
                    "SELECT * FROM specialists WHERE token=?", (token,)
                ).fetchone()
                if not row: return jsonify({'error':'Invalid token'}),401
                request.specialist_name = row['name']
                request.specialist_role = row['role'] or 'engineer'
        except Exception as e:
            return jsonify({'error':f'Auth error: {e}'}),401
        return f(*args,**kwargs)
    return decorated

def require_admin(f):
    """Same as require_specialist — all specialists can access admin panel."""
    @wraps(f)
    def decorated(*args,**kwargs):
        token = request.headers.get('X-Specialist-Token','').strip()
        if not token: return jsonify({'error':'Unauthorised'}),401
        try:
            with _db_conn() as con:
                row = con.execute(
                    "SELECT * FROM specialists WHERE token=?", (token,)
                ).fetchone()
                if not row: return jsonify({'error':'Invalid token'}),401
                request.specialist_name = row['name']
                request.specialist_role = row['role'] or 'engineer'
        except Exception as e:
            return jsonify({'error':f'Auth error: {e}'}),401
        return f(*args,**kwargs)
    return decorated

def optional_data_auth(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        if _DATA_API_KEY:
            key = request.headers.get('X-Api-Key','').strip()
            if key != _DATA_API_KEY:
                return jsonify({'error':'API key required for data access'}),401
        return f(*args,**kwargs)
    return decorated

# ── Audit log helper ──────────────────────────────────────────────────────────
def _audit(actor, action, target, detail='', result='ok', ip='system'):
    try:
        with _db_conn() as con:
            con.execute(
                "INSERT INTO audit_log (ts,actor,action,target,detail,ip,result) VALUES (?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), actor, action, target, detail, ip, result)
            )
    except Exception as e:
        print(f'[Audit] {e}')

# ── Demo mode ─────────────────────────────────────────────────────────────────
DEMO_DEVICES = [
    {'id':'net-byo-router-01',     'type':'router',         'bsig':90,'blat':35,'bbw':120,'btemp':42},
    {'id':'net-byo-switch-core',   'type':'switch',         'bsig':88,'blat':8, 'bbw':480,'btemp':38},
    {'id':'net-hre-router-01',     'type':'router',         'bsig':82,'blat':28,'bbw':95, 'btemp':45},
    {'id':'net-hre-wan-link',      'type':'wan_link',       'bsig':75,'blat':62,'bbw':55, 'btemp':40},
    {'id':'net-mut-firewall-01',   'type':'firewall',       'bsig':85,'blat':18,'bbw':75, 'btemp':44},
    {'id':'tc-byo-base-stn-01',    'type':'base_station',   'bsig':78,'blat':15,'bbw':220,'btemp':52},
    {'id':'tc-hre-tower-main',     'type':'network_tower',  'bsig':82,'blat':22,'bbw':180,'btemp':48},
    {'id':'tc-mut-microwave-01',   'type':'microwave_link', 'bsig':70,'blat':35,'bbw':120,'btemp':55},
    {'id':'mc-shaft1-pump-01',     'type':'pump',           'bsig':88,'blat':12,'bbw':18, 'btemp':68},
    {'id':'mc-shaft1-pump-02',     'type':'pump',           'bsig':84,'blat':14,'bbw':16, 'btemp':72},
    {'id':'mc-shaft2-ventilation', 'type':'ventilation',    'bsig':86,'blat':10,'bbw':22, 'btemp':75},
    {'id':'mc-shaft2-conveyor',    'type':'conveyor',       'bsig':90,'blat':8, 'bbw':20, 'btemp':62},
    {'id':'mc-plant-plc-01',       'type':'plc',            'bsig':92,'blat':6, 'bbw':30, 'btemp':55},
    {'id':'mc-surface-pwr-meter',  'type':'power_meter',    'bsig':95,'blat':9, 'bbw':12, 'btemp':48},
    {'id':'cbs-dnp3-mine-ctrl',    'type':'cbs_controller', 'bsig':96,'blat':5, 'bbw':8,  'btemp':35},
]

def _demo_ingest(payload):
    data, err = sanitize_metric(payload)
    if err: return
    process_single_metric(data)

def demo_worker():
    in_event = {d['id']:0 for d in DEMO_DEVICES}
    print('[Demo] Injection active — 15 devices, 4 sites')
    while True:
        for dev in DEMO_DEVICES:
            did = dev['id']; dtype = dev['type']
            if in_event[did]>0: in_event[did]-=1
            elif random.random()<0.08: in_event[did]=random.randint(4,12)
            if dtype=='cbs_controller' and random.random()<0.008:
                in_event[did]=random.randint(6,10)
            sev  = in_event[did]/12.0
            sig  = max(20, dev['bsig']*(1-sev*.45)+random.gauss(0,4))
            lat  = max(1,  dev['blat']*(1+sev*3.0)+random.gauss(0,dev['blat']*.1))
            bw   = max(1,  dev['bbw']*(1-sev*.6)+random.gauss(0,dev['bbw']*.08))
            temp = dev['btemp']*(1+sev*.5)+random.gauss(0,3)
            cpu  = min(98, 20+sev*75+random.gauss(0,8))
            loss = max(0,  sev*8+random.gauss(0,0.8))
            if dtype in MINING_TYPES:              mn,mv='temperature',round(temp,1)
            elif dtype in TELECOM_TYPES+CBS_TYPES: mn,mv='signal_strength',round(sig,1)
            else:                                  mn,mv='latency_ms',round(lat,1)
            proto = ('DNP3/Ethernet'        if dtype=='cbs_controller' else
                     'Profinet/EtherNet-IP' if dtype in MINING_TYPES   else
                     'SNMP/Ethernet-802.3')
            try:
                _demo_ingest({'device_id':did,'device_type':dtype,
                    'metric_name':mn,'metric_value':mv,
                    'cpu_load':round(cpu,1),'bandwidth_mbps':round(bw,1),
                    'latency_ms':round(lat,1),'packet_loss':round(loss,2),
                    'connected_devices':max(1,int(10*(1-sev*.4))),
                    'temperature':round(temp,1),'signal_strength':round(sig,1),
                    'protocol':proto})
            except Exception as e: print(f'[Demo] {e}')
        time.sleep(random.uniform(3.0,5.0))

if os.environ.get('DEMO_MODE','false').lower()=='true':
    threading.Thread(target=demo_worker, daemon=True).start()

# ── Node monitor ──────────────────────────────────────────────────────────────
_nodes: dict   = {}
_nodes_lock    = threading.Lock()
_node_executor = ThreadPoolExecutor(max_workers=32, thread_name_prefix='node-probe')
_PROBE_PORTS   = [80,443,22,161,8080]

def _probe_port(host: str, port: int, timeout: float=1.5):
    try:
        t0 = time.time()
        s  = _socket.create_connection((host,port), timeout=timeout)
        s.close()
        return True, round((time.time()-t0)*1000)
    except Exception:
        return False, None

def _probe_host(host: str, timeout: float=1.5):
    for port in _PROBE_PORTS:
        ok, lat = _probe_port(host, port, timeout)
        if ok: return True, lat
    try:
        t0 = time.time()
        _socket.getaddrinfo(host, None, _socket.AF_INET, _socket.SOCK_STREAM)
        return True, round((time.time()-t0)*1000)
    except Exception:
        return False, None

def _poll_node(node_id: str):
    with _nodes_lock:
        if node_id not in _nodes: return
        node = dict(_nodes[node_id])
    future = _node_executor.submit(_probe_host, node['host'], 1.5)
    try:
        reachable, latency = future.result(timeout=2.0)
    except Exception:
        reachable, latency = False, None
    loss_pct = 0
    if reachable:
        futures = [_node_executor.submit(_probe_port, node['host'], _PROBE_PORTS[0], 0.8)
                   for _ in range(3)]
        failed = sum(1 for f in futures if not f.result(timeout=1.5)[0])
        loss_pct = round((failed/3)*100)
    else:
        loss_pct = 100
    health = 0 if not reachable else max(0, round(
        100 - min(50,(latency or 0)/10) - loss_pct*0.6))
    status = 'up' if reachable else 'down'
    now    = time.time()
    with _nodes_lock:
        if node_id not in _nodes: return
        _nodes[node_id].update({
            'status':status,'latency_ms':latency,'loss_pct':loss_pct,
            'last_check':now,'health_score':health})
        hist = _nodes[node_id].get('history', deque(maxlen=20))
        hist.append({'ts':now,'status':status,'latency':latency,'health':health})
        _nodes[node_id]['history'] = hist
    sector = node.get('sector','net')
    label  = node.get('label', node['host'])
    did    = f"{sector}-node-{node_id[:8]}"
    try:
        features = [min(100,(latency or 0)/5), max(0,100-loss_pct*2),
                    min(500,latency or 0), loss_pct, 1, 35, health]
        arr   = np.array([features])
        score = float(np.clip(rf_model.predict(arr)[0],0,100))
        anom  = bool(iso_model.predict(arr)[0]==-1)
        _history_append(did, score)
        update_uptime(did, score)
        rec = {
            'device_id'        : did,
            'device_type'      : 'router' if sector=='net' else
                                 'base_station' if sector=='tc' else 'sensor',
            'metric_name'      : 'latency_ms',
            'metric_value'     : float(latency or 0),
            'health_score'     : score,
            'anomaly_flag'     : anom,
            'predicted_score'  : score,
            'ai_diagnosis'     : (f'Node {label} unreachable — packet loss 100%.' if not reachable
                                  else f'Elevated latency {latency}ms.' if (latency or 0)>120 else None),
            'automation_command': (f'ALERT: Node {label} ({node["host"]}) DOWN.'
                                   if not reachable else None)
        }
        with queue_lock: metric_queue.append(rec)
    except Exception as e: print(f'[NodePoll ML] {e}')

def _background_poller():
    while True:
        time.sleep(30)
        with _nodes_lock: ids = list(_nodes.keys())
        for nid in ids:
            _node_executor.submit(_poll_node, nid)

threading.Thread(target=_background_poller, daemon=True).start()

def _restore_nodes_from_db():
    time.sleep(2)
    try:
        with _db_conn() as con:
            rows = con.execute("SELECT id,host,label,sector FROM nodes").fetchall()
        for row in rows:
            nid,host,label,sector = row['id'],row['host'],row['label'],row['sector']
            with _nodes_lock:
                if nid not in _nodes:
                    _nodes[nid] = {'host':host,'label':label,'sector':sector,
                                   'status':'checking','latency_ms':None,'loss_pct':0,
                                   'last_check':None,'health_score':0,
                                   'history':deque(maxlen=20)}
            _node_executor.submit(_poll_node, nid)
        if rows: print(f'[Nodes] Restored {len(rows)} saved nodes')
    except Exception as e: print(f'[Nodes] Restore error: {e}')

threading.Thread(target=_restore_nodes_from_db, daemon=True).start()

# ════════════════════════════════════════════════════════════════════
# ROUTES — DASHBOARD
# ════════════════════════════════════════════════════════════════════
app_root = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def index():
    try:
        with open(os.path.join(app_root,'dashboard.html'),encoding='utf-8') as f:
            return f.read(),200,{'Content-Type':'text/html; charset=utf-8'}
    except FileNotFoundError:
        return '<h1>dashboard.html not found</h1>',404

@app.route('/admin')
def admin_panel():
    try:
        with open(os.path.join(app_root,'controlpanel.html'),encoding='utf-8') as f:
            return f.read(),200,{'Content-Type':'text/html; charset=utf-8'}
    except FileNotFoundError:
        return '<h1>controlpanel.html not found — place it in the backend/ folder</h1>',404

@app.route('/health')
def health_check():
    q    = len(metric_queue)
    age  = round(time.time()-_data_cache['ts'],1)
    start= platform_stats['uptime_start'].replace('Z','+00:00')
    up   = (datetime.now(timezone.utc)-datetime.fromisoformat(start)).total_seconds()
    deg  = q>450 or (age>300 and _data_cache['ts']>0)
    return jsonify({'status':'degraded' if deg else 'ok',
        'uptime_h':round(up/3600,2),'queue_depth':q,'cache_age_s':age,
        'devices':len(device_history),'version':'3.3'}),(503 if deg else 200)

@app.route('/api/data')
@optional_data_auth
def get_data():
    platform_stats['requests_total'] += 1
    return jsonify(get_cached_data())

@app.route('/api/metrics', methods=['POST','OPTIONS'])
def receive_metrics():
    if request.method=='OPTIONS': return '',204
    platform_stats['requests_total'] += 1
    raw = request.get_json(silent=True)
    if not raw:
        platform_stats['requests_failed'] += 1
        return jsonify({'error':'Empty payload'}),400
    data, err = sanitize_metric(raw)
    if err:
        platform_stats['requests_failed'] += 1
        return jsonify({'error':err}),400
    return jsonify(process_single_metric(data))

@app.route('/api/metrics/bulk', methods=['POST','OPTIONS'])
def receive_metrics_bulk():
    if request.method=='OPTIONS': return '',204
    platform_stats['requests_total'] += 1
    payload  = request.get_json(silent=True) or {}
    readings = payload if isinstance(payload,list) else payload.get('readings',[])
    if not readings:      return jsonify({'error':'Empty readings array'}),400
    if len(readings)>200: return jsonify({'error':'Max 200 per bulk call'}),400
    results=[]; errors=[]
    for raw in readings:
        data, err = sanitize_metric(raw)
        if err: errors.append({'device_id':raw.get('device_id','?'),'error':err}); continue
        try:
            r = process_single_metric(data)
            results.append({'device_id':data['device_id'],'health_score':r['health_score'],'ok':True})
        except Exception as e:
            errors.append({'device_id':data.get('device_id','?'),'error':str(e)})
    return jsonify({'ok':True,'processed':len(results),'errors':errors,'results':results})

# ── Collector endpoints ───────────────────────────────────────────────────────
@app.route('/api/collector/register', methods=['POST','OPTIONS'])
def register_collector():
    if request.method=='OPTIONS': return '',204
    data   = request.get_json(silent=True) or {}
    name   = str(data.get('name','')).strip()[:60]
    sector = str(data.get('sector','net')).strip()
    desc   = str(data.get('description','')).strip()[:200]
    if not name: return jsonify({'error':'name required'}),400
    if sector not in ('net','tc','mc','all'): sector='net'
    api_key = secrets.token_hex(32)
    cid     = f"col-{sector}-{uuid.uuid4().hex[:8]}"
    ts      = datetime.now(timezone.utc).isoformat()
    try:
        with _db_conn() as con:
            con.execute(
                "INSERT INTO collectors (id,name,api_key,sector,description,last_seen,reading_count,active,created_at) "
                "VALUES (?,?,?,?,?,?,0,1,?)",
                (cid,name,api_key,sector,desc,ts,ts))
    except Exception as e:
        return jsonify({'error':str(e)}),500
    return jsonify({'id':cid,'api_key':api_key,'name':name,'sector':sector,
                    'ingest_url':'/api/collector/ingest',
                    'header':f'X-Collector-Key: {api_key}',
                    'note':'Store this API key — it will not be shown again'})

@app.route('/api/collector/ingest', methods=['POST','OPTIONS'])
def collector_ingest():
    if request.method=='OPTIONS': return '',204
    api_key = request.headers.get('X-Collector-Key','').strip()
    if not api_key: return jsonify({'error':'Missing X-Collector-Key header'}),401
    try:
        with _db_conn() as con:
            row = con.execute(
                "SELECT id,name FROM collectors WHERE api_key=? AND active=1",
                (api_key,)).fetchone()
            if not row: return jsonify({'error':'Invalid or inactive key'}),401
            col_id,col_name = row['id'],row['name']
    except Exception as e:
        return jsonify({'error':f'Auth error: {e}'}),500
    payload  = request.get_json(silent=True) or {}
    readings = payload if isinstance(payload,list) else payload.get('readings',[])
    if not readings:      return jsonify({'error':'readings must be non-empty array'}),400
    if len(readings)>500: return jsonify({'error':'Max 500 per batch'}),400
    results=[]; errors=[]; processed=0
    for raw in readings:
        data, err = sanitize_metric(raw)
        if err: errors.append({'device_id':raw.get('device_id','?'),'error':err}); continue
        try:
            r = process_single_metric(data)
            results.append({'device_id':data['device_id'],'health_score':r['health_score'],'ok':True})
            processed+=1
        except Exception as e:
            errors.append({'device_id':data.get('device_id','?'),'error':str(e)})
    try:
        ts = datetime.now(timezone.utc).isoformat()
        with _db_conn() as con:
            con.execute("UPDATE collectors SET last_seen=?,reading_count=reading_count+? WHERE id=?",
                        (ts,processed,col_id))
    except Exception as e: print(f'[Collector] stats: {e}')
    platform_stats['collector_readings'] += processed
    return jsonify({'ok':True,'collector':col_name,'processed':processed,
                    'total_errors':len(errors),'errors':errors[:5]})

@app.route('/api/collectors')
@require_specialist
def list_collectors():
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT id,name,sector,description,last_seen,reading_count,active,created_at "
                "FROM collectors ORDER BY created_at DESC").fetchall()
        result=[]
        for r in rows:
            ls=r['last_seen']
            if ls:
                try:
                    age=(datetime.now(timezone.utc)-
                         datetime.fromisoformat(ls.replace('Z','+00:00'))).total_seconds()
                    status='active' if age<120 else 'idle' if age<600 else 'offline'
                except: status='unknown'
            else:
                status='never'
            result.append({**dict(r),'status':status})
        return jsonify(result)
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/collectors/<col_id>', methods=['DELETE'])
@require_specialist
def deactivate_collector(col_id):
    try:
        with _db_conn() as con:
            con.execute("UPDATE collectors SET active=0 WHERE id=?",(col_id,))
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),500

# ── Platform & intelligence ───────────────────────────────────────────────────
@app.route('/api/platform')
def platform_api():
    start = platform_stats['uptime_start'].replace('Z','+00:00')
    up    = (datetime.now(timezone.utc)-datetime.fromisoformat(start)).total_seconds()
    return jsonify({'queue_depth':len(metric_queue),'scoring_queue':len(scoring_queue),
        'cache_age_seconds':round(time.time()-_data_cache['ts'],1),
        'devices_tracked':len(device_history),'anomaly_count':anomaly_count,
        'retrain_needed':anomaly_count>=RETRAIN_THRESHOLD,
        'retrain_in_progress':_retrain_in_progress,
        'platform_uptime_h':round(up/3600,2),'platform_stats':platform_stats,
        'demo_mode':os.environ.get('DEMO_MODE','false').lower()=='true',
        'notifications':{'email_enabled':NOTIFY['email_enabled'],
            'sms_enabled':NOTIFY['sms_enabled'],'whatsapp_enabled':NOTIFY['whatsapp_enabled'],
            'recent':list(notification_log)[:5]}})

@app.route('/api/intelligence')
def get_intelligence():
    snap      = _history_snapshot()
    all_d     = get_cached_data()
    dtype_map = {r['device_id']:r.get('device_type','') for r in all_d}
    ttf_data  = {}
    for d,score in snap.items():
        v = get_ettf_minutes(d,score,dtype_map.get(d,''))
        if v is not None: ttf_data[d]=v
    return jsonify({
        'federated_index'      : get_federated_health_index(list(snap.values())),
        'device_scores'        : snap,
        'uptime'               : {d:get_uptime_pct(d) for d in device_uptime},
        'failure_probabilities': {d:get_failure_probability(d,snap[d]) for d in snap},
        'ttf_minutes'          : ttf_data,
        'retrain_needed'       : anomaly_count>=RETRAIN_THRESHOLD,
        'anomaly_count'        : anomaly_count,
        'total_devices'        : len(device_history)})

@app.route('/api/twin/<device_id>')
def digital_twin(device_id):
    h = _history_get(device_id)
    if not h: return jsonify({'error':'No history'}),404
    cur = h[-1]; scenarios=[]
    for mult in [1.1,1.2,1.5,2.0]:
        arr  = np.array([[min(100,50*mult),min(1000,100*mult),min(500,10*mult),
                          min(20,mult*.5),10,40,80]])
        sim  = float(np.clip(rf_model.predict(arr)[0],0,100))
        anom = bool(iso_model.predict(arr)[0]==-1)
        scenarios.append({'load_increase':f'+{int((mult-1)*100)}%',
            'predicted_score':round(sim,1),'anomaly_predicted':anom,
            'risk':'critical' if sim<30 else 'warning' if sim<60 else 'safe'})
    trend = {'direction':'insufficient data','slope_per_reading':0}
    if len(h)>=5:
        window=h[-10:]; n=len(window)
        xm=(n-1)/2; ym=sum(window)/n
        num=sum((i-xm)*(window[i]-ym) for i in range(n))
        den=sum((i-xm)**2 for i in range(n))
        slope=num/den if den>0 else 0
        rtc=round((cur-20)/abs(slope)) if slope<0 and cur>20 else None
        trend={'slope_per_reading':round(slope,2),
               'direction':'declining' if slope<0 else 'improving' if slope>0 else 'stable',
               'readings_to_critical':rtc}
    all_d=get_cached_data()
    dtype=next((r.get('device_type','') for r in all_d if r['device_id']==device_id),'')
    return jsonify({'device_id':device_id,'current_score':round(cur,1),
        'history':[round(x,1) for x in h],'scenarios':scenarios,'trend':trend,
        'failure_probability':get_failure_probability(device_id,cur),
        'ettf_minutes':get_ettf_minutes(device_id,cur,dtype)})

@app.route('/api/weather')
def get_weather():
    loc_key = request.args.get('loc','byo')
    loc     = LOCATIONS.get(loc_key, LOCATIONS['byo'])
    cached  = _weather_cache.get(loc_key)
    if cached and time.time()-cached['ts']<WEATHER_CACHE_TTL:
        return jsonify(cached['data'])
    try:
        url = (f"https://api.open-meteo.com/v1/forecast"
               f"?latitude={loc['lat']}&longitude={loc['lon']}"
               f"&current=temperature_2m,relative_humidity_2m,wind_speed_10m,"
               f"wind_gusts_10m,precipitation,weather_code,cloud_cover"
               f"&hourly=wind_speed_10m,precipitation_probability"
               f"&forecast_days=2&timezone=Africa/Harare")
        r    = req.get(url,timeout=10).json()
        cur  = r.get('current',{}); hrly=r.get('hourly',{})
        wind = cur.get('wind_speed_10m',0); gusts=cur.get('wind_gusts_10m',0)
        precip=cur.get('precipitation',0); temp=cur.get('temperature_2m',25)
        alerts=[]
        if wind>40:   alerts.append(f'High winds {wind:.0f}km/h — microwave at risk')
        if gusts>60:  alerts.append(f'Dangerous gusts {gusts:.0f}km/h — tower stability risk')
        if precip>10: alerts.append(f'Heavy precipitation {precip:.1f}mm — pump load increasing')
        if temp>38:   alerts.append(f'Extreme heat {temp:.0f}C — thermal stress elevated')
        pp24   = hrly.get('precipitation_probability',[])[:24]
        result = {'location':loc['name'],'temperature':temp,
            'humidity':cur.get('relative_humidity_2m',50),
            'wind_speed':wind,'wind_gusts':gusts,'precipitation':precip,
            'weather_code':cur.get('weather_code',0),'cloud_cover':cur.get('cloud_cover',0),
            'alerts':alerts,'equipment_impact':[],
            'max_precip_probability_24h':max(pp24) if pp24 else 0,
            'hourly_wind':hrly.get('wind_speed_10m',[])[:24],
            'hourly_precip_prob':pp24}
        _weather_cache[loc_key] = {'data':result,'ts':time.time()}
        return jsonify(result)
    except Exception as e:
        return jsonify({'error':str(e),'location':loc['name'],'temperature':25,
            'humidity':50,'wind_speed':0,'wind_gusts':0,'precipitation':0,
            'weather_code':0,'cloud_cover':0,'alerts':[],'equipment_impact':[],
            'max_precip_probability_24h':0,'hourly_wind':[],'hourly_precip_prob':[]}),200

@app.route('/api/login', methods=['POST','OPTIONS'])
def login():
    if request.method=='OPTIONS': return '',204
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
    if not _rate_ok(f'login:{ip}', max_calls=5, window=60):
        return jsonify({'success':False,'error':'Too many attempts — wait 60s'}),429
    data = request.get_json(silent=True) or {}
    name = str(data.get('name','')).strip()
    pwd  = str(data.get('password','')).strip()
    if not name or not pwd:
        return jsonify({'success':False,'error':'Missing credentials'}),400
    try:
        with _db_conn() as con:
            row = con.execute("SELECT * FROM specialists WHERE name=?", (name,)).fetchone()
            if not row or not check_password_hash(row['password_hash'] or '', pwd):
                return jsonify({'success':False,'error':'Invalid credentials'}),401
            token = row['token'] or secrets.token_hex(24)
            if not row['token']:
                con.execute("UPDATE specialists SET token=? WHERE id=?", (token, row['id']))
            _audit(name, 'LOGIN', name, ip=ip)
            return jsonify({'success':True,'token':token,
                            'name':row['name'],'role':row['role'] or 'engineer'})
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}),500

@app.route('/api/incidents')
@require_specialist
def get_incidents():
    status = request.args.get('status','open')
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY created_at DESC LIMIT 50",
                (status,)).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/incidents/<inc_id>/assign', methods=['POST'])
@require_specialist
def assign_incident(inc_id):
    data = request.get_json(silent=True) or {}
    try:
        with _db_conn() as con:
            con.execute("UPDATE incidents SET assigned_to=?,notes=?,status='assigned' WHERE id=?",
                        (data.get('assigned_to',''),data.get('notes',''),inc_id))
        _audit(getattr(request,'specialist_name','?'), 'ASSIGN_INCIDENT', inc_id, data.get('assigned_to',''))
        return jsonify({'success':True})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/incidents/<inc_id>/resolve', methods=['POST'])
@require_specialist
def resolve_incident(inc_id):
    data = request.get_json(silent=True) or {}
    try:
        with _db_conn() as con:
            con.execute("UPDATE incidents SET resolved_by=?,notes=?,status='resolved' WHERE id=?",
                        (data.get('resolved_by',''),data.get('notes',''),inc_id))
        _audit(getattr(request,'specialist_name','?'), 'RESOLVE_INCIDENT', inc_id)
        return jsonify({'success':True})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/shift-report')
@require_specialist
def shift_report():
    try:
        with _db_conn() as con:
            metrics_rows = con.execute(
                "SELECT * FROM (SELECT * FROM metrics ORDER BY created_at DESC) "
                "GROUP BY device_id LIMIT 500").fetchall()
            inc_rows = con.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT 100").fetchall()
        dm   = {r['device_id']:dict(r) for r in metrics_rows}
        crit = [d for d in dm.values() if d['health_score']<20]
        warn = [d for d in dm.values() if 20<=d['health_score']<50]
        ok   = [d for d in dm.values() if d['health_score']>=50]
        oi   = [dict(r) for r in inc_rows if r['status']=='open']
        scores=[d['health_score'] for d in dm.values()]
        return jsonify({'generated_at':datetime.now(timezone.utc).isoformat(),
            'total_devices':len(dm),
            'avg_health':round(sum(scores)/len(scores),1) if scores else 100,
            'critical_devices':len(crit),'warning_devices':len(warn),'healthy_devices':len(ok),
            'open_incidents':len(oi),
            'top_risks':[{'device':d['device_id'],'score':round(d['health_score'],1),
                          'diagnosis':d.get('ai_diagnosis','')}
                         for d in sorted(crit+warn,key=lambda x:x['health_score'])[:5]],
            'automation_commands':[{'device':d['device_id'],'command':d['automation_command']}
                                   for d in dm.values() if d.get('automation_command')]})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/notify/test', methods=['POST'])
@require_specialist
def test_notify():
    data = request.get_json(silent=True) or {}
    ch   = data.get('channel','all')
    msg  = 'IISentinel test notification — channels operational'
    if ch in ('sms','all'):      threading.Thread(target=send_sms,args=(msg,),daemon=True).start()
    if ch in ('whatsapp','all'): threading.Thread(target=send_whatsapp,args=(msg,),daemon=True).start()
    if ch in ('email','all'):    threading.Thread(target=send_email,
        kwargs=dict(subject='Test',body=msg,severity='info'),daemon=True).start()
    return jsonify({'ok':True,'channel':ch})

@app.route('/api/stream')
def sse_stream():
    sub_q = _queue.Queue(maxsize=100)
    with _sse_lock: _sse_subs.append(sub_q)
    def generate():
        yield 'event: connected\ndata: {"ok":true}\n\n'
        while True:
            try:
                msg = sub_q.get(timeout=25)
                yield msg
            except _queue.Empty:
                yield ':heartbeat\n\n'
    return Response(stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Connection':'keep-alive'})

@app.route('/api/export-pdf')
def export_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
    except ImportError:
        return jsonify({'error':'pip install reportlab'}),500
    buf = BytesIO()
    doc = SimpleDocTemplate(buf,pagesize=A4,
          rightMargin=18*mm,leftMargin=18*mm,topMargin=20*mm,bottomMargin=18*mm)
    DARK  = colors.HexColor('#0c1122'); ACCENT = colors.HexColor('#34c6f4')
    GREEN = colors.HexColor('#20e07a'); AMBER  = colors.HexColor('#f5a020')
    RED   = colors.HexColor('#ff3e50'); MUTED  = colors.HexColor('#8592a8')
    ROW   = colors.HexColor('#f0f4fa')
    styles = getSampleStyleSheet()
    def sty(n='Normal',**kw): return ParagraphStyle(n,parent=styles['Normal'],**kw)
    hdr = sty(fontName='Helvetica-Bold',fontSize=8,textColor=colors.white)
    cel = sty(fontName='Helvetica',fontSize=8,textColor=DARK)
    snap      = _history_snapshot(); scores=list(snap.values())
    fhi_v     = get_federated_health_index(scores)
    crit      = sum(1 for s in scores if s<20)
    warn      = sum(1 for s in scores if 20<=s<50)
    ok        = sum(1 for s in scores if s>=50)
    all_d     = get_cached_data()
    dtype_map = {r['device_id']:r.get('device_type','') for r in all_d}
    total_exp = sum(COST_RATES.get('sensor',8000)*(
        0.95 if s<20 else 0.6 if s<35 else 0.25 if s<50 else 0) for s in scores)
    now_s = datetime.now(timezone.utc).strftime('%d %B %Y  %H:%M UTC')
    story=[]
    story.append(Paragraph('IISentinel v3.3',
        sty(fontName='Helvetica-Bold',fontSize=22,textColor=DARK,spaceAfter=2)))
    story.append(Paragraph('Intelligent Infrastructure Sentinel — Shift Report',
        sty(fontName='Helvetica',fontSize=10,textColor=MUTED,spaceAfter=4)))
    story.append(Paragraph(f'Generated: {now_s}',
        sty(fontName='Helvetica',fontSize=9,textColor=MUTED,spaceAfter=8)))
    story.append(HRFlowable(width='100%',thickness=1.5,color=ACCENT,spaceAfter=10))
    kpi = [[Paragraph(c,hdr) for c in ['Metric','Value','Status']],
           [Paragraph(c,cel) for c in ['Federated Health Index',f'{fhi_v:.1f}/100',
                                       'HEALTHY' if fhi_v>=70 else 'WARNING' if fhi_v>=40 else 'CRITICAL']],
           [Paragraph(c,cel) for c in ['Total Devices',str(len(snap)),'']],
           [Paragraph(c,cel) for c in ['Critical (<20)',str(crit),'ALERT' if crit else 'NONE']],
           [Paragraph(c,cel) for c in ['Warning (20-50)',str(warn),'MONITOR' if warn else 'NONE']],
           [Paragraph(c,cel) for c in ['Healthy (>=50)',str(ok),'OK']],
           [Paragraph(c,cel) for c in ['Anomalies',str(anomaly_count),
                                       'HIGH' if anomaly_count>=RETRAIN_THRESHOLD else 'NORMAL']],
           [Paragraph(c,cel) for c in ['Hourly Risk Exposure',f'${total_exp:,.0f}/hr',
                                       'ELEVATED' if total_exp>50000 else 'MANAGED']]]
    kt = Table(kpi,colWidths=[75*mm,60*mm,40*mm])
    kt.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),DARK),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,ROW]),
        ('GRID',(0,0),(-1,-1),.35,colors.HexColor('#d4daea')),
        ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LEFTPADDING',(0,0),(-1,-1),7)]))
    story.append(kt); story.append(Spacer(1,8))
    if snap:
        story.append(Paragraph('Device Health Register + ETTF',
            sty(fontName='Helvetica-Bold',fontSize=9,textColor=ACCENT,spaceBefore=8,spaceAfter=4)))
        drows=[[Paragraph(c,hdr) for c in ['Device','Score','Risk','ETTF','Status']]]
        for did,s in sorted(snap.items(),key=lambda x:x[1])[:20]:
            p2   = get_failure_probability(did,s)
            stat = 'CRITICAL' if s<20 else 'WARNING' if s<50 else 'OK'
            col  = RED if s<20 else AMBER if s<50 else GREEN
            dtype= dtype_map.get(did,'')
            ttf  = get_ettf_minutes(did,s,dtype)
            ttf_str=(f'{ttf}min' if ttf is not None and ttf<60
                     else f'{ttf//60}h {ttf%60}m' if ttf is not None else 'Stable')
            drows.append([Paragraph(did[-36:],cel),
                Paragraph(f'{s:.0f}',sty(fontName='Helvetica-Bold',fontSize=8,textColor=col)),
                Paragraph(f'{p2:.0f}%',cel),Paragraph(ttf_str,cel),
                Paragraph(stat,sty(fontName='Helvetica-Bold',fontSize=8,textColor=col))])
        dt=Table(drows,colWidths=[68*mm,18*mm,22*mm,28*mm,22*mm])
        dt.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),DARK),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,ROW]),
            ('GRID',(0,0),(-1,-1),.35,colors.HexColor('#d4daea')),
            ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
            ('LEFTPADDING',(0,0),(-1,-1),5)]))
        story.append(dt)
    story.append(Spacer(1,14))
    story.append(HRFlowable(width='100%',thickness=0.7,color=MUTED,spaceAfter=5))
    story.append(Paragraph(f'IISentinel v3.3 Confidential — {now_s}',
        sty(fontName='Helvetica-Oblique',fontSize=7,textColor=MUTED)))
    doc.build(story); buf.seek(0)
    return send_file(buf,as_attachment=True,
        download_name=f'IISentinel_Report_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")}.pdf',
        mimetype='application/pdf')

# ── Node routes ───────────────────────────────────────────────────────────────
@app.route('/api/nodes')
def get_nodes():
    sector = request.args.get('sector',None)
    with _nodes_lock:
        result={}
        for nid,node in _nodes.items():
            if sector and node.get('sector')!=sector: continue
            result[nid]={
                'id':nid,'host':node['host'],'label':node['label'],
                'sector':node.get('sector','net'),'status':node.get('status','unknown'),
                'latency_ms':node.get('latency_ms'),'loss_pct':node.get('loss_pct',0),
                'health_score':node.get('health_score',0),
                'last_check':node.get('last_check'),
                'history':list(node.get('history',[]))}
    return jsonify(result)

@app.route('/api/nodes', methods=['POST'])
def add_node():
    data   = request.get_json(silent=True) or {}
    host   = str(data.get('host','')).strip()
    label  = str(data.get('label',host)).strip()[:60]
    sector = str(data.get('sector','net')).strip()
    if not host or len(host)>253: return jsonify({'error':'Invalid host'}),400
    if sector not in ('net','tc','mc'): sector='net'
    node_id = hashlib.md5(f"{sector}:{host}".encode()).hexdigest()[:12]
    with _nodes_lock:
        if node_id in _nodes:
            return jsonify({'error':'Node already registered','id':node_id}),409
        _nodes[node_id] = {'host':host,'label':label,'sector':sector,
            'status':'checking','latency_ms':None,'loss_pct':0,
            'last_check':None,'health_score':0,'history':deque(maxlen=20)}
    try:
        with _db_conn() as con:
            con.execute("INSERT OR REPLACE INTO nodes (id,host,label,sector,created_at) VALUES (?,?,?,?,?)",
                        (node_id,host,label,sector,datetime.now(timezone.utc).isoformat()))
    except Exception as e: print(f'[Nodes] persist: {e}')
    _node_executor.submit(_poll_node, node_id)
    return jsonify({'id':node_id,'host':host,'label':label,'sector':sector,'status':'checking'})

@app.route('/api/nodes/<node_id>', methods=['DELETE'])
def delete_node(node_id):
    with _nodes_lock:
        if node_id not in _nodes: return jsonify({'error':'Not found'}),404
        del _nodes[node_id]
    try:
        with _db_conn() as con:
            con.execute("DELETE FROM nodes WHERE id=?",(node_id,))
    except Exception as e: print(f'[Nodes] delete: {e}')
    return jsonify({'ok':True})

@app.route('/api/nodes/<node_id>/poll', methods=['POST'])
def poll_node_now(node_id):
    with _nodes_lock:
        if node_id not in _nodes: return jsonify({'error':'Not found'}),404
        _nodes[node_id]['status']='checking'
    _node_executor.submit(_poll_node, node_id)
    return jsonify({'ok':True,'status':'checking'})

# ── Cascade topology ──────────────────────────────────────────────────────────
_DEFAULT_TOPOLOGY = {
    "nodes":[
        {"id":"wan","label":"WAN Link","domain":"net","x":.15,"y":.20},
        {"id":"core-sw","label":"Core Switch","domain":"net","x":.28,"y":.32},
        {"id":"fw","label":"Firewall","domain":"net","x":.18,"y":.44},
        {"id":"noc","label":"NOC Router","domain":"net","x":.08,"y":.32},
        {"id":"tower","label":"BTS Tower","domain":"tc","x":.62,"y":.15},
        {"id":"mw-link","label":"MW Backhaul","domain":"tc","x":.52,"y":.28},
        {"id":"bs","label":"Base Station","domain":"tc","x":.72,"y":.32},
        {"id":"scada","label":"SCADA","domain":"mc","x":.22,"y":.58},
        {"id":"plc","label":"PLC Shaft 1","domain":"mc","x":.18,"y":.70},
        {"id":"pump","label":"Dewater Pump","domain":"mc","x":.10,"y":.82},
        {"id":"conv","label":"Conveyor","domain":"mc","x":.30,"y":.80},
        {"id":"pm","label":"Power Meter","domain":"mc","x":.35,"y":.62},
        {"id":"vent","label":"Ventilation","domain":"mc","x":.40,"y":.75},
        {"id":"cbs","label":"CBS Ctrl","domain":"cbs","x":.52,"y":.68},
        {"id":"plant","label":"Process Plant","domain":"plant","x":.55,"y":.85}
    ],
    "edges":[
        {"from":"wan","to":"core-sw"},{"from":"core-sw","to":"fw"},
        {"from":"core-sw","to":"noc"},{"from":"noc","to":"mw-link"},
        {"from":"tower","to":"mw-link"},{"from":"mw-link","to":"bs"},
        {"from":"fw","to":"scada"},{"from":"scada","to":"plc"},
        {"from":"scada","to":"cbs"},{"from":"plc","to":"pump"},
        {"from":"plc","to":"conv"},{"from":"pm","to":"plc"},
        {"from":"pm","to":"vent"},{"from":"conv","to":"plant"},
        {"from":"vent","to":"plant"}
    ]
}

@app.route('/api/cascade/topology')
def get_cascade_topology():
    try:
        with _db_conn() as con:
            row = con.execute("SELECT payload FROM cascade_topology WHERE id='default'").fetchone()
        if row: return jsonify(json.loads(row['payload']))
        return jsonify(_DEFAULT_TOPOLOGY)
    except Exception as e:
        print(f'[Cascade] GET: {e}'); return jsonify(_DEFAULT_TOPOLOGY)

@app.route('/api/cascade/topology', methods=['POST'])
@require_specialist
def save_cascade_topology():
    data  = request.get_json(silent=True) or {}
    nodes = data.get('nodes',[]); edges=data.get('edges',[])
    if not isinstance(nodes,list) or not isinstance(edges,list):
        return jsonify({'error':'nodes and edges must be arrays'}),400
    cn = [{'id':str(n.get('id',''))[:80],'label':str(n.get('label',''))[:60],
           'domain':n.get('domain','net') if n.get('domain') in
                    ('net','tc','mc','cbs','plant') else 'net',
           'x':max(0.0,min(1.0,float(n.get('x',.5)))),'y':max(0.0,min(1.0,float(n.get('y',.5))))}
          for n in nodes if isinstance(n,dict) and n.get('id')]
    ce = [{'from':str(e.get('from',''))[:80],'to':str(e.get('to',''))[:80]}
          for e in edges if isinstance(e,dict) and e.get('from') and e.get('to')]
    payload = json.dumps({'nodes':cn,'edges':ce})
    ts      = datetime.now(timezone.utc).isoformat()
    try:
        with _db_conn() as con:
            con.execute("""INSERT INTO cascade_topology (id,payload,updated_at) VALUES ('default',?,?)
               ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
               (payload,ts))
    except Exception as e: return jsonify({'error':str(e)}),500
    return jsonify({'ok':True,'nodes':len(cn),'edges':len(ce),'saved_at':ts})

@app.route('/api/cascade/topology', methods=['DELETE'])
@require_specialist
def reset_cascade_topology():
    try:
        with _db_conn() as con:
            con.execute("DELETE FROM cascade_topology WHERE id='default'")
        return jsonify({'ok':True,'message':'Topology reset to default'})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/token')
def get_admin_token():
    if os.environ.get('PRODUCTION','').lower()=='true':
        return jsonify({'error':'Disabled in production'}),403
    try:
        with _db_conn() as con:
            row = con.execute("SELECT token FROM specialists WHERE name='Admin'").fetchone()
            if row: return jsonify({'token':row['token'],'note':'Use as X-Specialist-Token header'})
        return jsonify({'error':'No admin found'}),404
    except Exception as e: return jsonify({'error':str(e)}),500

# ════════════════════════════════════════════════════════════════════
# ROUTES — CONTROL PANEL (admin)
# ════════════════════════════════════════════════════════════════════

@app.route('/api/admin/system')
@require_admin
def admin_system():
    try:
        db_size = os.path.getsize(_DB_PATH) if os.path.exists(_DB_PATH) else 0
        start   = platform_stats['uptime_start'].replace('Z','+00:00')
        up_s    = (datetime.now(timezone.utc)-datetime.fromisoformat(start)).total_seconds()
        with _db_conn() as con:
            metrics_count  = con.execute("SELECT COUNT(*) FROM metrics").fetchone()[0]
            incident_count = con.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
            node_count     = con.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            col_count      = con.execute("SELECT COUNT(*) FROM collectors WHERE active=1").fetchone()[0]
            audit_count    = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            maint_count    = con.execute(
                "SELECT COUNT(*) FROM maintenance_windows WHERE end_ts >= ?",
                (datetime.now(timezone.utc).isoformat(),)
            ).fetchone()[0]
        cpu_pct = mem_used = mem_tot = disk_pct = None
        try:
            import psutil
            cpu_pct  = _psutil_cache.get('cpu')
            mem_used = _psutil_cache.get('mem_used')
            mem_tot  = _psutil_cache.get('mem_tot')
            disk_pct = _psutil_cache.get('disk')
        except Exception:
            pass
        return jsonify({
            'uptime_s'           : round(up_s),
            'uptime_h'           : round(up_s/3600,2),
            'queue_depth'        : len(metric_queue),
            'scoring_queue'      : len(scoring_queue),
            'cache_age_s'        : round(time.time()-_data_cache['ts'],1),
            'devices_tracked'    : len(device_history),
            'db_size_kb'         : round(db_size/1024,1),
            'metrics_total'      : metrics_count,
            'open_incidents'     : incident_count,
            'node_count'         : node_count,
            'collector_count'    : col_count,
            'audit_entries'      : audit_count,
            'active_maintenance' : maint_count,
            'anomaly_count'      : anomaly_count,
            'retrain_needed'     : anomaly_count>=RETRAIN_THRESHOLD,
            'retrain_active'     : _retrain_in_progress,
            'sse_subscribers'    : len(_sse_subs),
            'cpu_pct'            : cpu_pct,
            'mem_used_mb'        : mem_used,
            'mem_total_mb'       : mem_tot,
            'disk_pct'           : disk_pct,
            'demo_mode'          : os.environ.get('DEMO_MODE','false').lower()=='true',
            'production'         : os.environ.get('PRODUCTION','false').lower()=='true',
            'platform_stats'     : platform_stats,
            'notifications'      : {
                'email'    : NOTIFY['email_enabled'],
                'sms'      : NOTIFY['sms_enabled'],
                'whatsapp' : NOTIFY['whatsapp_enabled'],
            }
        })
    except Exception as e: return jsonify({'error':str(e)}),500

# ── Thresholds ────────────────────────────────────────────────────
@app.route('/api/admin/thresholds', methods=['GET'])
@require_admin
def get_thresholds():
    try:
        with _db_conn() as con:
            rows = con.execute("SELECT * FROM thresholds").fetchall()
        stored = {r['device_type']: dict(r) for r in rows}
        all_types = NETWORK_TYPES + TELECOM_TYPES + MINING_TYPES + CBS_TYPES
        result = []
        for dt in all_types:
            if dt in stored:
                result.append(stored[dt])
            else:
                result.append({
                    'id': f'thr-{dt}', 'device_type': dt,
                    'critical_below': 20.0, 'warning_below': 50.0,
                    'cbs_hold_below': 90.0 if dt=='cbs_controller' else None,
                    'ettf_warn_minutes': 120, 'ettf_crit_minutes': 30,
                    'updated_by': None, 'updated_at': None
                })
        return jsonify(result)
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/thresholds', methods=['POST'])
@require_admin
def save_threshold():
    data  = request.get_json(silent=True) or {}
    dt    = str(data.get('device_type','')).strip()
    if not dt: return jsonify({'error':'device_type required'}),400
    actor = getattr(request,'specialist_name','unknown')
    ts    = datetime.now(timezone.utc).isoformat()
    try:
        with _db_conn() as con:
            con.execute("""
                INSERT INTO thresholds
                (id,device_type,critical_below,warning_below,cbs_hold_below,
                 ettf_warn_minutes,ettf_crit_minutes,updated_by,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(device_type) DO UPDATE SET
                    critical_below=excluded.critical_below,
                    warning_below=excluded.warning_below,
                    cbs_hold_below=excluded.cbs_hold_below,
                    ettf_warn_minutes=excluded.ettf_warn_minutes,
                    ettf_crit_minutes=excluded.ettf_crit_minutes,
                    updated_by=excluded.updated_by,
                    updated_at=excluded.updated_at
            """, (f'thr-{dt}', dt,
                  float(data.get('critical_below', 20)),
                  float(data.get('warning_below', 50)),
                  float(data.get('cbs_hold_below', 90)) if data.get('cbs_hold_below') else None,
                  int(data.get('ettf_warn_minutes', 120)),
                  int(data.get('ettf_crit_minutes', 30)),
                  actor, ts))
        global CBS_SAFETY_THRESHOLD
        if dt=='cbs_controller' and data.get('cbs_hold_below'):
            CBS_SAFETY_THRESHOLD = float(data['cbs_hold_below'])
        _audit(actor,'UPDATE_THRESHOLD',dt,
               f"crit={data.get('critical_below')} warn={data.get('warning_below')}")
        return jsonify({'ok':True,'device_type':dt})
    except Exception as e: return jsonify({'error':str(e)}),500

# ── Device registry ───────────────────────────────────────────────
@app.route('/api/admin/devices', methods=['GET'])
@require_admin
def admin_get_devices():
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT * FROM device_registry ORDER BY sector, label").fetchall()
        snap   = _history_snapshot()
        result = []
        for r in rows:
            d = dict(r)
            d['live_score'] = round(snap.get(r['id'], snap.get(r['label'], -1)), 1)
            result.append(d)
        return jsonify(result)
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/devices', methods=['POST'])
@require_admin
def admin_add_device():
    data   = request.get_json(silent=True) or {}
    label  = str(data.get('label','')).strip()[:80]
    dtype  = str(data.get('device_type','sensor')).strip()
    sector = str(data.get('sector','net')).strip()
    if not label: return jsonify({'error':'label required'}),400
    dev_id = f"{sector}-{dtype}-{uuid.uuid4().hex[:8]}"
    actor  = getattr(request,'specialist_name','unknown')
    ts     = datetime.now(timezone.utc).isoformat()
    try:
        with _db_conn() as con:
            con.execute("""
                INSERT INTO device_registry
                (id,label,device_type,protocol,ip,community,sector,
                 poll_interval,enabled,notes,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,1,?,?,?)
            """, (dev_id,label,dtype,
                  str(data.get('protocol','SNMP')),
                  str(data.get('ip','')),
                  str(data.get('community','public')),
                  sector,int(data.get('poll_interval',15)),
                  str(data.get('notes','')),ts,ts))
        _audit(actor,'ADD_DEVICE',dev_id,f"{dtype} @ {data.get('ip','N/A')}")
        return jsonify({'ok':True,'id':dev_id}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/devices/<dev_id>', methods=['PUT'])
@require_admin
def admin_update_device(dev_id):
    data  = request.get_json(silent=True) or {}
    actor = getattr(request,'specialist_name','unknown')
    ts    = datetime.now(timezone.utc).isoformat()
    try:
        with _db_conn() as con:
            con.execute("""
                UPDATE device_registry SET
                    label=?,device_type=?,protocol=?,ip=?,community=?,
                    sector=?,poll_interval=?,enabled=?,notes=?,updated_at=?
                WHERE id=?
            """, (str(data.get('label','')),str(data.get('device_type','sensor')),
                  str(data.get('protocol','SNMP')),str(data.get('ip','')),
                  str(data.get('community','public')),str(data.get('sector','net')),
                  int(data.get('poll_interval',15)),
                  1 if data.get('enabled',True) else 0,
                  str(data.get('notes','')),ts,dev_id))
        _audit(actor,'UPDATE_DEVICE',dev_id,f"enabled={data.get('enabled')}")
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/devices/<dev_id>', methods=['DELETE'])
@require_admin
def admin_delete_device(dev_id):
    actor = getattr(request,'specialist_name','unknown')
    try:
        with _db_conn() as con:
            con.execute("DELETE FROM device_registry WHERE id=?",(dev_id,))
        _audit(actor,'DELETE_DEVICE',dev_id)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),500

# ── Maintenance windows ───────────────────────────────────────────
@app.route('/api/admin/maintenance', methods=['GET'])
@require_admin
def get_maintenance():
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT * FROM maintenance_windows ORDER BY start_ts DESC LIMIT 50"
            ).fetchall()
        now = datetime.now(timezone.utc).isoformat()
        result = []
        for r in rows:
            d = dict(r)
            d['active'] = r['start_ts'] <= now <= r['end_ts']
            result.append(d)
        return jsonify(result)
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/maintenance', methods=['POST'])
@require_admin
def add_maintenance():
    data  = request.get_json(silent=True) or {}
    actor = getattr(request,'specialist_name','unknown')
    label = str(data.get('label','Maintenance')).strip()[:120]
    dids  = str(data.get('device_ids','')).strip()
    start = str(data.get('start_ts',datetime.now(timezone.utc).isoformat()))
    end   = str(data.get('end_ts',''))
    if not end: return jsonify({'error':'end_ts required'}),400
    mid = f"mw-{uuid.uuid4().hex[:10]}"
    ts  = datetime.now(timezone.utc).isoformat()
    try:
        with _db_conn() as con:
            con.execute(
                "INSERT INTO maintenance_windows "
                "(id,label,device_ids,start_ts,end_ts,suppress_alerts,created_by,created_at) "
                "VALUES (?,?,?,?,?,1,?,?)",
                (mid,label,dids,start,end,actor,ts))
        _refresh_maintenance()
        _audit(actor,'ADD_MAINTENANCE',mid,f"{label} until {end}")
        return jsonify({'ok':True,'id':mid}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/maintenance/<mid>', methods=['DELETE'])
@require_admin
def delete_maintenance(mid):
    actor = getattr(request,'specialist_name','unknown')
    try:
        with _db_conn() as con:
            con.execute("DELETE FROM maintenance_windows WHERE id=?",(mid,))
        _refresh_maintenance()
        _audit(actor,'DELETE_MAINTENANCE',mid)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),500

# ── User management ───────────────────────────────────────────────
@app.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_get_users():
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT id,name,role,token FROM specialists").fetchall()
        return jsonify([{'id':r['id'],'name':r['name'],
                         'role':r['role'] or 'engineer',
                         'has_token':bool(r['token'])} for r in rows])
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/users', methods=['POST'])
@require_admin
def admin_add_user():
    data  = request.get_json(silent=True) or {}
    name  = str(data.get('name','')).strip()[:60]
    role  = str(data.get('role','engineer')).strip()
    pwd   = str(data.get('password','')).strip()
    actor = getattr(request,'specialist_name','unknown')
    if not name or not pwd: return jsonify({'error':'name and password required'}),400
    if role not in ('engineer','admin','readonly'): role='engineer'
    uid = f"sp-{uuid.uuid4().hex[:8]}"
    tok = secrets.token_hex(24)
    ph  = generate_password_hash(pwd)
    try:
        with _db_conn() as con:
            con.execute("INSERT INTO specialists VALUES (?,?,?,?,?)",(uid,name,tok,ph,role))
        _audit(actor,'ADD_USER',name,f"role={role}")
        return jsonify({'ok':True,'id':uid,'name':name,'role':role}),201
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/users/<uid>/password', methods=['POST'])
@require_admin
def admin_reset_password(uid):
    data  = request.get_json(silent=True) or {}
    pwd   = str(data.get('password','')).strip()
    actor = getattr(request,'specialist_name','unknown')
    if not pwd or len(pwd)<6: return jsonify({'error':'Password must be >= 6 characters'}),400
    ph  = generate_password_hash(pwd)
    tok = secrets.token_hex(24)
    try:
        with _db_conn() as con:
            con.execute("UPDATE specialists SET password_hash=?,token=? WHERE id=?",(ph,tok,uid))
        _audit(actor,'RESET_PASSWORD',uid)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/users/<uid>', methods=['DELETE'])
@require_admin
def admin_delete_user(uid):
    actor = getattr(request,'specialist_name','unknown')
    try:
        with _db_conn() as con:
            row = con.execute("SELECT name FROM specialists WHERE id=?",(uid,)).fetchone()
            if row and row['name']=='Admin':
                return jsonify({'error':'Cannot delete default Admin'}),400
            con.execute("DELETE FROM specialists WHERE id=?",(uid,))
        _audit(actor,'DELETE_USER',uid)
        return jsonify({'ok':True})
    except Exception as e: return jsonify({'error':str(e)}),500

# ── Audit log ─────────────────────────────────────────────────────
@app.route('/api/admin/audit')
@require_admin
def get_audit_log():
    page     = int(request.args.get('page',1))
    limit    = min(int(request.args.get('limit',50)),200)
    actor_f  = request.args.get('actor','')
    action_f = request.args.get('action','')
    offset   = (page-1)*limit
    try:
        with _db_conn() as con:
            query = "SELECT * FROM audit_log"; params=[]; conds=[]
            if actor_f:  conds.append("actor LIKE ?");  params.append(f'%{actor_f}%')
            if action_f: conds.append("action LIKE ?"); params.append(f'%{action_f}%')
            if conds: query += ' WHERE '+' AND '.join(conds)
            count_q = query.replace('SELECT *','SELECT COUNT(*)')
            total   = con.execute(count_q,params).fetchone()[0]
            query  += ' ORDER BY id DESC LIMIT ? OFFSET ?'
            params += [limit,offset]
            rows    = con.execute(query,params).fetchall()
        return jsonify({'total':total,'page':page,'rows':[dict(r) for r in rows]})
    except Exception as e: return jsonify({'error':str(e)}),500

# ── Command dispatch ──────────────────────────────────────────────
@app.route('/api/admin/dispatch', methods=['POST'])
@require_admin
def admin_dispatch():
    data   = request.get_json(silent=True) or {}
    dtype  = str(data.get('dispatch_type','webhook')).strip()
    target = str(data.get('target','')).strip()
    payload= data.get('payload',{})
    actor  = getattr(request,'specialist_name','unknown')
    ts     = datetime.now(timezone.utc).isoformat()
    result = 'pending'
    if dtype=='webhook' and target.startswith('http'):
        try:
            r = req.post(target,json=payload,timeout=8)
            result = f"HTTP {r.status_code}"
        except Exception as e:
            result = f"ERROR: {e}"
    elif dtype=='email':
        threading.Thread(target=send_email,kwargs=dict(
            subject=payload.get('subject','IISentinel Command'),
            body=payload.get('body',''),severity='critical'),daemon=True).start()
        result='email_dispatched'
    elif dtype=='sms':
        threading.Thread(target=send_sms,args=(payload.get('message',''),),daemon=True).start()
        result='sms_dispatched'
    elif dtype=='whatsapp':
        threading.Thread(target=send_whatsapp,args=(payload.get('message',''),),daemon=True).start()
        result='whatsapp_dispatched'
    else:
        result=f'type {dtype} logged only'
    try:
        with _db_conn() as con:
            con.execute(
                "INSERT INTO dispatch_log (ts,device_id,command_type,payload,result,sent_by) "
                "VALUES (?,?,?,?,?,?)",
                (ts,target,dtype,json.dumps(payload),result,actor))
    except Exception: pass
    _audit(actor,'DISPATCH_COMMAND',target,f"type={dtype} result={result}")
    return jsonify({'ok':True,'result':result,'ts':ts})

@app.route('/api/admin/dispatch/log')
@require_admin
def get_dispatch_log():
    try:
        with _db_conn() as con:
            rows = con.execute(
                "SELECT * FROM dispatch_log ORDER BY id DESC LIMIT 100").fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e: return jsonify({'error':str(e)}),500

# ── Notification config ───────────────────────────────────────────
@app.route('/api/admin/notify/config', methods=['POST'])
@require_admin
def update_notify_config():
    data  = request.get_json(silent=True) or {}
    actor = getattr(request,'specialist_name','unknown')
    safe_keys = ['smtp_host','smtp_port','smtp_user','from_email',
                 'at_username','sms_gateway','wa_phone_id']
    changed = []
    for k in safe_keys:
        if k in data: NOTIFY[k]=data[k]; changed.append(k)
    if 'to_emails' in data and isinstance(data['to_emails'],list):
        NOTIFY['to_emails']=data['to_emails'][:10]; changed.append('to_emails')
    if 'sms_numbers' in data and isinstance(data['sms_numbers'],list):
        NOTIFY['sms_numbers']=data['sms_numbers'][:10]; changed.append('sms_numbers')
    if 'wa_numbers' in data and isinstance(data['wa_numbers'],list):
        NOTIFY['wa_numbers']=data['wa_numbers'][:10]; changed.append('wa_numbers')
    _audit(actor,'UPDATE_NOTIFY_CONFIG','notifications',f"changed={changed}")
    return jsonify({'ok':True,'changed':changed,
                    'note':'In-memory only — update .env for persistence'})

# ── DB maintenance ────────────────────────────────────────────────
@app.route('/api/admin/db/vacuum', methods=['POST'])
@require_admin
def db_vacuum():
    actor = getattr(request,'specialist_name','unknown')
    try:
        size_before = os.path.getsize(_DB_PATH) if os.path.exists(_DB_PATH) else 0
        with _db_conn() as con:
            con.execute("""
                DELETE FROM metrics WHERE id NOT IN (
                    SELECT id FROM metrics ORDER BY created_at DESC LIMIT 5000
                )
            """)
            cutoff = datetime.now(timezone.utc).isoformat()[:10]
            con.execute("""
                DELETE FROM incidents WHERE status='resolved'
                AND created_at < date(?,'-30 days')
            """, (cutoff,))
            con.execute("VACUUM")
        size_after = os.path.getsize(_DB_PATH) if os.path.exists(_DB_PATH) else 0
        freed_kb   = round((size_before-size_after)/1024,1)
        _audit(actor,'DB_VACUUM','database',f"freed={freed_kb}KB")
        return jsonify({'ok':True,'freed_kb':freed_kb,'size_kb':round(size_after/1024,1)})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/db/clear-incidents', methods=['POST'])
@require_admin
def db_clear_incidents():
    actor = getattr(request,'specialist_name','unknown')
    try:
        with _db_conn() as con:
            n = con.execute("SELECT COUNT(*) FROM incidents WHERE status='resolved'").fetchone()[0]
            con.execute("DELETE FROM incidents WHERE status='resolved'")
        _audit(actor,'CLEAR_INCIDENTS','incidents',f"deleted {n} resolved")
        return jsonify({'ok':True,'deleted':n})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/admin/cache/flush', methods=['POST'])
@require_admin
def flush_cache_route():
    actor = getattr(request,'specialist_name','unknown')
    _data_cache['ts']   = 0
    _data_cache['data'] = []
    _audit(actor,'FLUSH_CACHE','data_cache')
    return jsonify({'ok':True})

@app.route('/api/admin/retrain', methods=['POST'])
@require_admin
def trigger_retrain():
    global anomaly_count
    actor         = getattr(request,'specialist_name','unknown')
    anomaly_count = RETRAIN_THRESHOLD
    _audit(actor,'TRIGGER_RETRAIN','ml_model')
    return jsonify({'ok':True,'message':'Retrain scheduled for next cycle (~60s)'})

# ════════════════════════════════════════════════════════════════════
# BOOT
# ════════════════════════════════════════════════════════════════════
if __name__=='__main__':
    _refresh_maintenance()   # load any active windows from DB at startup
    demo = os.environ.get('DEMO_MODE','false').lower()=='true'
    try:
        with _db_conn() as con:
            row = con.execute("SELECT name,token FROM specialists WHERE name='Admin'").fetchone()
            if row:
                print(f"\n  Specialist login : Admin / admin123")
                print(f"  Specialist token : {row['token']}")
                print(f"  Retrieve token   : GET /api/admin/token\n")
    except: pass
    print("""
  IISentinel v3.3 — Intelligent Infrastructure Sentinel
  ────────────────────────────────────────────────────────
  Dashboard    : http://localhost:5000
  Control Panel: http://localhost:5000/admin
  Health check : http://localhost:5000/health
  PDF Report   : http://localhost:5000/api/export-pdf

  Collector ingest: POST /api/collector/ingest
                    Header: X-Collector-Key: <key>
    """)
    if demo: print('  [DEMO MODE] 15 devices, 4 sites — live injection active\n')
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)),
            debug=False, threaded=True)