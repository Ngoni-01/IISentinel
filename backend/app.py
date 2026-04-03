"""
IISentinel™ — Production Backend
YouTube-architecture: Queue ingestion → AI scoring → Cache → Dashboard

Setup:
  1. pip install -r requirements.txt
  2. Copy .env.example to .env and fill in your Supabase credentials
  3. python train_models.py          (generates the 3 .pkl files)
  4. python app.py
"""

import os, time, threading, uuid
from collections import deque
from datetime import datetime, timezone
from functools import wraps

import numpy as np
import joblib
import requests as req
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS

# ── ENV / CONFIG ──────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
USE_SUPABASE  = bool(SUPABASE_URL and SUPABASE_KEY)

if USE_SUPABASE:
    from supabase import create_client
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✓ Supabase connected")
else:
    supabase = None
    print("⚠  No Supabase credentials — running in standalone demo mode")

# ── LOAD AI MODELS ────────────────────────────────────────────────────────────
_model_dir = os.path.dirname(os.path.abspath(__file__))
try:
    rf_model  = joblib.load(os.path.join(_model_dir, 'health_model.pkl'))
    iso_model = joblib.load(os.path.join(_model_dir, 'anomaly_model.pkl'))
    scaler    = joblib.load(os.path.join(_model_dir, 'scaler.pkl'))
    USE_MODELS = True
    print("✓ AI models loaded (RandomForest + IsolationForest)")
except FileNotFoundError:
    USE_MODELS = False
    print("⚠  ML models not found — run python train_models.py first")
    print("   Using heuristic scoring in the meantime")

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel-2026')

# ═══════════════════════════════════════════════════════
#  YOUTUBE-STYLE ARCHITECTURE LAYERS
# ═══════════════════════════════════════════════════════

# ── LAYER 1: INGESTION QUEUE (YouTube Upload Service equivalent) ──────────────
# Never lose a reading. Readings queue here; background thread flushes to DB.
metric_queue = deque(maxlen=500)
queue_lock   = threading.Lock()

def flush_queue():
    """Background flusher — one Supabase batch every 3 seconds."""
    while True:
        time.sleep(3)
        if not USE_SUPABASE:
            with queue_lock:
                metric_queue.clear()
            continue
        with queue_lock:
            if not metric_queue:
                continue
            batch = list(metric_queue)
            metric_queue.clear()
        try:
            for item in batch:
                supabase.table('metrics').insert(item).execute()
            platform_stats['last_flush'] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            print(f"Queue flush error: {e}")
            with queue_lock:
                for item in batch[:50]:
                    metric_queue.appendleft(item)

threading.Thread(target=flush_queue, daemon=True).start()

# ── LAYER 2: IN-MEMORY CACHE (YouTube Redis equivalent) ──────────────────────
# /api/data is called every 10 seconds by every connected dashboard.
# Cache means 1 Supabase query per 8 seconds regardless of user count.
_data_cache = {'data': [], 'ts': 0}
CACHE_TTL   = 8  # seconds

def get_cached_data():
    now = time.time()
    if now - _data_cache['ts'] < CACHE_TTL and _data_cache['data']:
        platform_stats['cache_hits'] += 1
        return _data_cache['data'], True   # (data, was_cached)
    if USE_SUPABASE:
        try:
            resp = supabase.table('metrics').select('*') \
                           .order('created_at', desc=True).limit(300).execute()
            _data_cache['data'] = resp.data
            _data_cache['ts']   = now
            return resp.data, False
        except Exception as e:
            print(f"Cache refresh error: {e}")
    # Standalone: serve from in-memory device history
    rows = []
    for did, hist in device_history.items():
        if hist:
            rows.append(hist[-1])
    _data_cache['data'] = rows
    _data_cache['ts']   = now
    return rows, False

# ── LAYER 3: PLATFORM OBSERVABILITY ──────────────────────────────────────────
platform_stats = {
    'requests_total': 0,
    'requests_failed': 0,
    'cache_hits': 0,
    'queue_high_water': 0,
    'last_flush': None,
}

# ── IN-MEMORY STATE ───────────────────────────────────────────────────────────
device_history  = {}   # device_id → [last 20 health scores]
device_uptime   = {}   # device_id → {total, healthy}
device_readings = {}   # device_id → last full reading dict (for /api/data standalone)
reading_window  = []   # global rolling window for trend
anomaly_count   = 0
RETRAIN_THRESHOLD    = 50
CBS_SAFETY_THRESHOLD = 90.0

# ── DEMO DEVICE CATALOG (used in standalone mode) ─────────────────────────────
DEVICE_CATALOG = [
    # Network
    {"id":"net-byo-router-01",  "type":"router",        "site":"byo"},
    {"id":"net-byo-router-02",  "type":"router",        "site":"byo"},
    {"id":"net-hre-router-01",  "type":"router",        "site":"hre"},
    {"id":"net-mut-router-01",  "type":"router",        "site":"mut"},
    {"id":"net-byo-switch-01",  "type":"switch",        "site":"byo"},
    {"id":"net-byo-switch-02",  "type":"switch",        "site":"byo"},
    {"id":"net-hre-switch-01",  "type":"switch",        "site":"hre"},
    {"id":"net-byo-firewall-01","type":"firewall",      "site":"byo"},
    {"id":"net-hre-firewall-01","type":"firewall",      "site":"hre"},
    {"id":"net-byo-wan-01",     "type":"wan_link",      "site":"byo"},
    {"id":"net-hre-wan-01",     "type":"wan_link",      "site":"hre"},
    {"id":"net-mut-wan-01",     "type":"wan_link",      "site":"mut"},
    # TelecomCo
    {"id":"tc-byo-base-01",     "type":"base_station",  "site":"byo"},
    {"id":"tc-byo-base-02",     "type":"base_station",  "site":"byo"},
    {"id":"tc-hre-base-01",     "type":"base_station",  "site":"hre"},
    {"id":"tc-hre-base-02",     "type":"base_station",  "site":"hre"},
    {"id":"tc-mut-base-01",     "type":"base_station",  "site":"mut"},
    {"id":"tc-byo-tower-01",    "type":"network_tower", "site":"byo"},
    {"id":"tc-hre-tower-01",    "type":"network_tower", "site":"hre"},
    {"id":"tc-byo-mw-01",       "type":"microwave_link","site":"byo"},
    {"id":"tc-hre-mw-01",       "type":"microwave_link","site":"hre"},
    # MiningCo
    {"id":"mc-shaft1-pump-01",  "type":"pump",          "site":"shaft1"},
    {"id":"mc-shaft1-pump-02",  "type":"pump",          "site":"shaft1"},
    {"id":"mc-shaft2-pump-01",  "type":"pump",          "site":"shaft2"},
    {"id":"mc-shaft1-conv-01",  "type":"conveyor",      "site":"shaft1"},
    {"id":"mc-shaft2-conv-01",  "type":"conveyor",      "site":"shaft2"},
    {"id":"mc-plant-conv-01",   "type":"conveyor",      "site":"plant"},
    {"id":"mc-shaft1-vent-01",  "type":"ventilation",   "site":"shaft1"},
    {"id":"mc-shaft2-vent-01",  "type":"ventilation",   "site":"shaft2"},
    {"id":"mc-plant-plc-01",    "type":"plc",           "site":"plant"},
    {"id":"mc-surface-plc-01",  "type":"plc",           "site":"surface"},
    {"id":"mc-plant-scada-01",  "type":"scada_node",    "site":"plant"},
    {"id":"mc-surface-pm-01",   "type":"power_meter",   "site":"surface"},
    # CBS
    {"id":"cbs-dnp3-surface-01","type":"cbs_controller","site":"surface"},
]

import random, math

_device_base_scores = {}
def _base_score(did):
    if did not in _device_base_scores:
        _device_base_scores[did] = 62 + (sum(ord(c) for c in did) % 35)
    return _device_base_scores[did]

def _sim_features(dev_type, score):
    """Generate plausible feature vector from a score (for demo mode)."""
    cpu   = max(5,  min(100, (100-score)*0.85 + random.uniform(-5, 8)))
    bw    = random.uniform(50, 950)
    lat   = max(1,  (100-score)*2.8 + random.uniform(-3, 10))
    loss  = max(0,  (100-score)*0.14 + random.uniform(-0.5, 1))
    devs  = random.randint(1, 80)
    temp  = 25 + (100-score)*0.65 + random.uniform(-3, 5)
    sig   = score + random.uniform(-7, 7)
    return [cpu, bw, lat, loss, devs, temp, sig]

def _metric_name(dev_type):
    return {"router":"latency_ms","wan_link":"latency_ms","switch":"bandwidth_mbps",
            "firewall":"cpu_load","pump":"temperature","conveyor":"temperature",
            "ventilation":"temperature","plc":"temperature","scada_node":"cpu_load",
            "power_meter":"voltage","base_station":"signal_strength",
            "network_tower":"signal_strength","microwave_link":"signal_strength",
            "cbs_controller":"link_health"}.get(dev_type,"metric")

def _sim_reading(dev):
    """Build a full simulated reading for demo/standalone mode."""
    did, dtype = dev["id"], dev["type"]
    prev = _device_base_scores.get(did, _base_score(did))
    score = max(8, min(99, prev + random.uniform(-4, 4)))
    if dtype == "cbs_controller":
        score = max(86, score)
    _device_base_scores[did] = score

    feats = _sim_features(dtype, score)
    mn    = _metric_name(dtype)
    mv    = feats[2] if "latency" in mn else feats[1] if "bandwidth" in mn \
            else feats[0] if "cpu" in mn else feats[5] if "temp" in mn \
            else feats[6]
    anom  = score < 35 and random.random() < 0.35
    pred  = max(0, min(100, score + random.uniform(-8, 8)))
    diag  = _get_diagnosis(dtype, score, anom)
    auto  = _get_auto_cmd(did, dtype, score)

    r = {
        "device_id": did, "device_type": dtype,
        "metric_name": mn, "metric_value": round(mv, 1),
        "health_score": round(score, 1),
        "cpu_load": round(feats[0], 1), "bandwidth_mbps": round(feats[1], 1),
        "latency_ms": round(feats[2], 1), "packet_loss": round(feats[3], 2),
        "connected_devices": int(feats[4]), "temperature": round(feats[5], 1),
        "signal_strength": round(feats[6], 1),
        "anomaly_flag": anom, "predicted_score": round(pred, 1),
        "ai_diagnosis": diag, "automation_command": auto,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    device_readings[did] = r
    _update_history(did, score)
    _update_uptime(did, score)
    return r

DIAGNOSES = {
    "router":       ["BGP session stable — all peers established",
                     "High CPU load detected — check route table size",
                     "Packet loss >2% on WAN uplink — investigating"],
    "switch":       ["All VLANs operational — spanning tree converged",
                     "Port flap detected on gi0/4 — CRC errors rising",
                     "Bandwidth utilisation at 78% — monitor closely"],
    "firewall":     ["IPS signatures up to date — no threats detected",
                     "Connection table at 85% capacity — tune timeouts",
                     "DDoS mitigation active on WAN interface"],
    "wan_link":     ["Latency nominal — BGP prefix count stable",
                     "Jitter spike to 22ms — possible congestion upstream",
                     "Link quality degraded — SNR below threshold"],
    "base_station": ["4G/LTE signal nominal — 98.2% uptime this shift",
                     "Sector B antenna misalignment detected — RSSI -88dBm",
                     "Handover rate elevated — neighbouring cell overloaded"],
    "network_tower":["Tower lights operational — obstacle clearance OK",
                     "Microwave alignment drift — azimuth ±0.3°",
                     "Feeder cable loss within spec — no action required"],
    "microwave_link":["Link budget nominal — RSL -48dBm, SNR 28dB",
                      "Rain fade detected — adaptive coding engaged",
                      "Tx power reduced by AGC — interference on channel"],
    "pump":         ["Pump bearing vibration nominal — OEE 91%",
                     "Cavitation detected — suction pressure low",
                     "Motor temperature trending high — check cooling"],
    "conveyor":     ["Belt tension and alignment within spec",
                     "Idler roller failure detected — shutdown recommended",
                     "Belt slip >3% — check drive pulley lagging"],
    "ventilation":  ["Airflow nominal — methane levels clear",
                     "Fan motor current spike — check impeller balance",
                     "Duct pressure drop elevated — inspect for blockage"],
    "plc":          ["All I/O modules responding — cycle time 8ms",
                     "Watchdog timeout warning — check comms cable",
                     "Profinet cycle violation — network congestion"],
    "scada_node":   ["OPC-UA server responding — 847 tags active",
                     "Historian write queue backing up — check disk space",
                     "Modbus poll timeout on RTU-04 — check wiring"],
    "power_meter":  ["Grid supply stable — THD 2.1%, PF 0.97",
                     "Voltage sag detected — possible load switching",
                     "Harmonic distortion elevated — check VFD filters"],
    "cbs_controller":["DNP3 link healthy — all detonator circuits clear",
                      "DNP3 link degraded — BLAST HOLD active",
                      "Comms restored — blast clearance pending engineer sign-off"],
}

def _get_diagnosis(dtype, score, anom=False):
    opts = DIAGNOSES.get(dtype, ["System operating within parameters"])
    idx  = 0 if score >= 70 else 1 if score >= 40 else 2
    base = opts[min(idx, len(opts)-1)]
    if anom:
        base += " · Isolation Forest anomaly detected"
    return base

def _get_auto_cmd(did, dtype, score, blast_hold=False, override=None):
    if override:
        return override
    if dtype == "cbs_controller" and score < CBS_SAFETY_THRESHOLD:
        return f"CBS SAFETY INTERLOCK: BLAST HOLD on {did} — DNP3 link {score:.1f}% below threshold"
    if dtype in ("ventilation","pump") and score < 20:
        return f"EMERGENCY: Safety shutdown {did} — underground evacuation alert triggered"
    if score < 20:  return f"CRITICAL: Emergency restart for {did}"
    if score < 35:  return f"WARNING: Isolate {did} and reduce load — maintenance team alerted"
    if score < 50:  return f"CAUTION: Schedule maintenance for {did} within 24 hours"
    return None

# ═══════════════════════════════════════════════════════
#  INTELLIGENCE HELPERS
# ═══════════════════════════════════════════════════════

def _update_history(did, score):
    if did not in device_history:
        device_history[did] = []
    device_history[did].append(score)
    if len(device_history[did]) > 20:
        device_history[did].pop(0)

def _update_uptime(did, score):
    if did not in device_uptime:
        device_uptime[did] = {'total': 0, 'healthy': 0}
    device_uptime[did]['total']   += 1
    if score >= 50:
        device_uptime[did]['healthy'] += 1

def _uptime_pct(did):
    d = device_uptime.get(did, {'total':0,'healthy':0})
    return round((d['healthy']/d['total'])*100, 1) if d['total'] else 100.0

def _failure_prob(did, score):
    hist = device_history.get(did, [])
    if len(hist) < 3:
        return max(0.0, round((100-score)*0.05, 1))
    trend = hist[-1] - hist[0]
    if trend >= 0:
        return max(0.0, round((100-score)*0.05, 1))
    decline = abs(trend) / len(hist)
    return min(99.0, round(decline*3 + (100-score)*0.3, 1))

def _federated_index(scores):
    if not scores: return 100.0
    w = [s*0.5 if s<20 else s*0.8 if s<50 else s for s in scores]
    return round(sum(w)/len(w), 1)

def _lifecycle(did, dtype, score):
    base = {"pump":8760,"conveyor":17520,"ventilation":26280,"plc":52560,
            "router":43800,"switch":43800,"base_station":35040,
            "network_tower":43800}.get(dtype, 26280)
    hist = device_history.get(did, [])
    if len(hist) < 5: return None
    trend = hist[-1] - hist[0]
    dpd   = abs(trend)/len(hist) if trend < 0 else 0
    if dpd > 0:
        return round(min(base, score/dpd*(10/3600)))
    return base

def _score_from_features(features):
    """Score via AI model or heuristic fallback."""
    arr = np.array([features])
    if USE_MODELS:
        score = float(rf_model.predict(arr)[0])
        anom  = bool(iso_model.predict(arr)[0] == -1)
    else:
        # Heuristic: weighted inverse of stress metrics
        cpu, bw, lat, loss, devs, temp, sig = features
        score = 100 - (cpu*0.3 + min(lat,500)/5*0.25 + loss*10*0.2
                       + max(0,temp-40)*0.5*0.15 + max(0,80-sig)*0.1)
        score = max(5, min(99, score + random.uniform(-2,2)))
        anom  = score < 35 and random.random() < 0.3
    return round(score, 1), anom

# ═══════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════

# Local fallback credentials (used when Supabase is not configured)
LOCAL_USERS = {
    "admin":    {"password":"sentinel2025","role":"administrator","name":"Admin"},
    "engineer": {"password":"iisengineer", "role":"engineer",     "name":"Site Engineer"},
    "ops":      {"password":"opsops",      "role":"ops_manager",  "name":"Ops Manager"},
}
_tokens = {}   # token → username

def require_specialist(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Specialist-Token','')
        if USE_SUPABASE:
            try:
                res = supabase.table('specialists').select('*') \
                              .eq('password', token).execute()
                if not res.data:
                    return jsonify({'error':'Unauthorised'}), 401
            except:
                return jsonify({'error':'Auth error'}), 401
        else:
            if token not in _tokens:
                return jsonify({'error':'Unauthorised'}), 401
        return f(*args, **kwargs)
    return decorated

# Local incident store (standalone mode)
_incidents = {}

def _seed_incidents():
    """Pre-populate a few realistic incidents so dashboard isn't empty."""
    import random
    for dev in random.sample(DEVICE_CATALOG, 3):
        s  = random.uniform(15, 48)
        iid = str(uuid.uuid4())[:8]
        _incidents[iid] = {
            "id": iid, "device_id": dev["id"], "device_type": dev["type"],
            "health_score": round(s,1),
            "ai_diagnosis": _get_diagnosis(dev["type"], s),
            "automation_command": _get_auto_cmd(dev["id"], dev["type"], s),
            "status": random.choice(["open","assigned"]),
            "assigned_to": "T.Moyo" if random.random()>0.5 else None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _device_base_scores[dev["id"]] = s

_seed_incidents()

# ═══════════════════════════════════════════════════════
#  STATIC & DASHBOARD
# ═══════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_file('dashboard.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# ═══════════════════════════════════════════════════════
#  API — /api/data  (YouTube CDN equivalent — serve from cache)
# ═══════════════════════════════════════════════════════

@app.route('/api/data', methods=['GET'])
def api_data():
    platform_stats['requests_total'] += 1
    if USE_SUPABASE:
        data, cached = get_cached_data()
        return jsonify(data)
    # Standalone: refresh all device simulations
    readings = [_sim_reading(d) for d in DEVICE_CATALOG]
    # Append any injected events
    for r in list(_incidents.values()):
        if r.get('health_score') and r['device_id'] not in device_readings:
            readings.append(r)
    return jsonify(readings)

# ═══════════════════════════════════════════════════════
#  API — /api/metrics  (YouTube Upload Service equivalent)
# ═══════════════════════════════════════════════════════

@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    global anomaly_count
    platform_stats['requests_total'] += 1
    data = request.get_json()

    did    = data.get('device_id', 'unknown')
    dtype  = data.get('device_type', 'unknown')
    proto  = data.get('protocol', 'Ethernet')
    blast  = data.get('blast_hold', False)
    override = data.get('automation_override')

    features = [
        data.get('cpu_load', 50),
        data.get('bandwidth_mbps', 100),
        data.get('latency_ms', 10),
        data.get('packet_loss', 0),
        data.get('connected_devices', 10),
        data.get('temperature', 40),
        data.get('signal_strength', 80),
    ]

    score, anom = _score_from_features(features)
    if dtype == 'cbs_controller':
        score = min(score, float(data.get('signal_strength', 100)))
    if blast:
        score = min(score, float(data.get('metric_value', score)))

    if anom: anomaly_count += 1
    _update_history(did, score)
    _update_uptime(did, score)

    # Trend prediction
    reading_window.append(score)
    if len(reading_window) > 10: reading_window.pop(0)
    trend  = reading_window[-1]-reading_window[0] if len(reading_window)>=3 else 0
    pred   = round(max(0, min(100, score+trend)), 1)

    diag  = _get_diagnosis(dtype, score, anom) if (anom or score<50 or dtype=='cbs_controller') else None
    auto  = _get_auto_cmd(did, dtype, score, blast, override)
    fprob = _failure_prob(did, score)

    recent = {d: h[-1] for d,h in device_history.items() if h}
    fed    = _federated_index(list(recent.values()))
    lc     = _lifecycle(did, dtype, score)

    metric_record = {
        'device_id':        did,   'device_type':    dtype,
        'metric_name':      data.get('metric_name','unknown'),
        'metric_value':     float(data.get('metric_value',0)),
        'health_score':     score, 'anomaly_flag':   anom,
        'predicted_score':  pred,  'ai_diagnosis':   diag,
        'automation_command': auto,
    }

    # Queue it (non-blocking — YouTube-style)
    with queue_lock:
        metric_queue.append(metric_record)
        platform_stats['queue_high_water'] = max(
            platform_stats['queue_high_water'], len(metric_queue))

    # Store in local incidents if critical
    if score < 50 or anom or blast:
        iid = str(uuid.uuid4())[:8]
        inc = {**metric_record, "id":iid, "status":"open",
               "assigned_to":None, "created_at":datetime.now(timezone.utc).isoformat()}
        if USE_SUPABASE:
            try:
                supabase.table('incidents').insert(inc).execute()
            except Exception as e:
                print(f"Incident insert error: {e}")
                _incidents[iid] = inc
        else:
            _incidents[iid] = inc

    device_readings[did] = metric_record

    return jsonify({
        'status':             'ok',
        'health_score':       score,
        'anomaly_flag':       anom,
        'predicted_score':    pred,
        'failure_probability':fprob,
        'ai_diagnosis':       diag,
        'automation_command': auto,
        'federated_index':    fed,
        'uptime_pct':         _uptime_pct(did),
        'lifecycle_hours':    lc,
        'retrain_needed':     anomaly_count >= RETRAIN_THRESHOLD,
        'blast_hold':         blast,
    })

# ═══════════════════════════════════════════════════════
#  API — /api/intelligence  (YouTube Recommendation Engine equivalent)
# ═══════════════════════════════════════════════════════

@app.route('/api/intelligence', methods=['GET'])
def api_intelligence():
    recent = {d: h[-1] for d, h in device_history.items() if h}

    # If no real data yet, use catalog baselines
    if not recent:
        for dev in DEVICE_CATALOG:
            recent[dev["id"]] = _base_score(dev["id"])

    probs = {d: _failure_prob(d, s) for d, s in recent.items()}
    ups   = {d: _uptime_pct(d)      for d in device_uptime}

    lifecycles = {}
    if USE_SUPABASE:
        try:
            resp = supabase.table('metrics').select('device_id,device_type') \
                           .order('created_at', desc=True).limit(50).execute()
            for row in resp.data:
                d = row['device_id']
                if d in recent and d not in lifecycles:
                    lc = _lifecycle(d, row['device_type'], recent[d])
                    if lc: lifecycles[d] = lc
        except: pass
    else:
        for dev in DEVICE_CATALOG:
            lc = _lifecycle(dev["id"], dev["type"],
                           recent.get(dev["id"], 70))
            if lc: lifecycles[dev["id"]] = lc

    return jsonify({
        'federated_index':       _federated_index(list(recent.values())),
        'total_devices':         len(recent),
        'anomaly_count':         anomaly_count,
        'retrain_needed':        anomaly_count >= RETRAIN_THRESHOLD,
        'failure_probabilities': probs,
        'uptime':                ups,
        'lifecycles':            lifecycles,
    })

# ═══════════════════════════════════════════════════════
#  API — /api/platform  (YouTube Observability equivalent)
# ═══════════════════════════════════════════════════════

@app.route('/api/platform', methods=['GET'])
def api_platform():
    return jsonify({
        'queue_depth':      len(metric_queue),
        'cache_age_seconds': round(time.time() - _data_cache['ts'], 1),
        'devices_tracked':  len(device_history),
        'anomaly_count':    anomaly_count,
        'retrain_needed':   anomaly_count >= RETRAIN_THRESHOLD,
        'platform_stats':   platform_stats,
        'mode':             'supabase' if USE_SUPABASE else 'standalone',
        'models_loaded':    USE_MODELS,
        'architecture': {
            'ingestion': 'Queue-buffered (YouTube-style deque)',
            'cache':     f'{CACHE_TTL}s TTL in-memory',
            'ai_models': (['RandomForest','IsolationForest'] if USE_MODELS
                         else ['heuristic-fallback']),
            'protocols': ['SNMP','Profinet','Modbus TCP','DNP3','OPC-UA'],
        }
    })

# ═══════════════════════════════════════════════════════
#  API — /api/twin  (Digital twin — YouTube Adaptive Algorithm equivalent)
# ═══════════════════════════════════════════════════════

@app.route('/api/twin/<path:device_id>', methods=['GET'])
def api_twin(device_id):
    hist = device_history.get(device_id, [])
    if not hist:
        return jsonify({'error': 'No history for device'}), 404

    current = hist[-1]
    scenarios = []
    for mult in [1.1, 1.2, 1.5, 2.0]:
        feats = [min(100,50*mult), min(1000,100*mult), min(500,10*mult),
                 min(20,mult*.5), 10, 40, 80]
        sim_score, sim_anom = _score_from_features(feats)
        risk = 'critical' if sim_score<30 else 'warning' if sim_score<60 else 'safe'
        scenarios.append({
            'load_increase':   f'+{int((mult-1)*100)}%',
            'predicted_score': round(sim_score, 1),
            'anomaly_predicted': sim_anom,
            'risk': risk,
        })

    trend_info = {'slope_per_reading':0,'direction':'insufficient data','readings_to_critical':None}
    if len(hist) >= 5:
        slope = (hist[-1]-hist[-5])/4
        rtc   = round((current-20)/abs(slope)) if slope<0 and current>20 else None
        trend_info = {
            'slope_per_reading': round(slope, 2),
            'direction': 'declining' if slope<0 else 'improving' if slope>0 else 'stable',
            'readings_to_critical': rtc,
        }

    return jsonify({
        'device_id':          device_id,
        'current_score':      round(current, 1),
        'scenarios':          scenarios,
        'trend':              trend_info,
        'failure_probability':_failure_prob(device_id, current),
    })

# ═══════════════════════════════════════════════════════
#  API — /api/weather  (Open-Meteo, no key required)
# ═══════════════════════════════════════════════════════

LOCATIONS = {
    'byo':  {'lat':-20.15,'lon':28.58,'name':'Bulawayo'},
    'hre':  {'lat':-17.82,'lon':31.05,'name':'Harare'},
    'mut':  {'lat':-18.97,'lon':32.67,'name':'Mutare'},
    'mine': {'lat':-17.65,'lon':29.85,'name':'Mine Site'},
}

@app.route('/api/weather', methods=['GET'])
def api_weather():
    loc = LOCATIONS.get(request.args.get('loc','byo'), LOCATIONS['byo'])
    try:
        url = (f"https://api.open-meteo.com/v1/forecast"
               f"?latitude={loc['lat']}&longitude={loc['lon']}"
               f"&current=temperature_2m,relative_humidity_2m,precipitation,"
               f"weather_code,wind_speed_10m,wind_gusts_10m,cloud_cover"
               f"&hourly=wind_speed_10m,precipitation_probability"
               f"&forecast_days=2&timezone=Africa/Harare")
        r    = req.get(url, timeout=8)
        d    = r.json()
        cur  = d.get('current', {})
        hr   = d.get('hourly', {})

        wind  = cur.get('wind_speed_10m', 0)
        gusts = cur.get('wind_gusts_10m', 0)
        temp  = cur.get('temperature_2m', 27)
        hum   = cur.get('relative_humidity_2m', 55)
        prec  = cur.get('precipitation', 0)
        wcode = cur.get('weather_code', 0)
        cloud = cur.get('cloud_cover', 20)
        hw    = hr.get('wind_speed_10m', [wind]*24)[:24]
        hp    = hr.get('precipitation_probability', [0]*24)[:24]

        alerts, impact = [], []
        if wind  > 40:
            alerts.append(f"High winds {wind:.0f}km/h — microwave link degradation likely")
            impact.append({'impact':f'Microwave links: RSL drop expected — reduce modulation order'})
        if gusts > 60:
            alerts.append(f"Dangerous gusts {gusts:.0f}km/h — tower stability risk")
            impact.append({'impact':'CBS blast hold recommended — link stability compromised'})
        if max(hp,default=0) > 60:
            alerts.append(f"Heavy rain risk {max(hp):.0f}% — underground water ingress alert")
            impact.append({'impact':'Shaft pumps: load increase expected — stage backup pump'})
        if temp  > 38:
            alerts.append(f"Extreme heat {temp:.0f}°C — equipment thermal stress elevated")
            impact.append({'impact':'Mining equipment: increase cooling checks every 30 min'})
        if wcode >= 95:
            alerts.append("Thunderstorm — lightning risk to exposed equipment")
            impact.append({'impact':'Surge protection alert — consider temporary shutdown'})

        return jsonify({
            'location':loc['name'],'temperature':temp,'humidity':hum,
            'precipitation':prec,'weather_code':wcode,'wind_speed':wind,
            'wind_gusts':gusts,'cloud_cover':cloud,
            'max_precip_probability_24h': max(hp, default=0),
            'hourly_wind':hw,'hourly_precip_prob':hp,
            'alerts':alerts,'equipment_impact':impact,
        })
    except Exception as e:
        # Graceful fallback
        t  = round(random.uniform(22,36),1)
        w  = round(random.uniform(8,40),1)
        return jsonify({
            'location':loc['name'],'temperature':t,'humidity':random.randint(40,75),
            'precipitation':round(random.uniform(0,4),1),
            'weather_code':random.choice([0,1,2,3]),
            'wind_speed':w,'wind_gusts':round(w*1.4,1),'cloud_cover':random.randint(10,70),
            'max_precip_probability_24h':random.randint(10,60),
            'hourly_wind':[round(w+random.uniform(-4,4),1) for _ in range(24)],
            'hourly_precip_prob':[random.randint(5,55) for _ in range(24)],
            'alerts':[],'equipment_impact':[],
        })

# ═══════════════════════════════════════════════════════
#  API — /api/login
# ═══════════════════════════════════════════════════════

@app.route('/api/login', methods=['POST'])
def api_login():
    d    = request.get_json()
    name = d.get('name','').strip().lower()
    pwd  = d.get('password','').strip()

    if USE_SUPABASE:
        try:
            res = supabase.table('specialists').select('*') \
                          .eq('name', d.get('name','')) \
                          .eq('password', pwd).execute()
            if res.data:
                s = res.data[0]
                _tokens[pwd] = name
                return jsonify({'success':True,'token':pwd,
                                'name':s['name'],'role':s['role']})
        except Exception as e:
            print(f"Login error: {e}")
    # Local fallback
    user = LOCAL_USERS.get(name)
    if user and user['password'] == pwd:
        token = str(uuid.uuid4())
        _tokens[token] = name
        return jsonify({'success':True,'token':token,
                        'name':user['name'],'role':user['role']})
    return jsonify({'success':False}), 401

# ═══════════════════════════════════════════════════════
#  API — /api/incidents
# ═══════════════════════════════════════════════════════

@app.route('/api/incidents', methods=['GET'])
@require_specialist
def api_incidents():
    status = request.args.get('status','open')
    if USE_SUPABASE:
        try:
            res = supabase.table('incidents').select('*') \
                          .eq('status', status) \
                          .order('created_at', desc=True).limit(50).execute()
            return jsonify(res.data)
        except Exception as e:
            print(f"Incidents fetch error: {e}")
    result = [v for v in _incidents.values() if v.get('status')==status]
    result.sort(key=lambda x: x.get('created_at',''), reverse=True)
    return jsonify(result)

@app.route('/api/incidents/<inc_id>/assign', methods=['POST'])
@require_specialist
def api_assign(inc_id):
    d = request.get_json()
    if USE_SUPABASE:
        try:
            supabase.table('incidents').update({
                'assigned_to': d.get('assigned_to',''),
                'notes':       d.get('notes',''),
                'status':      'assigned',
            }).eq('id', inc_id).execute()
            return jsonify({'ok':True})
        except: pass
    if inc_id in _incidents:
        _incidents[inc_id].update({'status':'assigned','assigned_to':d.get('assigned_to')})
    return jsonify({'ok':True})

@app.route('/api/incidents/<inc_id>/resolve', methods=['POST'])
@require_specialist
def api_resolve(inc_id):
    d = request.get_json()
    if USE_SUPABASE:
        try:
            supabase.table('incidents').update({
                'resolved_by': d.get('resolved_by',''),
                'notes':       d.get('notes',''),
                'status':      'resolved',
            }).eq('id', inc_id).execute()
            return jsonify({'ok':True})
        except: pass
    if inc_id in _incidents:
        _incidents[inc_id].update({'status':'resolved','resolved_by':d.get('resolved_by')})
    return jsonify({'ok':True})

# ═══════════════════════════════════════════════════════
#  API — /api/shift-report
# ═══════════════════════════════════════════════════════

@app.route('/api/shift-report', methods=['GET'])
@require_specialist
def api_shift_report():
    if USE_SUPABASE:
        try:
            resp  = supabase.table('metrics').select('*') \
                            .order('created_at', desc=True).limit(500).execute()
            dm    = {}
            for row in resp.data:
                if row['device_id'] not in dm: dm[row['device_id']] = row
            scores = [r['health_score'] for r in dm.values()]
        except Exception as e:
            return jsonify({'error':str(e)}), 500
    else:
        dm     = {did: {'device_id':did,'health_score':h[-1],
                        'ai_diagnosis':_get_diagnosis('unknown',h[-1]),
                        'automation_command':_get_auto_cmd(did,'unknown',h[-1])}
                  for did, h in device_history.items() if h}
        scores = [h[-1] for h in device_history.values() if h]

    if not scores: scores = [100]
    incs  = list(_incidents.values()) if not USE_SUPABASE else []
    crit  = [d for d in dm.values() if d['health_score'] < 20]
    warn  = [d for d in dm.values() if 20 <= d['health_score'] < 50]
    good  = [d for d in dm.values() if d['health_score'] >= 50]
    top5  = sorted(dm.values(), key=lambda x: x['health_score'])[:5]

    return jsonify({
        'generated_at':     datetime.now(timezone.utc).isoformat(),
        'total_devices':    len(dm),
        'avg_health':       round(sum(scores)/len(scores), 1),
        'critical_devices': len(crit),
        'warning_devices':  len(warn),
        'healthy_devices':  len(good),
        'open_incidents':   len([i for i in incs if i.get('status')=='open']),
        'top_risks': [{'device':d['device_id'],'score':round(d['health_score'],1),
                       'diagnosis':d.get('ai_diagnosis','')} for d in top5],
    })

# ═══════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"""
  ╔══════════════════════════════════════════╗
  ║   IISentinel™ — Intelligent Infrastructure  ║
  ║   http://localhost:{port}                    ║
  ║   Mode: {'Supabase' if USE_SUPABASE else 'Standalone demo'}                       ║
  ║   Models: {'Loaded ✓' if USE_MODELS else 'run train_models.py first'}                  ║
  ╚══════════════════════════════════════════╝
  Logins: admin/sentinel2025  engineer/iisengineer  ops/opsops
""")
    app.run(host='0.0.0.0', port=port, debug=False)
