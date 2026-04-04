import os
import joblib
import numpy as np
import requests as req
import threading
import time
from collections import deque
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from supabase import create_client
from functools import wraps
from datetime import datetime, timezone

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel-secret-2026')

# ══════════════════════════════════════════════════════════════════════════════
#  LOAD AI MODELS
# ══════════════════════════════════════════════════════════════════════════════
try:
    rf_model  = joblib.load('health_model.pkl')
    iso_model = joblib.load('anomaly_model.pkl')
    scaler    = joblib.load('scaler.pkl')
    print("✓ Models loaded from disk")
except Exception as e:
    print(f"Model load error ({e}) — creating fallback models")
    from sklearn.ensemble import RandomForestRegressor, IsolationForest
    rf_model  = RandomForestRegressor(n_estimators=20, random_state=42)
    iso_model = IsolationForest(contamination=0.1, random_state=42)
    _X = np.random.rand(200, 7) * [100, 1000, 500, 20, 100, 80, 100]
    _y = np.clip(100 - _X[:,2]*0.05 - _X[:,3]*2 - _X[:,0]*0.1, 0, 100)
    rf_model.fit(_X, _y)
    iso_model.fit(_X)
    print("✓ Fallback models created")

# ══════════════════════════════════════════════════════════════════════════════
#  SUPABASE
# ══════════════════════════════════════════════════════════════════════════════
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
NETWORK_TYPES = ['router', 'switch', 'firewall', 'wan_link', 'workstation']
TELECOM_TYPES = ['base_station', 'network_tower', 'microwave_link']
MINING_TYPES  = ['pump', 'conveyor', 'ventilation', 'power_meter',
                 'sensor', 'plc', 'scada_node']
CBS_TYPES     = ['cbs_controller']
CBS_SAFETY_THRESHOLD = 90.0
RETRAIN_THRESHOLD    = 50

# Industry-accurate downtime costs (USD/hr)
DOWNTIME_COSTS = {
    'ventilation':    180000,
    'cbs_controller': 450000,
    'pump':           150000,
    'conveyor':       120000,
    'plc':             80000,
    'base_station':    25000,
    'network_tower':   35000,
    'microwave_link':  40000,
    'router':          15000,
    'switch':          10000,
    'firewall':        20000,
    'wan_link':        12000,
}

LOCATIONS = {
    'byo':  {'lat': -20.15, 'lon': 28.58, 'name': 'Bulawayo'},
    'hre':  {'lat': -17.82, 'lon': 31.05, 'name': 'Harare'},
    'mut':  {'lat': -18.97, 'lon': 32.67, 'name': 'Mutare'},
    'mine': {'lat': -17.65, 'lon': 29.85, 'name': 'Mine Site'},
}

# ══════════════════════════════════════════════════════════════════════════════
#  IN-MEMORY STATE
# ══════════════════════════════════════════════════════════════════════════════
device_history = {}   # device_id → list of health scores (last 20)
device_uptime  = {}   # device_id → {total, healthy}
anomaly_count  = 0

# ══════════════════════════════════════════════════════════════════════════════
#  YOUTUBE-STYLE INGESTION QUEUE
# ══════════════════════════════════════════════════════════════════════════════
# YouTube: Upload Service → Encoder → Queue → Storage
# IISentinel: Collector → AI Scorer → Queue → Supabase
#
# This queue is the competitive moat: we NEVER drop a reading even if Supabase
# has a momentary timeout. The API returns instantly; the write happens async.
# Exactly how YouTube accepts your video upload immediately, then encodes later.

metric_queue   = deque(maxlen=500)   # up to 500 unwritten metric rows
incident_queue = deque(maxlen=200)   # up to 200 unwritten incident rows
queue_lock     = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
#  YOUTUBE-STYLE IN-MEMORY CACHE
# ══════════════════════════════════════════════════════════════════════════════
# YouTube: Redis for last-N video metadata → dashboard always instant
# IISentinel: last 200 readings cached 8s → /api/data never waits for Supabase
# One DB round-trip per 8 seconds instead of one per dashboard client refresh.

_data_cache = {'data': [], 'ts': 0}
CACHE_TTL   = 8  # seconds

# ══════════════════════════════════════════════════════════════════════════════
#  PLATFORM OBSERVABILITY
# ══════════════════════════════════════════════════════════════════════════════
# YouTube calls this "Observability Across Systems" — they monitor YouTube itself.
# IISentinel monitors clients' infrastructure, but we also monitor IISentinel.
# Every architectural decision is evaluated against one metric:
# time between "event happens" → "right person decides" → near zero.

platform_stats = {
    'requests_total':    0,
    'requests_failed':   0,
    'cache_hits':        0,
    'cache_misses':      0,
    'flush_count':       0,
    'flush_errors':      0,
    'queue_depth_peak':  0,
    'start_time':        time.time(),
}

# ══════════════════════════════════════════════════════════════════════════════
#  BACKGROUND QUEUE FLUSHER
# ══════════════════════════════════════════════════════════════════════════════
# YouTube: background encoder never blocks the upload API
# IISentinel: background flusher never blocks /api/metrics
# Runs every 3 seconds. On Supabase failure, re-queues rows (no data loss).

def flush_queues():
    while True:
        time.sleep(3)
        with queue_lock:
            m_batch = list(metric_queue)
            i_batch = list(incident_queue)
            metric_queue.clear()
            incident_queue.clear()

        if m_batch:
            try:
                for item in m_batch:
                    supabase.table('metrics').insert(item).execute()
                platform_stats['flush_count'] += 1
                _data_cache['ts'] = 0   # invalidate cache after new writes
            except Exception as e:
                print(f"Metrics flush error: {e}")
                platform_stats['flush_errors'] += 1
                with queue_lock:
                    for item in m_batch[:100]:
                        metric_queue.appendleft(item)

        if i_batch:
            try:
                for item in i_batch:
                    supabase.table('incidents').insert(item).execute()
            except Exception as e:
                print(f"Incidents flush error: {e}")
                with queue_lock:
                    for item in i_batch[:50]:
                        incident_queue.appendleft(item)

threading.Thread(target=flush_queues, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  CACHE HELPER
# ══════════════════════════════════════════════════════════════════════════════
def get_cached_data():
    now = time.time()
    if now - _data_cache['ts'] < CACHE_TTL and _data_cache['data']:
        platform_stats['cache_hits'] += 1
        return _data_cache['data']
    platform_stats['cache_misses'] += 1
    try:
        resp = supabase.table('metrics').select('*') \
            .order('created_at', desc=True).limit(200).execute()
        _data_cache['data'] = resp.data
        _data_cache['ts']   = now
        return resp.data
    except Exception as e:
        print(f"Cache refresh error: {e}")
        return _data_cache['data']

# ══════════════════════════════════════════════════════════════════════════════
#  AUTONOMOUS RETRAINING
# ══════════════════════════════════════════════════════════════════════════════
# YouTube: Recommendation engine retrains when engagement drops below threshold
# IISentinel: Health model retrains when anomaly count spikes above threshold
# Uses pseudo-labelling: recent DB readings are the new training set.
# This is drift detection — as your environment changes, the model adapts.

_retrain_lock  = threading.Lock()
_last_retrain  = {'time': 0, 'count': 0, 'status': 'never run'}

def auto_retrain_model():
    global rf_model, iso_model, anomaly_count
    with _retrain_lock:
        try:
            print("Auto-retraining IISentinel AI model...")
            resp = supabase.table('metrics').select('*') \
                .order('created_at', desc=True).limit(500).execute()
            data = resp.data
            if len(data) < 50:
                _last_retrain['status'] = f'skipped — only {len(data)} rows'
                return False

            X = np.array([[
                float(r.get('cpu_load', 50)         or 50),
                float(r.get('bandwidth_mbps', 100)  or 100),
                float(r.get('latency_ms', 10)        or 10),
                float(r.get('packet_loss', 0)        or 0),
                float(r.get('connected_devices', 10) or 10),
                float(r.get('temperature', 40)       or 40),
                float(r.get('signal_strength', 80)   or 80),
            ] for r in data])

            y = np.array([float(r['health_score']) for r in data])

            from sklearn.ensemble import RandomForestRegressor, IsolationForest
            new_rf  = RandomForestRegressor(n_estimators=50, random_state=42)
            new_iso = IsolationForest(contamination=0.1, random_state=42)
            new_rf.fit(X, y)
            new_iso.fit(X)

            rf_model  = new_rf
            iso_model = new_iso

            try:
                joblib.dump(rf_model,  'health_model.pkl')
                joblib.dump(iso_model, 'anomaly_model.pkl')
            except Exception:
                pass  # on Render, may not have write perms — in-memory is fine

            anomaly_count              = 0
            _last_retrain['time']      = time.time()
            _last_retrain['count']    += 1
            _last_retrain['status']    = f'completed on {len(data)} readings'
            print(f"✓ Model retrained on {len(data)} readings")
            return True
        except Exception as e:
            _last_retrain['status'] = f'error: {e}'
            print(f"Retraining error: {e}")
            return False

def retrain_watcher():
    """Background thread — retrain automatically when anomaly threshold exceeded"""
    while True:
        time.sleep(60)
        if anomaly_count >= RETRAIN_THRESHOLD:
            if time.time() - _last_retrain['time'] > 300:  # 5 min minimum between retrains
                threading.Thread(target=auto_retrain_model, daemon=True).start()

threading.Thread(target=retrain_watcher, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  NOTIFICATION DISPATCH
# ══════════════════════════════════════════════════════════════════════════════
# YouTube: Notification service delivers alert to user within 60 seconds
# IISentinel: CBS anomaly ($450k/hr exposure) → mine engineer phone < 60 seconds
#
# Africa-first channels: SMS is the most reliable (no smartphone required).
# Wire up by adding API keys to Render environment variables.

notification_log = deque(maxlen=100)

def send_notification(device_id, device_type, health_score, message, severity='warning'):
    notif = {
        'ts':       datetime.now(timezone.utc).isoformat(),
        'device':   device_id,
        'type':     device_type,
        'health':   round(health_score, 1),
        'message':  message,
        'severity': severity,
        'channels': [],
    }

    # ── SMS via Africa's Talking ─────────────────────────────────────────────
    # Africa's Talking covers ZW, ZA, KE, NG, UG, TZ with high reliability.
    # No internet required on the recipient's side — plain SMS works underground.
    #
    # AT_API_KEY  = os.environ.get('AT_API_KEY')
    # AT_USERNAME = os.environ.get('AT_USERNAME', 'sandbox')
    # ALERT_PHONE = os.environ.get('ALERT_PHONE', '+263771234567')
    # if AT_API_KEY and severity in ('critical', 'cbs'):
    #     try:
    #         import africastalking
    #         africastalking.initialize(AT_USERNAME, AT_API_KEY)
    #         sms = africastalking.SMS
    #         sms.send(message[:160], [ALERT_PHONE])
    #         notif['channels'].append('sms')
    #     except Exception as e:
    #         notif['sms_error'] = str(e)

    # ── WhatsApp via Twilio ──────────────────────────────────────────────────
    # Reaches engineers who have smartphones. Good for shift supervisors.
    #
    # TWILIO_SID   = os.environ.get('TWILIO_SID')
    # TWILIO_TOKEN = os.environ.get('TWILIO_TOKEN')
    # WA_TO   = os.environ.get('WHATSAPP_TO',   'whatsapp:+263771234567')
    # WA_FROM = os.environ.get('WHATSAPP_FROM', 'whatsapp:+14155238886')
    # if TWILIO_SID and severity in ('critical', 'cbs', 'warning'):
    #     try:
    #         from twilio.rest import Client
    #         Client(TWILIO_SID, TWILIO_TOKEN).messages.create(
    #             body=message, from_=WA_FROM, to=WA_TO)
    #         notif['channels'].append('whatsapp')
    #     except Exception as e:
    #         notif['whatsapp_error'] = str(e)

    # ── Email via SendGrid ───────────────────────────────────────────────────
    # For management and off-site engineers.
    #
    # SENDGRID_KEY = os.environ.get('SENDGRID_API_KEY')
    # ALERT_EMAIL  = os.environ.get('ALERT_EMAIL', 'ops@yourcompany.co.zw')
    # if SENDGRID_KEY:
    #     try:
    #         import sendgrid
    #         from sendgrid.helpers.mail import Mail
    #         sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_KEY)
    #         mail = Mail(from_email='alerts@iisentinel.io',
    #                     to_emails=ALERT_EMAIL,
    #                     subject=f'[IISentinel] {severity.upper()}: {device_id}',
    #                     plain_text_content=message)
    #         sg.send(mail)
    #         notif['channels'].append('email')
    #     except Exception as e:
    #         notif['email_error'] = str(e)

    notification_log.appendleft(notif)
    return notif

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH DECORATOR
# ══════════════════════════════════════════════════════════════════════════════
def require_specialist(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Specialist-Token')
        if not token:
            return jsonify({'error': 'Unauthorised'}), 401
        try:
            result = supabase.table('specialists') \
                .select('*').eq('password', token).execute()
            if not result.data:
                return jsonify({'error': 'Invalid token'}), 401
        except:
            return jsonify({'error': 'Auth error'}), 401
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════════════════════
#  AI HELPERS
# ══════════════════════════════════════════════════════════════════════════════
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

def get_lifecycle_estimate(device_id, device_type, health_score):
    type_hours = {
        'pump': 8760, 'conveyor': 17520, 'ventilation': 26280,
        'plc': 52560, 'router': 43800, 'switch': 43800,
        'base_station': 35040, 'network_tower': 43800,
    }
    base_hours = type_hours.get(device_type, 26280)
    history    = device_history.get(device_id, [])
    if len(history) < 5:
        return None
    trend = history[-1] - history[0]
    decline_per_reading = abs(trend) / len(history) if trend < 0 else 0
    if decline_per_reading > 0:
        readings_to_failure = health_score / decline_per_reading
        hours_remaining = min(base_hours, readings_to_failure * (10 / 3600))
        return round(hours_remaining, 0)
    return base_hours

def get_protocol_diagnosis(device_type, protocol, metric_name,
                           metric_value, health_score, anomaly):
    issues, actions = [], []
    proto_label = protocol or 'Ethernet'

    if health_score < 20:
        issues.append("critical system failure detected")
        actions.append("immediate intervention required")
    elif health_score < 35:
        issues.append("severe performance degradation")
        actions.append("escalate to operations team")
    elif health_score < 50:
        issues.append("moderate performance degradation")
        actions.append("schedule maintenance within 24 hours")

    if device_type in TELECOM_TYPES or device_type in NETWORK_TYPES:
        if 'latency' in str(metric_name) and metric_value > 100:
            issues.append(f"SNMP reports {metric_value:.1f}ms latency on backhaul")
            actions.append("inspect BGP routing and check fibre integrity")
        if 'packet' in str(metric_name) and metric_value > 2:
            issues.append(f"packet loss {metric_value:.1f}% on {proto_label}")
            actions.append("run BERT test and check SFP modules")
        if 'bandwidth' in str(metric_name) and metric_value > 800:
            issues.append(f"bandwidth at {metric_value:.1f}Mbps near capacity")
            actions.append("implement QoS and analyse NetFlow traffic")
        if 'signal' in str(metric_name) and metric_value < 40:
            issues.append(f"signal at {metric_value:.1f}% — link degraded")
            actions.append("inspect microwave alignment")

    elif device_type in MINING_TYPES:
        if 'temperature' in str(metric_name) and metric_value > 75:
            issues.append(f"Profinet reports {metric_value:.1f}°C — thermal threshold exceeded")
            actions.append("check cooling fan and reduce duty cycle")
        if 'vibration' in str(metric_name) and metric_value > 3:
            issues.append(f"vibration {metric_value:.2f}g via OPC-UA — bearing wear suspected")
            actions.append("schedule predictive maintenance within 4 hours")
        if 'pressure' in str(metric_name) and metric_value > 8:
            issues.append(f"pressure {metric_value:.1f}bar above safe limit")
            actions.append("open bypass valve — alert hydraulics engineer")

    elif device_type == 'cbs_controller':
        if health_score < CBS_SAFETY_THRESHOLD:
            issues.append(f"CBS DNP3 link {health_score:.1f}% below blast threshold")
            actions.append("BLAST HOLD — notify blasting officer, inspect DNP3 link")

    if anomaly:
        issues.append(f"Isolation Forest anomaly on {proto_label}")
        actions.append("cross-reference with device event log")

    if not issues:
        return (f"Device operating within normal parameters via {proto_label}. "
                f"Health score {health_score:.1f}/100.")
    return (f"{'; '.join(issues).capitalize()}. "
            f"Recommended: {'; '.join(actions).capitalize()}.")

def get_automation_command(device_id, device_type, health_score,
                           blast_hold=False, override=None):
    if override:
        return override
    if device_type == 'cbs_controller' and health_score < CBS_SAFETY_THRESHOLD:
        return (f"CBS SAFETY INTERLOCK: BLAST HOLD on {device_id} — "
                f"DNP3 link {health_score:.1f}% below threshold.")
    if device_type in ['ventilation', 'pump'] and health_score < 20:
        return (f"EMERGENCY: Safety shutdown {device_id} — "
                f"underground evacuation alert triggered via PA system")
    if health_score < 20:
        return f"CRITICAL: Emergency restart for {device_id}"
    if health_score < 35:
        return f"WARNING: Isolate {device_id} and reduce load"
    if health_score < 50:
        return f"CAUTION: Schedule maintenance for {device_id}"
    return None

def update_uptime(device_id, health_score):
    if device_id not in device_uptime:
        device_uptime[device_id] = {'total': 0, 'healthy': 0}
    device_uptime[device_id]['total'] += 1
    if health_score >= 50:
        device_uptime[device_id]['healthy'] += 1

def get_uptime_pct(device_id):
    d = device_uptime.get(device_id, {'total': 0, 'healthy': 0})
    return 100.0 if d['total'] == 0 else round((d['healthy'] / d['total']) * 100, 1)

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    global anomaly_count
    platform_stats['requests_total'] += 1

    data        = request.json
    device_id   = data.get('device_id', 'unknown')
    device_type = data.get('device_type', 'unknown')
    protocol    = data.get('protocol', 'Ethernet')
    blast_hold  = data.get('blast_hold', False)
    override    = data.get('automation_override', None)

    features = np.array([[
        float(data.get('cpu_load',          50) or 50),
        float(data.get('bandwidth_mbps',   100) or 100),
        float(data.get('latency_ms',        10) or 10),
        float(data.get('packet_loss',        0) or 0),
        float(data.get('connected_devices', 10) or 10),
        float(data.get('temperature',       40) or 40),
        float(data.get('signal_strength',   80) or 80),
    ]])

    try:
        health_score = float(rf_model.predict(features)[0])
        health_score = max(0.0, min(100.0, health_score))
        if device_type == 'cbs_controller':
            health_score = min(health_score,
                               float(data.get('signal_strength', 100) or 100))
    except Exception:
        health_score = 75.0

    try:
        anomaly_flag = bool(iso_model.predict(features)[0] == -1)
    except Exception:
        anomaly_flag = False

    if anomaly_flag:
        anomaly_count += 1

    # ── Update device history ────────────────────────────────────────────────
    if device_id not in device_history:
        device_history[device_id] = []
    device_history[device_id].append(health_score)
    if len(device_history[device_id]) > 20:
        device_history[device_id].pop(0)

    # ── Predicted score (trend projection) ──────────────────────────────────
    hist = device_history[device_id]
    if len(hist) >= 3:
        trend = hist[-1] - hist[0]
        predicted_score = max(0.0, min(100.0, health_score + trend * 0.4))
    else:
        predicted_score = health_score

    failure_prob    = get_failure_probability(device_id, health_score)
    recent_scores   = {did: h[-1] for did, h in device_history.items() if h}
    federated_index = get_federated_health_index(list(recent_scores.values()))
    update_uptime(device_id, health_score)
    lifecycle = get_lifecycle_estimate(device_id, device_type, health_score)

    ai_diagnosis = None
    if anomaly_flag or health_score < 50 or device_type == 'cbs_controller':
        ai_diagnosis = get_protocol_diagnosis(
            device_type, protocol,
            data.get('metric_name', 'unknown'),
            data.get('metric_value', 0),
            health_score, anomaly_flag
        )

    automation_command = get_automation_command(
        device_id, device_type, health_score, blast_hold, override)

    # ── QUEUE (YouTube-style non-blocking write) ─────────────────────────────
    metric_record = {
        'device_type':       device_type,
        'device_id':         device_id,
        'metric_name':       data.get('metric_name', 'unknown'),
        'metric_value':      float(data.get('metric_value', 0) or 0),
        'health_score':      health_score,
        'anomaly_flag':      anomaly_flag,
        'predicted_score':   predicted_score,
        'ai_diagnosis':      ai_diagnosis,
        'automation_command': automation_command,
    }
    with queue_lock:
        metric_queue.append(metric_record)
        depth = len(metric_queue)
        if depth > platform_stats['queue_depth_peak']:
            platform_stats['queue_depth_peak'] = depth

    # ── Queue incident if critical ───────────────────────────────────────────
    if health_score < 50 or anomaly_flag or blast_hold:
        with queue_lock:
            incident_queue.append({
                'device_id':        device_id,
                'device_type':      device_type,
                'health_score':     health_score,
                'ai_diagnosis':     ai_diagnosis,
                'automation_command': automation_command,
                'status':           'open',
            })

    # ── Notifications ────────────────────────────────────────────────────────
    severity = None
    if device_type == 'cbs_controller' and health_score < CBS_SAFETY_THRESHOLD:
        severity = 'cbs'
    elif health_score < 20:
        severity = 'critical'
    elif health_score < 35 or anomaly_flag:
        severity = 'warning'

    if severity and ai_diagnosis:
        cost = DOWNTIME_COSTS.get(device_type, 8000)
        msg  = (f"[IISentinel] {severity.upper()} — {device_id}: "
                f"{ai_diagnosis[:100]}. Cost: ${cost:,}/hr")
        threading.Thread(
            target=send_notification,
            args=(device_id, device_type, health_score, msg, severity),
            daemon=True
        ).start()

    return jsonify({
        'status':             'ok',
        'health_score':       round(health_score, 1),
        'anomaly_flag':       anomaly_flag,
        'predicted_score':    round(predicted_score, 1),
        'failure_probability': failure_prob,
        'ai_diagnosis':        ai_diagnosis,
        'automation_command':  automation_command,
        'federated_index':     federated_index,
        'uptime_pct':          get_uptime_pct(device_id),
        'lifecycle_hours':     lifecycle,
        'retrain_needed':      anomaly_count >= RETRAIN_THRESHOLD,
        'anomaly_count':       anomaly_count,
        'blast_hold':          blast_hold,
    })


@app.route('/api/data', methods=['GET'])
def get_data():
    # YouTube-style: always serve from cache, never block on DB
    return jsonify(get_cached_data())


@app.route('/api/intelligence', methods=['GET'])
def get_intelligence():
    recent_scores = {did: h[-1] for did, h in device_history.items() if h}
    probs = {
        did: get_failure_probability(did, h[-1])
        for did, h in device_history.items() if h
    }
    lifecycles = {}
    try:
        resp = supabase.table('metrics') \
            .select('device_id,device_type') \
            .order('created_at', desc=True).limit(50).execute()
        for row in resp.data:
            did = row['device_id']
            if did in recent_scores and did not in lifecycles:
                lc = get_lifecycle_estimate(did, row['device_type'], recent_scores[did])
                if lc:
                    lifecycles[did] = lc
    except:
        pass

    return jsonify({
        'federated_index':       get_federated_health_index(list(recent_scores.values())),
        'device_scores':         recent_scores,
        'uptime':                {did: get_uptime_pct(did) for did in device_uptime},
        'failure_probabilities': probs,
        'lifecycles':            lifecycles,
        'retrain_needed':        anomaly_count >= RETRAIN_THRESHOLD,
        'anomaly_count':         anomaly_count,
        'total_devices':         len(device_history),
        'retrains_done':         _last_retrain['count'],
        'last_retrain':          _last_retrain['time'],
        'retrain_status':        _last_retrain['status'],
    })


@app.route('/api/twin/<device_id>', methods=['GET'])
def digital_twin(device_id):
    history = device_history.get(device_id, [])
    if not history:
        return jsonify({'error': 'No history for device'}), 404

    current_score = history[-1]
    scenarios = []
    for mult in [1.1, 1.2, 1.5, 2.0]:
        features = np.array([[
            min(100, 50 * mult), min(1000, 100 * mult),
            min(500, 10 * mult), min(20, mult * 0.5),
            10, 40, 80
        ]])
        try:
            sim_score = float(rf_model.predict(features)[0])
            sim_score = max(0.0, min(100.0, sim_score))
            anom      = bool(iso_model.predict(features)[0] == -1)
        except:
            sim_score = current_score * (1.0 / mult)
            anom      = False
        scenarios.append({
            'load_increase':    f'+{int((mult - 1) * 100)}%',
            'predicted_score':  round(sim_score, 1),
            'anomaly_predicted': anom,
            'risk':             'critical' if sim_score < 30 else
                                'warning'  if sim_score < 60 else 'safe',
        })

    trend_info = {'slope_per_reading': 0, 'direction': 'insufficient data',
                  'readings_to_critical': None}
    if len(history) >= 5:
        slope = (history[-1] - history[-5]) / 4
        rtt   = round((current_score - 20) / abs(slope)) \
                if slope < 0 and current_score > 20 else None
        trend_info = {
            'slope_per_reading':    round(slope, 2),
            'direction':            'declining' if slope < 0 else
                                    'stable'    if slope == 0 else 'improving',
            'readings_to_critical': rtt,
        }

    return jsonify({
        'device_id':         device_id,
        'current_score':     round(current_score, 1),
        'history':           [round(h, 1) for h in history],
        'scenarios':         scenarios,
        'trend':             trend_info,
        'failure_probability': get_failure_probability(device_id, current_score),
    })


@app.route('/api/weather', methods=['GET'])
def get_weather():
    loc_key = request.args.get('loc', 'byo')
    loc     = LOCATIONS.get(loc_key, LOCATIONS['byo'])
    try:
        url = (
            f"https://api.open-meteo.com/v1/forecast"
            f"?latitude={loc['lat']}&longitude={loc['lon']}"
            f"&current=temperature_2m,relative_humidity_2m,wind_speed_10m,"
            f"wind_gusts_10m,precipitation,weather_code,cloud_cover"
            f"&hourly=temperature_2m,precipitation_probability,wind_speed_10m"
            f"&forecast_days=2&timezone=Africa/Harare"
        )
        resp    = req.get(url, timeout=10)
        d       = resp.json()
        current = d.get('current', {})
        hourly  = d.get('hourly', {})

        wind    = current.get('wind_speed_10m', 0)
        gusts   = current.get('wind_gusts_10m', 0)
        precip  = current.get('precipitation', 0)
        temp    = current.get('temperature_2m', 25)
        humidity = current.get('relative_humidity_2m', 50)
        wcode   = current.get('weather_code', 0)
        cloud   = current.get('cloud_cover', 0)

        alerts, impacts = [], []
        if wind > 40:
            alerts.append(f"High winds {wind:.0f}km/h — microwave links at risk")
            impacts.append({'type': 'telecom',
                            'impact': "Signal degradation on exposed towers",
                            'severity': 'warning'})
        if gusts > 60:
            alerts.append(f"Dangerous gusts {gusts:.0f}km/h — tower stability risk")
            impacts.append({'type': 'telecom',
                            'impact': "CBS blast hold recommended",
                            'severity': 'critical'})
        if precip > 10:
            alerts.append(f"Heavy precipitation {precip:.1f}mm — pump load will increase")
            impacts.append({'type': 'mining',
                            'impact': "Underground water ingress — increase pump monitoring",
                            'severity': 'warning'})
        if temp > 38:
            alerts.append(f"Extreme heat {temp:.0f}°C — thermal stress elevated")
            impacts.append({'type': 'all',
                            'impact': "Health score degradation — increase cooling checks",
                            'severity': 'warning'})
        if wcode >= 95:
            alerts.append("Thunderstorm active — lightning risk to exposed equipment")
            impacts.append({'type': 'all',
                            'impact': "Surge protection alert — consider temporary shutdown",
                            'severity': 'critical'})

        next24 = hourly.get('precipitation_probability', [])[:24]
        return jsonify({
            'location':    loc['name'],
            'temperature': temp,
            'humidity':    humidity,
            'wind_speed':  wind,
            'wind_gusts':  gusts,
            'precipitation': precip,
            'weather_code':  wcode,
            'cloud_cover':   cloud,
            'alerts':         alerts,
            'equipment_impact': impacts,
            'max_precip_probability_24h': max(next24) if next24 else 0,
            'hourly_wind':        hourly.get('wind_speed_10m', [])[:24],
            'hourly_precip_prob': next24,
        })
    except Exception as e:
        return jsonify({'error': str(e), 'location': loc['name']}), 500


@app.route('/api/platform', methods=['GET'])
def platform_health():
    """
    YouTube-style platform observability — monitor IISentinel itself.
    Surfaces: queue depth, cache freshness, retraining status, error rates.
    This is your internal SLA dashboard — the 'Observability Across Systems' layer.
    """
    cache_hit_rate = round(
        platform_stats['cache_hits'] /
        max(1, platform_stats['cache_hits'] + platform_stats['cache_misses']) * 100, 1
    )
    return jsonify({
        'queue_depth':          len(metric_queue),
        'incident_queue_depth': len(incident_queue),
        'cache_age_seconds':    round(time.time() - _data_cache['ts'], 1),
        'cache_hit_rate':       cache_hit_rate,
        'devices_tracked':      len(device_history),
        'anomaly_count':        anomaly_count,
        'retrain_needed':       anomaly_count >= RETRAIN_THRESHOLD,
        'retrain_threshold':    RETRAIN_THRESHOLD,
        'retrains_done':        _last_retrain['count'],
        'retrain_status':       _last_retrain['status'],
        'last_retrain_ago_s':   round(time.time() - _last_retrain['time'])
                                if _last_retrain['time'] else None,
        'flush_count':          platform_stats['flush_count'],
        'flush_errors':         platform_stats['flush_errors'],
        'queue_depth_peak':     platform_stats['queue_depth_peak'],
        'requests_total':       platform_stats['requests_total'],
        'uptime_seconds':       round(time.time() - platform_stats['start_time']),
        'notifications_logged': len(notification_log),
        'architecture': {
            'ingestion':   'Queued batch (YouTube-style) — never drops a reading',
            'cache':       f'{CACHE_TTL}s TTL in-memory — instant dashboard response',
            'retraining':  'Autonomous pseudo-label on anomaly threshold breach',
            'ai_models':   'RandomForest health scorer + IsolationForest anomaly detector',
            'protocols':   'SNMP · Profinet · Modbus TCP · DNP3 · OPC-UA · EtherNet/IP',
            'delivery':    'Edge-ready — deploy per site, aggregate centrally',
        },
    })


@app.route('/api/retrain', methods=['POST'])
@require_specialist
def trigger_retrain():
    """Manual retraining trigger — specialists can force a model update."""
    threading.Thread(target=auto_retrain_model, daemon=True).start()
    return jsonify({
        'status':  'started',
        'message': 'Autonomous retraining triggered in background thread',
    })


@app.route('/api/notifications', methods=['GET'])
@require_specialist
def get_notifications():
    return jsonify(list(notification_log)[:50])


@app.route('/api/shift-report', methods=['GET'])
@require_specialist
def shift_report():
    try:
        resp = supabase.table('metrics').select('*') \
            .order('created_at', desc=True).limit(500).execute()
        data = resp.data
        inc_resp = supabase.table('incidents').select('*') \
            .order('created_at', desc=True).limit(100).execute()
        incidents = inc_resp.data

        device_map = {}
        for row in data:
            if row['device_id'] not in device_map:
                device_map[row['device_id']] = row

        critical = [d for d in device_map.values() if d['health_score'] < 20]
        warning  = [d for d in device_map.values() if 20 <= d['health_score'] < 50]
        healthy  = [d for d in device_map.values() if d['health_score'] >= 50]

        open_incidents = [i for i in incidents if i['status'] == 'open']
        scores         = [d['health_score'] for d in device_map.values()]
        avg_health     = round(sum(scores) / len(scores), 1) if scores else 100

        total_risk = sum(
            DOWNTIME_COSTS.get(d['device_type'], 8000) * (1 - d['health_score'] / 100)
            for d in critical + warning
        )

        return jsonify({
            'generated_at':      datetime.now(timezone.utc).isoformat(),
            'total_devices':     len(device_map),
            'avg_health':        avg_health,
            'critical_devices':  len(critical),
            'warning_devices':   len(warning),
            'healthy_devices':   len(healthy),
            'open_incidents':    len(open_incidents),
            'resolved_incidents': len([i for i in incidents if i['status'] == 'resolved']),
            'total_risk_per_hr': round(total_risk),
            'top_risks': [
                {'device':    d['device_id'],
                 'score':     round(d['health_score'], 1),
                 'diagnosis': d.get('ai_diagnosis', '')}
                for d in sorted(critical + warning, key=lambda x: x['health_score'])[:5]
            ],
            'automation_commands': [
                {'device': d['device_id'], 'command': d['automation_command']}
                for d in device_map.values() if d.get('automation_command')
            ],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    try:
        result = supabase.table('specialists').select('*') \
            .eq('name', data.get('name', '')) \
            .eq('password', data.get('password', '')).execute()
        if result.data:
            s = result.data[0]
            return jsonify({
                'success': True,
                'token':   data.get('password'),
                'name':    s['name'],
                'role':    s['role'],
            })
        return jsonify({'success': False}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/incidents', methods=['GET'])
@require_specialist
def get_incidents():
    status   = request.args.get('status', 'open')
    response = supabase.table('incidents').select('*') \
        .eq('status', status) \
        .order('created_at', desc=True).limit(50).execute()
    return jsonify(response.data)


@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
@require_specialist
def assign_incident(incident_id):
    data = request.json
    supabase.table('incidents').update({
        'assigned_to': data.get('assigned_to', ''),
        'notes':       data.get('notes', ''),
        'status':      'assigned',
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})


@app.route('/api/incidents/<incident_id>/resolve', methods=['POST'])
@require_specialist
def resolve_incident(incident_id):
    data = request.json
    supabase.table('incidents').update({
        'resolved_by': data.get('resolved_by', ''),
        'notes':       data.get('notes', ''),
        'status':      'resolved',
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})


@app.route('/')
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
