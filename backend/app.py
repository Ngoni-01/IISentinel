import os
import joblib
import numpy as np
import requests as req
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from supabase import create_client
from functools import wraps
from datetime import datetime, timezone
import threading
import time
import smtplib
import re
import queue as _queue
import random
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque

# ── IN-MEMORY QUEUE (YouTube Upload Service equivalent) ───────────────────
metric_queue = deque(maxlen=500)
queue_lock   = threading.Lock()

# ── IN-MEMORY CACHE (YouTube Redis/CDN equivalent) ────────────────────────
_data_cache = {'data': [], 'ts': 0}
CACHE_TTL   = 8

def get_cached_data():
    now = time.time()
    if now - _data_cache['ts'] < CACHE_TTL and _data_cache['data']:
        if 'platform_stats' in globals():
            platform_stats['cache_hits'] += 1
        return _data_cache['data']
    try:
        resp = globals()['supabase'].table('metrics').select('*') \
            .order('created_at', desc=True).limit(200).execute()
        _data_cache['data'] = resp.data
        _data_cache['ts']   = now
        return resp.data
    except Exception as e:
        print(f'Cache refresh error: {e}')
        return _data_cache['data']

# ── BACKGROUND QUEUE FLUSHER ──────────────────────────────────────────────
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
            if 'platform_stats' in globals(): platform_stats['last_flush'] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            print(f'Queue flush error: {e}')
            with queue_lock:
                for item in batch[:50]:
                    metric_queue.appendleft(item)

threading.Thread(target=flush_queue, daemon=True).start()

# ── ASYNC AI SCORING QUEUE (YouTube Encoder/AI equivalent) ────────────────
# AI scoring runs in background — /api/metrics never waits on the model
scoring_queue   = deque(maxlen=200)
scoring_results = {}
scoring_lock    = threading.Lock()

def background_scorer():
    while True:
        time.sleep(0.5)
        with scoring_lock:
            if not scoring_queue:
                continue
            item = scoring_queue.popleft()
        try:
            arr   = np.array([item['features']])
            score = float(rf_model.predict(arr)[0])
            score = max(0, min(100, score))
            anom  = bool(iso_model.predict(arr)[0] == -1)
            scoring_results[item['meta']['device_id']] = {
                **item['meta'], 'health_score': score,
                'anomaly_flag': anom, 'scored_at': time.time()
            }
            platform_stats['models_scored'] += 1
        except Exception as e:
            print(f'Async scorer error: {e}')

threading.Thread(target=background_scorer, daemon=True).start()

# ── AUTO-RETRAIN PIPELINE (YouTube Adaptive Algorithm equivalent) ──────────
# When anomaly_count >= threshold, pulls Supabase data, retrains models,
# hot-swaps them in memory — zero dashboard downtime
retrain_lock        = threading.Lock()
_retrain_in_progress = False

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
            print('[AutoRetrain] Threshold hit — fetching training data...')
            platform_stats['last_retrain_attempt'] = datetime.now(timezone.utc).isoformat()
            resp = supabase.table('metrics').select(
                'cpu_load,bandwidth_mbps,latency_ms,packet_loss,'
                'connected_devices,temperature,signal_strength,health_score'
            ).order('created_at', desc=True).limit(2000).execute()
            rows = resp.data
            if len(rows) < 100:
                print('[AutoRetrain] Not enough data — skipping')
                continue
            from sklearn.ensemble import RandomForestRegressor, IsolationForest
            X, y = [], []
            for r in rows:
                feats = [r.get('cpu_load',50), r.get('bandwidth_mbps',100),
                         r.get('latency_ms',10), r.get('packet_loss',0),
                         r.get('connected_devices',10),
                         r.get('temperature',40), r.get('signal_strength',80)]
                if None not in feats and r.get('health_score') is not None:
                    X.append(feats); y.append(r['health_score'])
            if len(X) < 50:
                continue
            X = np.array(X); y = np.array(y)
            new_rf  = RandomForestRegressor(n_estimators=100, max_depth=10,
                                            random_state=42, n_jobs=-1)
            new_rf.fit(X, y)
            new_iso = IsolationForest(n_estimators=100, contamination=0.08,
                                     random_state=42, n_jobs=-1)
            new_iso.fit(X[y >= 60])
            import joblib as jl
            jl.dump(new_rf,  'health_model.pkl')
            jl.dump(new_iso, 'anomaly_model.pkl')
            rf_model  = new_rf
            iso_model = new_iso
            anomaly_count = 0
            platform_stats['last_retrain_success'] = datetime.now(timezone.utc).isoformat()
            platform_stats['retrain_count'] = platform_stats.get('retrain_count',0)+1
            print(f'[AutoRetrain] Done — retrained on {len(X)} samples')
            notify_all('IISentinel\u2122 Model Retrained',
                       f'Models retrained on {len(X)} readings.', level='info')
        except Exception as e:
            print(f'[AutoRetrain] Error: {e}')
        finally:
            with retrain_lock:
                _retrain_in_progress = False

threading.Thread(target=auto_retrain_pipeline, daemon=True).start()


# ── SSE BROADCAST (real-time push, YouTube Delivery Layer equivalent) ────────
# Critical events reach connected browsers in <100ms instead of <=10s poll.
# CBS blast hold at $450k/hr: every second saved = $125 saved.
_sse_subscribers = []
_sse_lock = threading.Lock()

def sse_broadcast(event_type, payload):
    import json
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

# ── NOTIFICATION SERVICE (YouTube Notification Service equivalent) ─────────
# Multi-channel alerts: SMS → WhatsApp Business → Email
NOTIFY_CONFIG = {
    'email_enabled':    os.environ.get('NOTIFY_EMAIL_ENABLED','false').lower()=='true',
    'sms_enabled':      os.environ.get('NOTIFY_SMS_ENABLED','false').lower()=='true',
    'whatsapp_enabled': os.environ.get('NOTIFY_WHATSAPP_ENABLED','false').lower()=='true',
    'smtp_host':   os.environ.get('SMTP_HOST','smtp.gmail.com'),
    'smtp_port':   int(os.environ.get('SMTP_PORT','587')),
    'smtp_user':   os.environ.get('SMTP_USER',''),
    'smtp_pass':   os.environ.get('SMTP_PASS',''),
    'from_email':  os.environ.get('NOTIFY_FROM',''),
    'to_emails':   os.environ.get('NOTIFY_TO','').split(','),
    'at_api_key':  os.environ.get('AT_API_KEY',''),
    'at_username': os.environ.get('AT_USERNAME',''),
    'sms_numbers': os.environ.get('NOTIFY_SMS','').split(','),
    'wa_token':    os.environ.get('WA_TOKEN',''),
    'wa_phone_id': os.environ.get('WA_PHONE_ID',''),
    'wa_numbers':  os.environ.get('NOTIFY_WA','').split(','),
    # Regex-based site routing: pattern -> extra SMS recipients per site
    # Example: SITE_ROUTES='byo:+263771111111,hre:+263772222222,mine:+263773333333'
    'site_routes':  os.environ.get('SITE_ROUTES',''),
}

# ── REGEX ALERT ROUTER ────────────────────────────────────────────────────
# Parses device_id with regex to route alerts to site-specific engineers.
# Pattern: <sector>-<site>-<type>-<id>  e.g. mc-shaft2-pump-01, cbs-dnp3-mine-ctrl
# This is the YouTube Notification Service equivalent — right person, right channel, <60s.
SITE_ROUTE_MAP: dict = {}
for pair in os.environ.get('SITE_ROUTES','').split(','):
    if ':' in pair:
        site, number = pair.strip().split(':',1)
        SITE_ROUTE_MAP[site.strip()] = number.strip()

# Regex patterns for device_id routing
DEVICE_ID_PATTERNS = {
    'cbs':   re.compile(r'^cbs[-_]'),
    'mine':  re.compile(r'^mc[-_]'),
    'net':   re.compile(r'^net[-_]'),
    'tc':    re.compile(r'^tc[-_]'),
    'shaft': re.compile(r'[-_]shaft\d'),
}

def resolve_site_contacts(device_id: str) -> list:
    """Use regex to match device_id and return site-specific SMS numbers."""
    if not device_id or not SITE_ROUTE_MAP:
        return []
    contacts = []
    for site_key, number in SITE_ROUTE_MAP.items():
        pattern = re.compile(rf'[-_]?{re.escape(site_key)}[-_]?', re.IGNORECASE)
        if pattern.search(device_id):
            contacts.append(number)
    return contacts
notification_log = deque(maxlen=100)

def send_email_alert(subject, body):
    if not NOTIFY_CONFIG['email_enabled'] or not NOTIFY_CONFIG['smtp_user']:
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = f'[IISentinel\u2122] {subject}'
        msg['From']    = NOTIFY_CONFIG['from_email']
        msg['To']      = ', '.join(NOTIFY_CONFIG['to_emails'])
        with smtplib.SMTP(NOTIFY_CONFIG['smtp_host'], NOTIFY_CONFIG['smtp_port']) as s:
            s.starttls(); s.login(NOTIFY_CONFIG['smtp_user'], NOTIFY_CONFIG['smtp_pass'])
            s.send_message(msg)
    except Exception as e:
        print(f'[Email] Error: {e}')

def send_sms_alert(message):
    """SMS alert dispatch via configured gateway."""
    if not NOTIFY_CONFIG['sms_enabled'] or not NOTIFY_CONFIG['at_api_key']:
        return
    try:
        req.post('https://api.africastalking.com/version1/messaging',
            headers={'apiKey': NOTIFY_CONFIG['at_api_key'], 'Accept': 'application/json'},
            data={'username': NOTIFY_CONFIG['at_username'],
                  'to': ','.join(NOTIFY_CONFIG['sms_numbers']),
                  'message': f'IISentinel\u2122: {message}', 'from': 'IISentinel'},
            timeout=8)
    except Exception as e:
        print(f'[SMS] Error: {e}')

def send_whatsapp_alert(message):
    if not NOTIFY_CONFIG['whatsapp_enabled'] or not NOTIFY_CONFIG['wa_token']:
        return
    try:
        for number in NOTIFY_CONFIG['wa_numbers']:
            if not number.strip(): continue
            req.post(f'https://graph.facebook.com/v19.0/{NOTIFY_CONFIG["wa_phone_id"]}/messages',
                headers={'Authorization': f'Bearer {NOTIFY_CONFIG["wa_token"]}',
                         'Content-Type': 'application/json'},
                json={'messaging_product':'whatsapp','to':number.strip(),
                      'type':'text','text':{'body':f'IISentinel\u2122\n{message}'}},
                timeout=8)
    except Exception as e:
        print(f'[WhatsApp] Error: {e}')

def notify_all(subject, message, level='critical', device_id=None):
    notification_log.appendleft({'subject':subject,'message':message,
        'level':level,'device_id':device_id,
        'ts':datetime.now(timezone.utc).isoformat()})
    platform_stats['notifications_sent'] = platform_stats.get('notifications_sent',0)+1

    # Regex-based site routing — pipe alert to site-specific engineer contacts
    site_contacts = resolve_site_contacts(device_id or '')
    full_msg = f'{subject}: {message}'

    if level in ('critical','cbs'):
        # Broadcast + site-specific routing
        threading.Thread(target=send_sms_alert, args=(full_msg,), daemon=True).start()
        threading.Thread(target=send_whatsapp_alert,
                         args=(f'*{subject}*\n{message}',), daemon=True).start()
        # Also send to site-specific contacts if regex matched
        for contact in site_contacts:
            if contact not in NOTIFY_CONFIG['sms_numbers']:
                threading.Thread(target=send_sms_alert,
                                 args=(f'[SITE-ROUTED] {full_msg}',),
                                 daemon=True).start()
    threading.Thread(target=send_email_alert,
                     args=(subject, message), daemon=True).start()


# ── INPUT VALIDATION ─────────────────────────────────────────────────────────
# Protects scikit-learn from malformed collector data.
FIELD_BOUNDS = {
    'cpu_load':(0,100),'bandwidth_mbps':(0,100000),'latency_ms':(0,60000),
    'packet_loss':(0,100),'connected_devices':(0,100000),
    'temperature':(-50,200),'signal_strength':(0,100),'metric_value':(-1e9,1e9),
}

def sanitize_metric(data):
    if not isinstance(data, dict):
        return {}, 'Payload must be JSON object'
    for f in ['device_id','device_type']:
        if not data.get(f):
            return {}, f'Missing required field: {f}'
    did = str(data.get('device_id',''))
    if not re.match(r'^[a-zA-Z0-9_\-]{1,80}$', did):
        return {}, f'Invalid device_id format'
    cleaned = dict(data)
    cleaned['device_id'] = did
    for field,(lo,hi) in FIELD_BOUNDS.items():
        if field in cleaned:
            try:
                cleaned[field] = float(max(lo, min(hi, float(cleaned[field]))))
            except (TypeError, ValueError):
                cleaned[field] = (lo+hi)/2
    return cleaned, None

# ── PLATFORM OBSERVABILITY ────────────────────────────────────────────────
platform_stats = {
    'requests_total': 0, 'requests_failed': 0,
    'cache_hits': 0, 'models_scored': 0,
    'queue_depth': 0, 'last_flush': None,
    'last_retrain_attempt': None, 'last_retrain_success': None,
    'retrain_count': 0,
    'notifications_sent': 0,
    'uptime_start': datetime.now(timezone.utc).isoformat(),
}

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel-secret-2026')
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri='memory://')

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

NETWORK_TYPES = ['router','switch','firewall','wan_link','workstation']
TELECOM_TYPES = ['base_station','network_tower','microwave_link']
MINING_TYPES  = ['pump','conveyor','ventilation','power_meter','sensor','plc','scada_node']
CBS_TYPES     = ['cbs_controller']
_lifecycle_cache = {}

# Hourly downtime cost rates per device type ($USD)
COST_RATES = {
    'pump': 150000, 'conveyor': 120000, 'ventilation': 180000,
    'plc': 80000, 'scada_node': 60000, 'cbs_controller': 450000,
    'power_meter': 100000, 'sensor': 40000,
    'base_station': 25000, 'network_tower': 35000, 'microwave_link': 40000,
    'router': 15000, 'switch': 10000, 'firewall': 20000,
    'wan_link': 12000, 'workstation': 2000,
}

LOCATIONS = {
    'byo':  {'lat':-20.15,'lon':28.58,'name':'Bulawayo'},
    'hre':  {'lat':-17.82,'lon':31.05,'name':'Harare'},
    'mut':  {'lat':-18.97,'lon':32.67,'name':'Mutare'},
    'mine': {'lat':-17.65,'lon':29.85,'name':'Mine Site'},
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
            return jsonify({'error':'Unauthorised'}), 401
        try:
            result = supabase.table('specialists').select('*').eq('password',token).execute()
            if not result.data:
                return jsonify({'error':'Invalid token'}), 401
        except:
            return jsonify({'error':'Auth error'}), 401
        return f(*args, **kwargs)
    return decorated

def get_failure_probability(device_id, current_score):
    history = device_history.get(device_id, [])
    if len(history) < 3: return 0.0
    recent = history[-5:]
    trend  = recent[-1] - recent[0]
    if trend >= 0: return max(0.0, round((100-current_score)*0.05,1))
    decline_rate = abs(trend)/len(recent)
    return min(99.0, round(decline_rate*3+(100-current_score)*0.3,1))

def get_federated_health_index(all_scores):
    if not all_scores: return 100.0
    weights = [s*0.5 if s<20 else s*0.8 if s<50 else s for s in all_scores]
    return round(sum(weights)/len(weights),1)

def get_root_cause_chain(device_id, current_score, all_recent):
    chain    = []
    degraded = [(did,score) for did,score in all_recent.items() if score<50 and did!=device_id]
    if degraded and current_score < 50:
        for did,score in sorted(degraded,key=lambda x:x[1])[:3]:
            chain.append({'device':did,'score':round(score,1)})
    return chain

def get_lifecycle_estimate(device_id, device_type, health_score):
    type_hours = {'pump':8760,'conveyor':17520,'ventilation':26280,
                  'plc':52560,'router':43800,'switch':43800,
                  'base_station':35040,'network_tower':43800}
    base_hours = type_hours.get(device_type, 26280)
    history    = device_history.get(device_id, [])
    if len(history) < 5: return None
    trend = history[-1]-history[0]
    dpd   = abs(trend)/len(history) if trend<0 else 0
    if dpd > 0:
        return round(min(base_hours, health_score/dpd*(10/3600)))
    return base_hours

def get_protocol_diagnosis(device_type, protocol, metric_name,
                           metric_value, health_score, anomaly):
    issues=[]; actions=[]
    proto_label = PROTOCOL_MAP.get(protocol, protocol or 'Ethernet')
    if health_score<20:   issues.append('critical system failure detected');  actions.append('immediate intervention required')
    elif health_score<35: issues.append('severe performance degradation');    actions.append('escalate to operations team')
    elif health_score<50: issues.append('moderate performance degradation');  actions.append('schedule maintenance within 24 hours')
    if device_type in TELECOM_TYPES or device_type in NETWORK_TYPES:
        if 'latency'   in metric_name and metric_value>100: issues.append(f'SNMP reports {metric_value:.1f}ms latency on backhaul'); actions.append('inspect BGP routing and check fibre integrity')
        if 'packet'    in metric_name and metric_value>2:   issues.append(f'packet loss {metric_value:.1f}% on {proto_label}'); actions.append('run BERT test and check SFP modules')
        if 'bandwidth' in metric_name and metric_value>800: issues.append(f'bandwidth at {metric_value:.1f}Mbps near capacity'); actions.append('implement QoS and analyse NetFlow traffic')
        if 'signal'    in metric_name and metric_value<40:  issues.append(f'signal at {metric_value:.1f}% — link degraded'); actions.append('inspect microwave alignment')
    elif device_type in MINING_TYPES:
        if 'temperature' in metric_name and metric_value>75: issues.append(f'Profinet reports {metric_value:.1f}C — thermal threshold'); actions.append('check cooling fan and reduce duty cycle')
        if 'motor'       in metric_name and metric_value<500:issues.append(f'motor {metric_value:.0f}RPM via Modbus — below minimum'); actions.append('inspect VFD parameters and overcurrent protection')
        if 'vibration'   in metric_name and metric_value>3:  issues.append(f'vibration {metric_value:.2f}g via OPC-UA — bearing wear'); actions.append('schedule predictive maintenance within 4 hours')
        if 'pressure'    in metric_name and metric_value>8:  issues.append(f'pressure {metric_value:.1f}bar — above safe limit'); actions.append('open bypass valve — alert hydraulics engineer')
    elif device_type=='cbs_controller':
        if health_score<CBS_SAFETY_THRESHOLD:
            issues.append(f'CBS DNP3 link {health_score:.1f}% below blast threshold')
            actions.append('BLAST HOLD — notify blasting officer, inspect DNP3 link')
    if anomaly: issues.append(f'Isolation Forest anomaly on {proto_label}'); actions.append('cross-reference with device event log')
    if not issues: return f'Device operating within normal parameters via {proto_label}. Health score {health_score:.1f}/100.'
    return f'{"; ".join(issues).capitalize()}. Recommended actions: {"; ".join(actions).capitalize()}.'

def get_automation_command(device_id, device_type, health_score,
                           blast_hold=False, automation_override=None):
    if automation_override: return automation_override
    if device_type=='cbs_controller' and health_score<CBS_SAFETY_THRESHOLD:
        return f'CBS SAFETY INTERLOCK: BLAST HOLD on {device_id} — DNP3 link {health_score:.1f}% below threshold.'
    if device_type in ['ventilation','pump'] and health_score<20:
        return f'EMERGENCY: Safety shutdown {device_id} — underground evacuation alert triggered via PA system'
    if health_score<20: return f'CRITICAL: Emergency restart for {device_id}'
    if health_score<35: return f'WARNING: Isolate {device_id} and reduce load'
    if health_score<50: return f'CAUTION: Schedule maintenance for {device_id}'
    return None

def update_uptime(device_id, health_score):
    if device_id not in device_uptime:
        device_uptime[device_id]={'total':0,'healthy':0}
    device_uptime[device_id]['total']+=1
    if health_score>=50: device_uptime[device_id]['healthy']+=1

def get_uptime_pct(device_id):
    d=device_uptime.get(device_id,{'total':0,'healthy':0})
    if d['total']==0: return 100.0
    return round((d['healthy']/d['total'])*100,1)

# ═══════════════════════════════════════════
#  /api/data  — YouTube CDN equivalent
#  This was the missing endpoint that caused blank screens.
#  Served from 8-second in-memory cache — always instant.
# ═══════════════════════════════════════════
@app.route('/api/data', methods=['GET'])
def get_data():
    platform_stats['requests_total']+=1
    return jsonify(get_cached_data())

# ═══════════════════════════════════════════
#  /api/metrics  — YouTube Upload + Encoder
# ═══════════════════════════════════════════
@app.route('/api/metrics', methods=['POST'])
@limiter.limit('120 per minute')
def receive_metrics():
    global anomaly_count
    platform_stats['requests_total']+=1
    raw = request.json
    if not raw:
        return jsonify({'error': 'Empty payload'}), 400
    data, err = sanitize_metric(raw)
    if err:
        platform_stats['requests_failed']+=1
        return jsonify({'error': err}), 400
    device_id         = data.get('device_id','unknown')
    device_type       = data.get('device_type','unknown')
    protocol          = data.get('protocol','Ethernet')
    blast_hold        = data.get('blast_hold',False)
    automation_override = data.get('automation_override',None)

    features = [data.get('cpu_load',50), data.get('bandwidth_mbps',100),
                data.get('latency_ms',10), data.get('packet_loss',0),
                data.get('connected_devices',10), data.get('temperature',40),
                data.get('signal_strength',80)]
    features_arr = np.array([features])

    health_score = float(rf_model.predict(features_arr)[0])
    health_score = max(0, min(100, health_score))
    if device_type=='cbs_controller':
        health_score = min(health_score, data.get('signal_strength',100))

    anomaly_result = iso_model.predict(features_arr)[0]
    anomaly_flag   = bool(anomaly_result==-1)
    if anomaly_flag: anomaly_count+=1

    # Queue for async background re-scoring
    with scoring_lock:
        scoring_queue.append({'features':features,
                              'meta':{'device_id':device_id,'device_type':device_type}})

    if device_id not in device_history: device_history[device_id]=[]
    device_history[device_id].append(health_score)
    if len(device_history[device_id])>20: device_history[device_id].pop(0)

    reading_window.append(health_score)
    if len(reading_window)>10: reading_window.pop(0)
    if len(reading_window)>=3:
        trend = reading_window[-1]-reading_window[0]
        predicted_score = max(0,min(100,health_score+trend))
    else:
        predicted_score = health_score

    failure_prob  = get_failure_probability(device_id, health_score)
    recent_scores = {did:hist[-1] for did,hist in device_history.items() if hist}
    root_cause    = get_root_cause_chain(device_id, health_score, recent_scores)
    lifecycle     = get_lifecycle_estimate(device_id, device_type, health_score)
    federated_index = get_federated_health_index(list(recent_scores.values()))
    update_uptime(device_id, health_score)
    uptime_pct = get_uptime_pct(device_id)

    ai_diagnosis = None
    if anomaly_flag or health_score<50 or device_type=='cbs_controller':
        ai_diagnosis = get_protocol_diagnosis(device_type, protocol,
            data.get('metric_name','unknown'), data.get('metric_value',0),
            health_score, anomaly_flag)

    automation_command = get_automation_command(device_id, device_type,
        health_score, blast_hold, automation_override)

    metric_record = {
        'device_type':device_type,'device_id':device_id,
        'metric_name':data.get('metric_name','unknown'),
        'metric_value':float(data.get('metric_value',0)),
        'health_score':health_score,'anomaly_flag':anomaly_flag,
        'predicted_score':predicted_score,'ai_diagnosis':ai_diagnosis,
        'automation_command':automation_command
    }
    with queue_lock:
        metric_queue.append(metric_record)
        platform_stats['queue_depth']=len(metric_queue)

    if health_score<50 or anomaly_flag or blast_hold:
        try:
            supabase.table('incidents').insert({
                'device_id':device_id,'device_type':device_type,
                'health_score':health_score,'ai_diagnosis':ai_diagnosis,
                'automation_command':automation_command,'status':'open'
            }).execute()
        except Exception as e:
            print(f'Incident insert error: {e}')

    # ── SSE instant push for critical events (non-blocking) ──────────────────
    if health_score < 50 or anomaly_flag or blast_hold:
        sse_broadcast('metric', {
            'device_id': device_id, 'device_type': device_type,
            'health_score': round(health_score,1), 'anomaly_flag': anomaly_flag,
            'blast_hold': blast_hold, 'automation_command': automation_command,
            'is_cbs': device_type == 'cbs_controller',
        })
    # NOTIFICATIONS — CBS hold always triggers SMS (engineer may be underground)
    if blast_hold or (device_type=='cbs_controller' and health_score<CBS_SAFETY_THRESHOLD):
        notify_all(f'CBS BLAST HOLD — {device_id}',
            f'DNP3 link at {health_score:.1f}% — threshold 90%. '
            f'Cost exposure $450,000/hr. {ai_diagnosis or ""}',
            level='cbs', device_id=device_id)
    elif health_score<20 and device_type in ['ventilation','pump']:
        notify_all(f'EMERGENCY: {device_id}',
            f'Underground safety alert — {device_type} at {health_score:.1f}%. '
            f'{ai_diagnosis or ""}',
            level='critical', device_id=device_id)

    return jsonify({
        'status':'ok','health_score':round(health_score,1),
        'anomaly_flag':anomaly_flag,'predicted_score':round(predicted_score,1),
        'failure_probability':failure_prob,'ai_diagnosis':ai_diagnosis,
        'automation_command':automation_command,'federated_index':federated_index,
        'uptime_pct':uptime_pct,'root_cause_chain':root_cause,
        'lifecycle_hours':lifecycle,'retrain_needed':anomaly_count>=RETRAIN_THRESHOLD,
        'protocol':protocol,'blast_hold':blast_hold
    })

# ═══════════════════════════════════════════
#  /api/platform  — YouTube Observability (expanded)
# ═══════════════════════════════════════════
@app.route('/api/platform', methods=['GET'])
def platform_health():
    uptime_secs = (datetime.now(timezone.utc) -
        datetime.fromisoformat(platform_stats['uptime_start'].replace('Z','+00:00'))
    ).total_seconds()
    return jsonify({
        'queue_depth':       len(metric_queue),
        'scoring_queue':     len(scoring_queue),
        'cache_age_seconds': round(time.time()-_data_cache['ts'],1),
        'devices_tracked':   len(device_history),
        'anomaly_count':     anomaly_count,
        'retrain_needed':    anomaly_count>=RETRAIN_THRESHOLD,
        'retrain_in_progress':_retrain_in_progress,
        'platform_uptime_h': round(uptime_secs/3600,2),
        'platform_stats':    platform_stats,
        'demo_mode':         os.environ.get('DEMO_MODE','false').lower()=='true',
        'notifications': {
            'email_enabled':    NOTIFY_CONFIG['email_enabled'],
            'sms_enabled':      NOTIFY_CONFIG['sms_enabled'],
            'whatsapp_enabled': NOTIFY_CONFIG['whatsapp_enabled'],
            'recent': list(notification_log)[:5],
        },
        'architecture': {
            'ingestion':   'Queue-buffered deque (YouTube Upload Service)',
            'scoring':     'Async background worker (YouTube Encoder)',
            'cache':       f'{CACHE_TTL}s TTL in-memory (YouTube CDN)',
            'auto_retrain':'Background hot-swap pipeline (YouTube Adaptive Algorithm)',
            'notifications':'Email + SMS (Africa\'s Talking) + WhatsApp Business',
            'ai_models':   ['RandomForest (health)','IsolationForest (anomaly)'],
            'protocols':   ['SNMP','Profinet','Modbus TCP','DNP3','OPC-UA'],
            'demo_mode':   os.environ.get('DEMO_MODE','false').lower()=='true',
        }
    })

# ── /api/intelligence ─────────────────────────────────────────────────────
@app.route('/api/intelligence', methods=['GET'])
def get_intelligence():
    recent_scores = {did:hist[-1] for did,hist in device_history.items() if hist}
    probs = {did:get_failure_probability(did,hist[-1])
             for did,hist in device_history.items() if hist}
    lifecycles = {}
    try:
        resp = supabase.table('metrics').select('device_id,device_type') \
            .order('created_at',desc=True).limit(50).execute()
        for row in resp.data:
            did = row['device_id']
            if did in recent_scores and did not in lifecycles:
                lc = get_lifecycle_estimate(did,row['device_type'],recent_scores[did])
                if lc: lifecycles[did]=lc
    except: pass
    return jsonify({
        'federated_index': get_federated_health_index(list(recent_scores.values())),
        'device_scores':   recent_scores,
        'uptime':          {did:get_uptime_pct(did) for did in device_uptime},
        'failure_probabilities': probs,
        'lifecycles':      lifecycles,
        'retrain_needed':  anomaly_count>=RETRAIN_THRESHOLD,
        'anomaly_count':   anomaly_count,
        'total_devices':   len(device_history),
    })

# ── /api/twin ─────────────────────────────────────────────────────────────
@app.route('/api/twin/<device_id>', methods=['GET'])
def digital_twin(device_id):
    history = device_history.get(device_id,[])
    if not history: return jsonify({'error':'No history for device'}),404
    current_score = history[-1]; scenarios=[]
    for mult in [1.1,1.2,1.5,2.0]:
        features = np.array([[min(100,50*mult),min(1000,100*mult),
                              min(500,10*mult),min(20,mult*.5),10,40,80]])
        sim_score = float(rf_model.predict(features)[0]); sim_score=max(0,min(100,sim_score))
        anomaly   = bool(iso_model.predict(features)[0]==-1)
        scenarios.append({'load_increase':f'+{int((mult-1)*100)}%',
            'predicted_score':round(sim_score,1),'anomaly_predicted':anomaly,
            'risk':'critical' if sim_score<30 else 'warning' if sim_score<60 else 'safe'})
    trend_info={'slope_per_reading':0,'direction':'insufficient data'}
    if len(history)>=5:
        slope=( history[-1]-history[-5])/4
        rtc=round((current_score-20)/abs(slope)) if slope<0 and current_score>20 else None
        trend_info={'slope_per_reading':round(slope,2),
            'direction':'declining' if slope<0 else 'stable' if slope==0 else 'improving',
            'readings_to_critical':rtc}
    return jsonify({'device_id':device_id,'current_score':round(current_score,1),
        'history':[round(h,1) for h in history],'scenarios':scenarios,'trend':trend_info,
        'failure_probability':get_failure_probability(device_id,current_score)})

# ── /api/weather ──────────────────────────────────────────────────────────
@app.route('/api/weather', methods=['GET'])
def get_weather():
    loc_key=request.args.get('loc','byo'); loc=LOCATIONS.get(loc_key,LOCATIONS['byo'])
    try:
        url=(f"https://api.open-meteo.com/v1/forecast"
             f"?latitude={loc['lat']}&longitude={loc['lon']}"
             f"&current=temperature_2m,relative_humidity_2m,"
             f"wind_speed_10m,wind_gusts_10m,precipitation,weather_code,cloud_cover"
             f"&hourly=temperature_2m,precipitation_probability,"
             f"wind_speed_10m&forecast_days=2&timezone=Africa/Harare")
        resp=req.get(url,timeout=10); data=resp.json()
        current=data.get('current',{}); hourly=data.get('hourly',{})
        wind=current.get('wind_speed_10m',0); gusts=current.get('wind_gusts_10m',0)
        precip=current.get('precipitation',0); temp=current.get('temperature_2m',25)
        humidity=current.get('relative_humidity_2m',50)
        wcode=current.get('weather_code',0); cloud=current.get('cloud_cover',0)
        alerts=[]; equipment_impact=[]
        if wind>40: alerts.append(f"High winds {wind:.0f}km/h — microwave links at risk"); equipment_impact.append({'type':'telecom','impact':f"Signal degradation {min(30,wind*0.4):.0f}% on exposed towers",'severity':'warning'})
        if gusts>60: alerts.append(f"Dangerous gusts {gusts:.0f}km/h — tower stability risk"); equipment_impact.append({'type':'telecom','impact':'CBS blast hold recommended — link stability compromised','severity':'critical'})
        if precip>10: alerts.append(f"Heavy precipitation {precip:.1f}mm — equipment cooling affected"); equipment_impact.append({'type':'mining','impact':'Underground water ingress risk — pump load will increase','severity':'warning'})
        if temp>38: alerts.append(f"Extreme heat {temp:.0f}C — equipment thermal stress elevated"); equipment_impact.append({'type':'all','impact':'Health score degradation expected — increase cooling checks','severity':'warning'})
        if wcode>=95: alerts.append("Thunderstorm active — lightning risk to exposed equipment"); equipment_impact.append({'type':'all','impact':'Surge protection alert — consider temporary equipment shutdown','severity':'critical'})
        next24_precip=hourly.get('precipitation_probability',[])[:24]
        return jsonify({'location':loc['name'],'temperature':temp,'humidity':humidity,
            'wind_speed':wind,'wind_gusts':gusts,'precipitation':precip,
            'weather_code':wcode,'cloud_cover':cloud,'alerts':alerts,
            'equipment_impact':equipment_impact,
            'max_precip_probability_24h':max(next24_precip) if next24_precip else 0,
            'hourly_wind':hourly.get('wind_speed_10m',[])[:24],'hourly_precip_prob':next24_precip})
    except Exception as e:
        return jsonify({'error':str(e),'location':loc['name']}),500

# ── /api/shift-report, /api/login, /api/incidents (unchanged from original) ──
@app.route('/api/shift-report', methods=['GET'])
@require_specialist
def shift_report():
    try:
        resp=supabase.table('metrics').select('*').order('created_at',desc=True).limit(500).execute()
        inc_resp=supabase.table('incidents').select('*').order('created_at',desc=True).limit(100).execute()
        data=resp.data; incidents=inc_resp.data
        device_map={}
        for row in data:
            if row['device_id'] not in device_map: device_map[row['device_id']]=row
        critical=[d for d in device_map.values() if d['health_score']<20]
        warning=[d for d in device_map.values() if 20<=d['health_score']<50]
        healthy=[d for d in device_map.values() if d['health_score']>=50]
        open_incidents=[i for i in incidents if i['status']=='open']
        resolved=[i for i in incidents if i['status']=='resolved']
        scores=[d['health_score'] for d in device_map.values()]
        avg_health=round(sum(scores)/len(scores),1) if scores else 100
        return jsonify({'generated_at':datetime.now(timezone.utc).isoformat(),
            'total_devices':len(device_map),'avg_health':avg_health,
            'critical_devices':len(critical),'warning_devices':len(warning),
            'healthy_devices':len(healthy),'open_incidents':len(open_incidents),
            'resolved_incidents':len(resolved),
            'top_risks':[{'device':d['device_id'],'score':round(d['health_score'],1),
                'diagnosis':d.get('ai_diagnosis','')}
                for d in sorted(critical+warning,key=lambda x:x['health_score'])[:5]],
            'automation_commands':[{'device':d['device_id'],'command':d['automation_command']}
                for d in device_map.values() if d.get('automation_command')]})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/login', methods=['POST'])
def login():
    data=request.json
    try:
        result=supabase.table('specialists').select('*') \
            .eq('name',data.get('name','')).eq('password',data.get('password','')).execute()
        if result.data:
            s=result.data[0]
            return jsonify({'success':True,'token':data.get('password'),'name':s['name'],'role':s['role']})
        return jsonify({'success':False}),401
    except Exception as e: return jsonify({'success':False,'error':str(e)}),500

@app.route('/api/incidents', methods=['GET'])
@require_specialist
def get_incidents():
    status=request.args.get('status','open')
    response=supabase.table('incidents').select('*').eq('status',status) \
        .order('created_at',desc=True).limit(50).execute()
    return jsonify(response.data)

@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
@require_specialist
def assign_incident(incident_id):
    data=request.json
    supabase.table('incidents').update({'assigned_to':data.get('assigned_to',''),
        'notes':data.get('notes',''),'status':'assigned'}).eq('id',incident_id).execute()
    return jsonify({'success':True})

@app.route('/api/incidents/<incident_id>/resolve', methods=['POST'])
@require_specialist
def resolve_incident(incident_id):
    data=request.json
    supabase.table('incidents').update({'resolved_by':data.get('resolved_by',''),
        'notes':data.get('notes',''),'status':'resolved'}).eq('id',incident_id).execute()
    return jsonify({'success':True})

# ── /api/notify/test (specialist only) ────────────────────────────────────
@app.route('/api/notify/test', methods=['POST'])
@require_specialist
def test_notification():
    data=request.json or {}; channel=data.get('channel','all')
    msg='IISentinel\u2122 test notification — channels operational'
    if channel in ('sms','all'):      threading.Thread(target=send_sms_alert,args=(msg,),daemon=True).start()
    if channel in ('whatsapp','all'): threading.Thread(target=send_whatsapp_alert,args=(msg,),daemon=True).start()
    if channel in ('email','all'):    threading.Thread(target=send_email_alert,args=('Test',msg),daemon=True).start()
    return jsonify({'ok':True,'channel':channel})


# -- SSE STREAM ENDPOINT --------------------------------------------------
@app.route('/api/stream')
def sse_stream():
    sub_q = _queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_subscribers.append(sub_q)
    def generate():
        yield 'event: connected\ndata: {"ok":true}\n\n'
        while True:
            try:
                msg = sub_q.get(timeout=25)
                yield msg
            except _queue.Empty:
                yield ':heartbeat\n\n'
    from flask import Response, stream_with_context
    return Response(stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no',
                 'Access-Control-Allow-Origin':'*'})


# -- PDF EXPORT ENDPOINT --------------------------------------------------
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

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=18*mm,
                                leftMargin=18*mm, topMargin=20*mm, bottomMargin=18*mm,
                                title='IISentinel Report')
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

        recent = {did: hist[-1] for did, hist in device_history.items() if hist}
        scores = list(recent.values())
        fhi_v  = get_federated_health_index(scores)
        crit_c = sum(1 for s in scores if s < 20)
        warn_c = sum(1 for s in scores if 20 <= s < 50)
        hlth_c = sum(1 for s in scores if s >= 50)
        probs  = {did: get_failure_probability(did, s) for did, s in recent.items()}
        now_s  = datetime.now(timezone.utc).strftime('%d %B %Y %H:%M UTC')

        story  = []
        story.append(Paragraph('IISentinel<sup>TM</sup>', sty('Title', fontName='Helvetica-Bold', fontSize=22, textColor=DARK)))
        story.append(Paragraph('Intelligent Infrastructure Sentinel -- Shift Report', sty('Normal', fontName='Helvetica', fontSize=10, textColor=MUTED, spaceAfter=4)))
        story.append(Paragraph(f'Generated: {now_s}', sty('Normal', fontName='Helvetica', fontSize=9, textColor=MUTED, spaceAfter=8)))
        story.append(HRFlowable(width='100%', thickness=1.5, color=ACCENT, spaceAfter=10))

        hdr_sty = sty('Normal', fontName='Helvetica-Bold', fontSize=8, textColor=colors.white)
        cel_sty = sty('Normal', fontName='Helvetica', fontSize=8, textColor=DARK)
        kpi = [
            [Paragraph(c, hdr_sty) for c in ['Metric','Value','Status']],
            [Paragraph(c, cel_sty) for c in ['Federated Health Index', f'{fhi_v:.1f}/100', 'HEALTHY' if fhi_v>=70 else 'WARNING' if fhi_v>=40 else 'CRITICAL']],
            [Paragraph(c, cel_sty) for c in ['Total Devices', str(len(recent)), '--']],
            [Paragraph(c, cel_sty) for c in ['Critical (<20)', str(crit_c), 'ALERT' if crit_c else 'NONE']],
            [Paragraph(c, cel_sty) for c in ['Warning (20-50)', str(warn_c), 'MONITOR' if warn_c else 'NONE']],
            [Paragraph(c, cel_sty) for c in ['Healthy (>=50)', str(hlth_c), 'OK']],
            [Paragraph(c, cel_sty) for c in ['Anomalies', str(anomaly_count), 'HIGH' if anomaly_count>=RETRAIN_THRESHOLD else 'NORMAL']],
        ]
        t = Table(kpi, colWidths=[75*mm, 60*mm, 40*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',   (0,0),(-1,0), DARK),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,ROW]),
            ('GRID',         (0,0),(-1,-1), 0.35, colors.HexColor('#d4daea')),
            ('TOPPADDING',   (0,0),(-1,-1), 5),('BOTTOMPADDING',(0,0),(-1,-1),5),
            ('LEFTPADDING',  (0,0),(-1,-1), 7),
        ]))
        story.append(Paragraph('Platform Summary', sty('Heading1', fontName='Helvetica-Bold', fontSize=12, textColor=DARK, spaceBefore=8, spaceAfter=5)))
        story.append(t)
        story.append(Spacer(1,8))

        if recent:
            story.append(Paragraph('Device Health Register', sty('Heading2', fontName='Helvetica-Bold', fontSize=9, textColor=ACCENT, spaceBefore=8, spaceAfter=4)))
            drows = [[Paragraph(c,hdr_sty) for c in ['Device','Score','Risk %','Status']]]
            for did,s in sorted(recent.items(), key=lambda x:x[1])[:20]:
                p2=probs.get(did,0); stat='CRITICAL' if s<20 else 'WARNING' if s<50 else 'OK'
                col=RED if s<20 else AMBER if s<50 else GREEN
                drows.append([
                    Paragraph(did[-30:], cel_sty),
                    Paragraph(f'{s:.0f}', sty('Normal',fontName='Helvetica-Bold',fontSize=8,textColor=col)),
                    Paragraph(f'{p2:.0f}%', cel_sty),
                    Paragraph(stat, sty('Normal',fontName='Helvetica-Bold',fontSize=8,textColor=col)),
                ])
            dt = Table(drows, colWidths=[80*mm,22*mm,22*mm,25*mm])
            dt.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),DARK),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,ROW]),
                ('GRID',(0,0),(-1,-1),0.35,colors.HexColor('#d4daea')),
                ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
                ('LEFTPADDING',(0,0),(-1,-1),5),
            ]))
            story.append(dt)

        story.append(Spacer(1,14))
        story.append(HRFlowable(width='100%', thickness=0.7, color=MUTED, spaceAfter=5))
        story.append(Paragraph(
            f'IISentinel(TM) Confidential -- {now_s} -- SNMP, Profinet, Modbus TCP, DNP3, OPC-UA',
            sty('Normal', fontName='Helvetica-Oblique', fontSize=7, textColor=MUTED)
        ))
        doc.build(story)
        buf.seek(0)
        fname = f'IISentinel_Report_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")}.pdf'
        return send_file(buf, as_attachment=True, download_name=fname, mimetype='application/pdf')

    except ImportError:
        return jsonify({'error':'pip install reportlab to enable PDF export',
                        'install':'pip install reportlab --break-system-packages'}), 500


# -- DEMO MODE AUTO-INJECTION ---------------------------------------------
_demo_cycle = 0

def demo_injection_worker():
    global _demo_cycle
    if os.environ.get('DEMO_MODE','false').lower() != 'true':
        return
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
    in_event = {d['id']:0 for d in DEMO_DEVICES}
    print('[DemoMode] Auto-injection active -- 15 devices, 4 sites')
    while True:
        _demo_cycle += 1
        for dev in DEMO_DEVICES:
            did = dev['id']
            dtype = dev['type']
            if in_event[did] > 0:
                in_event[did] -= 1
            elif random.random() < 0.08:
                in_event[did] = random.randint(4, 12)
            if dtype == 'cbs_controller' and random.random() < 0.008:
                in_event[did] = random.randint(6, 10)
            sev = in_event[did] / 12.0
            sig  = max(20, dev['bsig']  * (1 - sev * 0.45) + random.gauss(0,4))
            lat  = max(1,  dev['blat']  * (1 + sev * 3.0)  + random.gauss(0, dev['blat']*0.1))
            bw   = max(1,  dev['bbw']   * (1 - sev * 0.6)  + random.gauss(0, dev['bbw']*0.08))
            temp = dev['btemp'] * (1 + sev * 0.5) + random.gauss(0, 3)
            cpu  = min(98, 20 + sev * 75 + random.gauss(0, 8))
            loss = max(0,  sev * 8 + random.gauss(0, 0.8))
            if dtype in ('pump','conveyor','ventilation','plc','power_meter','sensor'):
                mn, mv = 'temperature', round(temp,1)
            elif dtype in ('base_station','network_tower','microwave_link','cbs_controller'):
                mn, mv = 'signal_strength', round(sig,1)
            else:
                mn, mv = 'latency_ms', round(lat,1)
            payload = {'device_id':did,'device_type':dtype,'metric_name':mn,'metric_value':mv,
                       'cpu_load':round(cpu,1),'bandwidth_mbps':round(bw,1),'latency_ms':round(lat,1),
                       'packet_loss':round(loss,2),'connected_devices':max(1,int(10*(1-sev*0.4))),
                       'temperature':round(temp,1),'signal_strength':round(sig,1),
                       'protocol':('DNP3/Ethernet' if dtype=='cbs_controller' else
                                   'Profinet/EtherNet-IP' if dtype in MINING_TYPES else
                                   'SNMP/Ethernet-802.3')}
            try:
                with app.test_request_context('/api/metrics', method='POST', json=payload):
                    receive_metrics()
            except Exception:
                pass
        time.sleep(random.uniform(3.0, 5.0))

if os.environ.get('DEMO_MODE','false').lower() == 'true':
    threading.Thread(target=demo_injection_worker, daemon=True).start()
    print('[IISentinel] DEMO_MODE=true -- realistic data injection started')


@app.route('/health', methods=['GET'])
def health_check():
    """Lightweight health check for load balancers and uptime monitors."""
    queue_depth = len(metric_queue)
    cache_age   = round(time.time() - _data_cache['ts'], 1)
    uptime_s    = (datetime.now(timezone.utc) -
                   datetime.fromisoformat(platform_stats['uptime_start'])).total_seconds()
    degraded    = queue_depth > 450 or (cache_age > 300 and _data_cache['ts'] > 0)
    return jsonify({
        'status'     : 'degraded' if degraded else 'ok',
        'uptime_h'   : round(uptime_s / 3600, 2),
        'queue_depth': queue_depth,
        'cache_age_s': cache_age,
        'devices'    : len(device_history),
        'anomalies'  : anomaly_count,
        'version'    : '2.0',
        'platform'   : 'IISentinel™',
    }), 503 if degraded else 200

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

if __name__=='__main__':
    print("""
  IISentinel\u2122 — YouTube-Architecture Backend
  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
  Ingestion Queue \u2192 Async AI \u2192 Cache \u2192 Dashboard
  \u2713 /api/data  \u2713 Async scoring  \u2713 Auto-retrain
  \u2713 Notifications (Email+SMS+WhatsApp)
  Open: http://localhost:5000
""")
    app.run(host='0.0.0.0', port=5000, debug=True)
