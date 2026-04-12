import os, joblib, numpy as np, requests as req, threading, time, re, json, smtplib
from flask import Flask, request, jsonify, render_template, Response, stream_with_context
from flask_cors import CORS
from supabase import create_client
from functools import wraps
from datetime import datetime, timezone
from collections import deque
from email.mime.text import MIMEText


# ─────────────────────────────────────────────────────────────────────────
# A — REGEX PATTERN LIBRARY (single source of truth)
# ─────────────────────────────────────────────────────────────────────────
import re as _re
PATTERNS = {
    "LINK_STATE":      _re.compile(r"Interface\s([\w\/\.]+),\schanged state to\s(\w+)"),
    "BGP_NOTIFY":      _re.compile(r"BGP-(\d+)-NOTIFICATION:\s(.+)\sfrom\s([\d.]+)"),
    "SIGNAL_DBM":      _re.compile(r"Rx level[:\s]+([-\d.]+)\s*dBm", _re.I),
    "MODBUS_EX":       _re.compile(r"Modbus Exception.*?0x([0-9A-Fa-f]{2})"),
    "CONVEYOR_TRIP":   _re.compile(r"Conveyor\s([\w-]+)\strip(?:ped)?", _re.I),
    "PUMP_CAVITATION": _re.compile(r"pump\s([\w-]+)\s(?:cavitat|pressure\sdrop)", _re.I),
    "CBS_HOLD":        _re.compile(r"^CBS-HOLD:\s(SHAFT-[12]|SURFACE)\s@\s(\d{2}:\d{2}:\d{2})$"),
    "CBS_CLEAR":       _re.compile(r"^CBS-CLEAR:\s(SHAFT-[12]|SURFACE)\s@\s(\d{2}:\d{2}:\d{2})$"),
    "SCRIPT_INJECT":   _re.compile(r"<script|javascript:", _re.I),
    "SQL_INJECT":      _re.compile(r"(\bDROP\b|\bDELETE\b|\bUNION\b)[\s\S]*?\bTABLE\b", _re.I),
    "PATH_TRAVERSAL":  _re.compile(r"\.\./|\.\.\\ |%2e%2e", _re.I),
}

def parse_log(raw, source="api"):
    base = {"raw":raw,"source":source,"parsed":None,"severity":"info","ts":datetime.now(timezone.utc).isoformat()}
    for pname, sev, build in [
        ("LINK_STATE",  "critical" if True else "info", lambda m: {"type":"LINK_STATE","iface":m.group(1),"state":m.group(2)}),
        ("MODBUS_EX",   "warning",                      lambda m: {"type":"MODBUS_EX","code":m.group(1)}),
        ("CONVEYOR_TRIP","critical",                    lambda m: {"type":"CONVEYOR_TRIP","unit":m.group(1)}),
        ("PUMP_CAVITATION","warning",                   lambda m: {"type":"PUMP_CAVITATION","unit":m.group(1)}),
    ]:
        m = PATTERNS[pname].search(raw)
        if m:
            ev = {"type":pname}
            try: ev.update(build(m))
            except: pass
            return {**base,"parsed":ev,"severity":sev}
    return base

def tag_incident(text):
    tags=[]
    if _re.search(r"pump|motor|bearing|vibrat",text,_re.I): tags.append("MECHANICAL")
    if _re.search(r"conveyor|belt|chute",text,_re.I): tags.append("CONVEYOR")
    if _re.search(r"ventilat|fan|airflow",text,_re.I): tags.append("VENTILATION")
    if _re.search(r"shaft[-\s]?1",text,_re.I): tags.append("SHAFT-1")
    if _re.search(r"shaft[-\s]?2",text,_re.I): tags.append("SHAFT-2")
    if _re.search(r"network|router|switch|bgp",text,_re.I): tags.append("NETWORK")
    if _re.search(r"signal|tower|base.?station|mw",text,_re.I): tags.append("TELECOM")
    return tags

_dedup_seen, _dedup_lock = {}, threading.Lock()
DEDUP_WINDOW = 30

def is_new_alert(raw):
    fp = ((_re.search(r"Interface\s[\w\/]+|CBS-\w+|Conveyor\s[\w-]+|pump\s[\w-]+",raw,_re.I) or type("",(),{"group":lambda s,n:raw[:48]})()).group(0) if raw else raw[:48]).lower()
    now = time.time()
    with _dedup_lock:
        if fp in _dedup_seen and now - _dedup_seen[fp] < DEDUP_WINDOW: return False
        _dedup_seen[fp] = now
        for k in [k for k,v in _dedup_seen.items() if now-v > DEDUP_WINDOW*2]: del _dedup_seen[k]
    return True

def handle_cbs_message(raw):
    is_hold = bool(PATTERNS["CBS_HOLD"].match(raw))
    is_clear = bool(PATTERNS["CBS_CLEAR"].match(raw))
    if not is_hold and not is_clear:
        return {"action":"HOLD","reason":"format_validation_failed","validated":False}
    m = (PATTERNS["CBS_HOLD"] if is_hold else PATTERNS["CBS_CLEAR"]).match(raw)
    return {"action":"HOLD" if is_hold else "CLEAR","section":m.group(1),"time":m.group(2),"validated":True}

# ─────────────────────────────────────────────────────────────────────────
# D — BEHAVIOUR SCORING
# ─────────────────────────────────────────────────────────────────────────
_behaviour_events = {}
_behaviour_scores = {}

def record_behaviour_event(device_id, health_score, anomaly_flag, was_critical):
    if device_id not in _behaviour_events:
        _behaviour_events[device_id] = {"anomaly_count":0,"breach_count":0,"recovery_count":0,"readings":0,"last_score":health_score}
    ev = _behaviour_events[device_id]
    ev["readings"] += 1
    if anomaly_flag: ev["anomaly_count"] += 1
    if health_score < 50: ev["breach_count"] += 1
    if ev["last_score"] < 20 and health_score >= 50: ev["recovery_count"] += 1
    ev["last_score"] = health_score

def score_behaviour(device_id):
    ev = _behaviour_events.get(device_id)
    if not ev or ev["readings"] < 3: return {"score":None,"grade":"?","reason":"Insufficient readings"}
    n = max(ev["readings"],1)
    ar = ev["anomaly_count"]/n; br = ev["breach_count"]/n
    rp = max(0, ev["breach_count"] - ev["recovery_count"]) / max(n,1)
    score = round(max(0, min(100, 100 - ar*30 - br*30 - rp*20 - (0 if ev["recovery_count"]>0 else 10))))
    grade = "A" if score>=90 else "B" if score>=75 else "C" if score>=55 else "D" if score>=35 else "F"
    result = {"score":score,"grade":grade,"anomaly_rate":round(ar*100,1),"breach_rate":round(br*100,1),"recoveries":ev["recovery_count"],"total_readings":ev["readings"]}
    _behaviour_scores[device_id] = {**result,"updated_at":datetime.now(timezone.utc).isoformat()}
    return result

DEVICE_MTBF = {"pump":8760,"conveyor":17520,"ventilation":26280,"plc":52560,"router":43800,"switch":43800,"base_station":35040,"network_tower":43800,"firewall":35000,"scada_node":26280,"power_meter":17520,"sensor":8760,"microwave_link":26280,"cbs_controller":52560,"wan_link":35000}

def predict_next_maintenance(device_id, device_type, health_score):
    beh = score_behaviour(device_id); b_score = beh.get("score") or 75
    mtbf = DEVICE_MTBF.get(device_type, 26280)
    hrs_run = _behaviour_events.get(device_id, {}).get("readings",0) * (10/60)
    adj_mtbf = mtbf * (1 - (b_score/100)*0.4)
    hrs_rem = max(0, (adj_mtbf - hrs_run) * (1 - (health_score/100)*0.5))
    priority = "urgent" if hrs_rem<72 else "scheduled" if hrs_rem<240 else "routine"
    return {"device_id":device_id,"device_type":device_type,"hours_remaining":round(hrs_rem),"priority":priority,"behaviour_score":b_score,"behaviour_grade":beh.get("grade","?")}

# ─────────────────────────────────────────────────────────────────────────
# E — TENANT CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────
TENANTS = {
    "default":      {"name":"IISentinel — Full Platform","sectors":["network","telecom","mining","cbs","weather","intelligence"],"protocols":["SNMP","Profinet","Modbus TCP","DNP3","OPC-UA"],"cbs_mandatory":True},
    "telecom-only": {"name":"TelecomCo Monitor","sectors":["telecom","weather","intelligence"],"protocols":["SNMP","LTE","MW_backhaul"],"cbs_mandatory":False},
    "mining-only":  {"name":"MiningCo Safety Platform","sectors":["mining","cbs","weather","intelligence"],"protocols":["Profinet","Modbus TCP","OPC-UA","EtherNet/IP","DNP3"],"cbs_mandatory":True,"blast_cost_usd":500000},
    "network-only": {"name":"Network / ISP Monitor","sectors":["network","weather","intelligence"],"protocols":["SNMP v3","BGP","OSPF","NetFlow","ICMP"],"cbs_mandatory":False},
}
ACTIVE_TENANT = os.environ.get("TENANT","default")

# ─────────────────────────────────────────────────────────────────────────
# F — EVENT ARCHIVE
# ─────────────────────────────────────────────────────────────────────────
_archive_buffer, _archive_lock2 = deque(maxlen=200), threading.Lock()

def archive_event(event, tenant_id="default"):
    record = {"tenant_id":tenant_id,"source":event.get("source","unknown"),"event_type":event.get("parsed",{}).get("type","raw") if event.get("parsed") else "raw","severity":event.get("severity","info"),"device_id":event.get("source",""),"raw":str(event.get("raw",""))[:500],"parsed":json.dumps(event.get("parsed") or {}),"ts":event.get("ts",datetime.now(timezone.utc).isoformat())}
    with _archive_lock2: _archive_buffer.append(record)

def _flush_archive():
    while True:
        time.sleep(10)
        with _archive_lock2:
            if not _archive_buffer: continue
            batch=list(_archive_buffer); _archive_buffer.clear()
        try:
            for r in batch: supabase.table("event_archive").insert(r).execute()
        except Exception as e:
            print(f"[Archive] {e}")
            with _archive_lock2:
                for r in batch[:50]: _archive_buffer.appendleft(r)

threading.Thread(target=_flush_archive, daemon=True).start()

# ─────────────────────────────────────────────────────────────────────────
# H — PRICING
# ─────────────────────────────────────────────────────────────────────────
PRICING = {
    "network-only": {"model":"per_device","monthly_usd":{"min":15,"max":30},"billing_unit":"device","roi_example":"Avg 73% reduction in MTTR"},
    "telecom-only": {"model":"per_site","monthly_usd":{"min":200,"max":500},"billing_unit":"tower site","roi_example":"Avg $12,000/hr prevented per outage"},
    "mining-only":  {"model":"per_site","monthly_usd":{"min":2000,"max":5000},"billing_unit":"mine site","safety_surcharge":True,"roi_example":"$500,000+ protected per CBS event"},
    "default":      {"model":"enterprise_annual","annual_usd":{"min":60000,"max":200000},"billing_unit":"site licence","roi_example":"Full-stack infrastructure intelligence"},
}


app = Flask(__name__, template_folder='templates')
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel2026')

# ── SUPABASE ──────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
try:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print('[OK] Supabase connected')
except Exception as e:
    print(f'[WARN] Supabase: {e}')
    supabase = None

# ── AI MODELS (auto-generate if missing) ─────────────────────────────────
def generate_models():
    print('[IISentinel] Generating AI models...')
    from sklearn.ensemble import RandomForestRegressor, IsolationForest
    from sklearn.preprocessing import StandardScaler
    np.random.seed(42)
    N = 2000
    X = np.column_stack([
        np.random.uniform(5, 95, N),
        np.random.uniform(10, 900, N),
        np.random.uniform(1, 400, N),
        np.random.uniform(0, 15, N),
        np.random.uniform(1, 500, N),
        np.random.uniform(20, 90, N),
        np.random.uniform(20, 100, N),
    ])
    y = np.clip(100 - X[:,0]*0.3 - X[:,2]*0.08 - X[:,3]*2.5 + X[:,6]*0.15 + np.random.normal(0,5,N), 0, 100)
    sc = StandardScaler()
    Xs = sc.fit_transform(X)
    rf = RandomForestRegressor(n_estimators=50, random_state=42)
    rf.fit(Xs, y)
    iso = IsolationForest(contamination=0.1, random_state=42)
    iso.fit(Xs[y > 50])
    joblib.dump(rf, 'health_model.pkl')
    joblib.dump(iso, 'anomaly_model.pkl')
    joblib.dump(sc, 'scaler.pkl')
    print('[OK] Models generated')
    return rf, iso, sc

try:
    rf_model  = joblib.load('health_model.pkl')
    iso_model = joblib.load('anomaly_model.pkl')
    scaler    = joblib.load('scaler.pkl')
    print('[OK] Models loaded')
except FileNotFoundError:
    rf_model, iso_model, scaler = generate_models()

# ── STATE ─────────────────────────────────────────────────────────────────
device_history = {}
device_uptime  = {}
anomaly_count  = 0
reading_window = []
RETRAIN_THRESHOLD    = 50
CBS_SAFETY_THRESHOLD = 90.0

metric_queue = deque(maxlen=500)
queue_lock   = threading.Lock()
_data_cache  = {'data': [], 'ts': 0}
CACHE_TTL    = 8

_sse_subs = []
_sse_lock = threading.Lock()

platform_stats = {
    'requests_total': 0,
    'uptime_start': datetime.now(timezone.utc).isoformat(),
}

# ── NOTIFICATIONS ─────────────────────────────────────────────────────────
NOTIFY_EMAIL    = os.environ.get('NOTIFY_EMAIL_ENABLED', 'false').lower() == 'true'
NOTIFY_SMS      = os.environ.get('NOTIFY_SMS_ENABLED',   'false').lower() == 'true'
NOTIFY_WHATSAPP = os.environ.get('NOTIFY_WHATSAPP_ENABLED', 'false').lower() == 'true'

def send_email(subject, body):
    if not NOTIFY_EMAIL: return
    try:
        msg = MIMEText(body)
        msg['Subject'] = f'[IISentinel] {subject}'
        msg['From'] = os.environ.get('NOTIFY_FROM', '')
        msg['To']   = os.environ.get('NOTIFY_TO', '')
        with smtplib.SMTP(os.environ.get('SMTP_HOST','smtp.gmail.com'),
                          int(os.environ.get('SMTP_PORT','587'))) as s:
            s.starttls()
            s.login(os.environ.get('SMTP_USER',''), os.environ.get('SMTP_PASS',''))
            s.send_message(msg)
    except Exception as e:
        print(f'Email error: {e}')

def notify_all(subject, message, level='critical', device_id=None):
    threading.Thread(target=send_email, args=(subject, message), daemon=True).start()
    if NOTIFY_SMS:
        try:
            req.post('https://api.africastalking.com/version1/messaging',
                headers={'apiKey': os.environ.get('AT_API_KEY',''), 'Accept':'application/json'},
                data={'username': os.environ.get('AT_USERNAME',''),
                      'to': os.environ.get('NOTIFY_SMS',''),
                      'message': f'IISentinel: {subject} {message[:100]}'}, timeout=8)
        except Exception as e:
            print(f'SMS error: {e}')

# ── BACKGROUND THREADS ────────────────────────────────────────────────────
def flush_queue():
    while True:
        time.sleep(3)
        with queue_lock:
            if not metric_queue: continue
            batch = list(metric_queue)
            metric_queue.clear()
        if not supabase: continue
        try:
            for item in batch:
                supabase.table('metrics').insert(item).execute()
            _data_cache['ts'] = 0
        except Exception as e:
            print(f'Flush error: {e}')
            with queue_lock:
                for item in batch[:50]:
                    metric_queue.appendleft(item)

threading.Thread(target=flush_queue, daemon=True).start()

def sse_broadcast(event_type, payload):
    msg = f'event: {event_type}\ndata: {json.dumps(payload)}\n\n'
    with _sse_lock:
        dead = []
        for q in _sse_subs:
            try: q.put_nowait(msg)
            except: dead.append(q)
        for q in dead: _sse_subs.remove(q)

# ── HELPERS ───────────────────────────────────────────────────────────────
def get_cached_data():
    now = time.time()
    if now - _data_cache['ts'] < CACHE_TTL and _data_cache['data']:
        return _data_cache['data']
    if not supabase:
        return _data_cache['data']
    try:
        resp = supabase.table('metrics').select('*').order('created_at', desc=True).limit(200).execute()
        _data_cache['data'] = resp.data
        _data_cache['ts']   = now
        return resp.data
    except Exception as e:
        print(f'Cache error: {e}')
        return _data_cache['data']

def fhi(scores):
    if not scores: return 100.0
    w = [s*0.5 if s < 20 else s*0.8 if s < 50 else s for s in scores]
    return round(sum(w)/len(w), 1)

def failure_prob(device_id, score):
    h = device_history.get(device_id, [])
    if len(h) < 3: return 0.0
    trend = h[-1] - h[0]
    if trend >= 0: return max(0.0, round((100-score)*0.05, 1))
    return min(99.0, round(abs(trend)/len(h)*3 + (100-score)*0.3, 1))

def update_uptime(device_id, score):
    if device_id not in device_uptime:
        device_uptime[device_id] = {'total': 0, 'healthy': 0}
    device_uptime[device_id]['total'] += 1
    if score >= 50: device_uptime[device_id]['healthy'] += 1

def get_uptime(device_id):
    d = device_uptime.get(device_id, {'total':0,'healthy':0})
    return 100.0 if not d['total'] else round(d['healthy']/d['total']*100, 1)

def sanitize(data):
    if not isinstance(data, dict): return {}, 'Not JSON'
    for f in ['device_id', 'device_type']:
        if not data.get(f): return {}, f'Missing {f}'
    did = str(data.get('device_id',''))
    if not re.match(r'^[a-zA-Z0-9_-]{1,80}$', did): return {}, 'Bad device_id'
    cleaned = dict(data)
    cleaned['device_id'] = did
    BOUNDS = {'cpu_load':(0,100),'bandwidth_mbps':(0,100000),'latency_ms':(0,60000),
              'packet_loss':(0,100),'connected_devices':(0,100000),
              'temperature':(-50,200),'signal_strength':(0,100),'metric_value':(-1e9,1e9)}
    for field,(lo,hi) in BOUNDS.items():
        if field in cleaned:
            try: cleaned[field] = float(max(lo, min(hi, float(cleaned[field]))))
            except: cleaned[field] = (lo+hi)/2
    return cleaned, None

def require_specialist(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Specialist-Token')
        if not token: return jsonify({'error':'Unauthorised'}), 401
        if not supabase: return jsonify({'error':'No DB'}), 503
        try:
            result = supabase.table('specialists').select('*').eq('password', token).execute()
            if not result.data: return jsonify({'error':'Invalid token'}), 401
        except: return jsonify({'error':'Auth error'}), 401
        return f(*args, **kwargs)
    return decorated

LOCATIONS = {
    'byo':  {'lat':-20.15,'lon':28.58,'name':'Bulawayo'},
    'hre':  {'lat':-17.82,'lon':31.05,'name':'Harare'},
    'mut':  {'lat':-18.97,'lon':32.67,'name':'Mutare'},
    'mine': {'lat':-17.65,'lon':29.85,'name':'Mine Site'},
}

COST_RATES = {
    'pump':150000,'conveyor':120000,'ventilation':180000,'plc':80000,
    'scada_node':60000,'cbs_controller':450000,'power_meter':100000,
    'sensor':40000,'base_station':25000,'network_tower':35000,
    'microwave_link':40000,'router':15000,'switch':10000,'firewall':20000,
    'wan_link':12000,'workstation':2000,
}

NETWORK_TYPES = ['router','switch','firewall','wan_link','workstation']
TELECOM_TYPES = ['base_station','network_tower','microwave_link']
MINING_TYPES  = ['pump','conveyor','ventilation','power_meter','sensor','plc','scada_node']

def get_diagnosis(device_type, protocol, metric_name, metric_value, health_score, anomaly):
    issues, actions = [], []
    if health_score < 20:   issues.append('critical failure'); actions.append('immediate intervention required')
    elif health_score < 35: issues.append('severe degradation'); actions.append('escalate to ops team')
    elif health_score < 50: issues.append('moderate degradation'); actions.append('schedule maintenance 24h')
    if device_type in TELECOM_TYPES or device_type in NETWORK_TYPES:
        if 'latency' in metric_name and metric_value > 100: issues.append(f'latency {metric_value:.1f}ms')
        if 'packet' in metric_name and metric_value > 2: issues.append(f'packet loss {metric_value:.1f}%')
        if 'signal' in metric_name and metric_value < 40: issues.append(f'signal {metric_value:.1f}%')
    elif device_type in MINING_TYPES:
        if 'temperature' in metric_name and metric_value > 75: issues.append(f'temp {metric_value:.1f}C')
    elif device_type == 'cbs_controller':
        if health_score < CBS_SAFETY_THRESHOLD: issues.append(f'CBS DNP3 link {health_score:.1f}% below threshold')
    if anomaly: issues.append('Isolation Forest anomaly')
    if not issues: return f'Device OK via {protocol}. Health {health_score:.1f}/100.'
    return f'{"; ".join(issues).capitalize()}. Actions: {"; ".join(actions).capitalize()}.'

def get_command(device_id, device_type, health_score, blast_hold=False):
    if device_type == 'cbs_controller' and health_score < CBS_SAFETY_THRESHOLD:
        return f'CBS SAFETY INTERLOCK: BLAST HOLD on {device_id} — link {health_score:.1f}%'
    if health_score < 20: return f'CRITICAL: Emergency restart {device_id}'
    if health_score < 35: return f'WARNING: Isolate {device_id}'
    if health_score < 50: return f'CAUTION: Schedule maintenance {device_id}'
    return None

# ── ROUTES ────────────────────────────────────────────────────────────────

@app.route('/api/behaviour')
def get_behaviour():
    scores = {}
    for did in device_history:
        r = score_behaviour(did)
        if r.get('score') is not None: scores[did] = r
    ranked = sorted(scores.items(), key=lambda x: x[1]['score'])
    return jsonify({'total':len(scores),'ranked':[{'device_id':k,**v} for k,v in ranked],'f_grade':[k for k,v in ranked if v['grade']=='F']})

@app.route('/api/maintenance')
def get_maintenance():
    schedule = []
    recent = {did: hist[-1] for did, hist in device_history.items() if hist}
    type_map = {}
    try:
        resp = supabase.table('metrics').select('device_id,device_type').order('created_at',desc=True).limit(100).execute()
        for row in resp.data: type_map[row['device_id']] = row['device_type']
    except: pass
    for did, score in recent.items():
        schedule.append(predict_next_maintenance(did, type_map.get(did,'sensor'), score))
    schedule.sort(key=lambda x: x['hours_remaining'])
    urgent=[s for s in schedule if s['priority']=='urgent']
    sched=[s for s in schedule if s['priority']=='scheduled']
    routine=[s for s in schedule if s['priority']=='routine']
    return jsonify({'total':len(schedule),'urgent':urgent,'scheduled':sched,'routine':routine,'summary':{'urgent_count':len(urgent),'scheduled_count':len(sched),'routine_count':len(routine)}})

@app.route('/api/tenant')
def get_tenant():
    cfg = TENANTS.get(ACTIVE_TENANT, TENANTS['default'])
    return jsonify({'tenant_key':ACTIVE_TENANT,'config':cfg,'all_tenants':list(TENANTS.keys())})

@app.route('/api/archive')
def get_archive():
    tenant_id=request.args.get('tenant',ACTIVE_TENANT)
    source=request.args.get('source')
    limit=min(int(request.args.get('limit','100')),500)
    try:
        q=supabase.table('event_archive').select('*').eq('tenant_id',tenant_id).order('ts',desc=True).limit(limit)
        if source: q=q.ilike('source',f'%{source}%')
        resp=q.execute()
        return jsonify({'tenant_id':tenant_id,'total':len(resp.data or []),'results':resp.data or []})
    except Exception as e:
        return jsonify({'error':str(e)})

@app.route('/api/pricing')
def get_pricing():
    key=request.args.get('tenant',ACTIVE_TENANT)
    p=PRICING.get(key,PRICING['default'])
    devices=len(device_history)
    if p['model']=='per_device' and devices>0: quote={'monthly_usd':devices*p['monthly_usd']['min'],'annual_usd':devices*p['monthly_usd']['min']*12,'devices':devices}
    elif p['model']=='per_site': quote={'monthly_usd':p['monthly_usd']['min'],'annual_usd':p['monthly_usd']['min']*12}
    else: quote={'annual_usd':p.get('annual_usd',{}).get('min',60000)}
    return jsonify({'tenant_key':key,'pricing':p,'live_quote':quote,'all_tiers':PRICING})


@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/data')
def get_data():
    return jsonify(get_cached_data())

@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    global anomaly_count
    platform_stats['requests_total'] += 1
    raw = request.json
    if not raw: return jsonify({'error':'Empty'}), 400
    data, err = sanitize(raw)
    if err: return jsonify({'error':err}), 400

    device_id   = data.get('device_id','unknown')
    device_type = data.get('device_type','unknown')
    protocol    = data.get('protocol','Ethernet')
    blast_hold  = data.get('blast_hold', False)

    features = np.array([[
        data.get('cpu_load',50), data.get('bandwidth_mbps',100),
        data.get('latency_ms',10), data.get('packet_loss',0),
        data.get('connected_devices',10), data.get('temperature',40),
        data.get('signal_strength',80)
    ]])

    try: fs = scaler.transform(features)
    except: fs = features

    health_score = float(rf_model.predict(fs)[0])
    health_score = max(0, min(100, health_score))
    if device_type == 'cbs_controller':
        health_score = min(health_score, data.get('signal_strength', 100))

    try: anomaly_flag = bool(iso_model.predict(fs)[0] == -1)
    except: anomaly_flag = False
    if anomaly_flag: anomaly_count += 1

    if device_id not in device_history: device_history[device_id] = []
    device_history[device_id].append(health_score)
    if len(device_history[device_id]) > 20: device_history[device_id].pop(0)

    reading_window.append(health_score)
    if len(reading_window) > 10: reading_window.pop(0)
    predicted = max(0, min(100, health_score + (reading_window[-1]-reading_window[0]))) if len(reading_window) >= 3 else health_score

    update_uptime(device_id, health_score)
    recent = {did: hist[-1] for did, hist in device_history.items() if hist}
    fed_idx = fhi(list(recent.values()))
    fp = failure_prob(device_id, health_score)

    diagnosis = None
    if anomaly_flag or health_score < 50 or device_type == 'cbs_controller':
        diagnosis = get_diagnosis(device_type, protocol,
            data.get('metric_name','unknown'), data.get('metric_value',0),
            health_score, anomaly_flag)

    command = get_command(device_id, device_type, health_score, blast_hold)

    if health_score < 50 or anomaly_flag or blast_hold:
        sse_broadcast('metric', {
            'device_id': device_id, 'health_score': round(health_score,1),
            'anomaly_flag': anomaly_flag, 'blast_hold': blast_hold,
            'is_cbs': device_type == 'cbs_controller'
        })

    if blast_hold or (device_type == 'cbs_controller' and health_score < CBS_SAFETY_THRESHOLD):
        notify_all(f'CBS BLAST HOLD {device_id}', f'DNP3 {health_score:.1f}% Cost $450k/hr', 'cbs', device_id)
    elif health_score < 20 and device_type in ['ventilation','pump']:
        notify_all(f'EMERGENCY {device_id}', f'{device_type} at {health_score:.1f}%', 'critical', device_id)

    record = {
        'device_type': device_type, 'device_id': device_id,
        'metric_name': data.get('metric_name','unknown'),
        'metric_value': float(data.get('metric_value',0)),
        'health_score': health_score, 'anomaly_flag': anomaly_flag,
        'predicted_score': predicted, 'ai_diagnosis': diagnosis,
        'automation_command': command
    }
    with queue_lock:
        metric_queue.append(record)

    if (health_score < 50 or anomaly_flag or blast_hold) and supabase:
        try:
            supabase.table('incidents').insert({
                'device_id': device_id, 'device_type': device_type,
                'health_score': health_score, 'ai_diagnosis': diagnosis,
                'automation_command': command, 'status': 'open'
            }).execute()
        except Exception as e:
            print(f'Incident error: {e}')

    return jsonify({
        'status':'ok', 'health_score':round(health_score,1),
        'anomaly_flag':anomaly_flag, 'predicted_score':round(predicted,1),
        'failure_probability':fp, 'ai_diagnosis':diagnosis,
        'automation_command':command, 'federated_index':fed_idx,
        'uptime_pct':get_uptime(device_id), 'blast_hold':blast_hold
    })

@app.route('/api/platform')
def platform_health():
    uptime_s = (datetime.now(timezone.utc) -
        datetime.fromisoformat(platform_stats['uptime_start'].replace('Z','+00:00'))).total_seconds()
    return jsonify({
        'queue_depth': len(metric_queue),
        'cache_age_seconds': round(time.time()-_data_cache['ts'],1),
        'devices_tracked': len(device_history),
        'anomaly_count': anomaly_count,
        'retrain_needed': anomaly_count >= RETRAIN_THRESHOLD,
        'platform_uptime_h': round(uptime_s/3600,2),
        'notifications': {
            'email_enabled': NOTIFY_EMAIL,
            'sms_enabled': NOTIFY_SMS,
            'whatsapp_enabled': NOTIFY_WHATSAPP,
        }
    })

@app.route('/api/intelligence')
def get_intelligence():
    recent = {did: hist[-1] for did, hist in device_history.items() if hist}
    probs  = {did: failure_prob(did, s) for did, s in recent.items()}
    return jsonify({
        'federated_index': fhi(list(recent.values())),
        'device_scores': recent,
        'failure_probabilities': probs,
        'uptime': {did: get_uptime(did) for did in device_uptime},
        'anomaly_count': anomaly_count,
        'total_devices': len(device_history),
        'retrain_needed': anomaly_count >= RETRAIN_THRESHOLD,
    })

@app.route('/api/twin/<device_id>')
def digital_twin(device_id):
    history = device_history.get(device_id, [])
    if not history: return jsonify({'error':'No history'}), 404
    current = history[-1]
    scenarios = []
    for mult in [1.1, 1.2, 1.5, 2.0]:
        f = np.array([[min(100,50*mult),min(1000,100*mult),min(500,10*mult),min(20,mult*.5),10,40,80]])
        try: fs = scaler.transform(f)
        except: fs = f
        sim = float(rf_model.predict(fs)[0])
        sim = max(0, min(100, sim))
        try: anom = bool(iso_model.predict(fs)[0] == -1)
        except: anom = False
        scenarios.append({'load_increase':f'+{int((mult-1)*100)}%','predicted_score':round(sim,1),
                          'anomaly_predicted':anom,'risk':'critical' if sim<30 else 'warning' if sim<60 else 'safe'})
    return jsonify({'device_id':device_id,'current_score':round(current,1),
                    'history':[round(h,1) for h in history],'scenarios':scenarios,
                    'failure_probability':failure_prob(device_id,current)})

@app.route('/api/weather')
def get_weather():
    loc = LOCATIONS.get(request.args.get('loc','byo'), LOCATIONS['byo'])
    try:
        url = (f"https://api.open-meteo.com/v1/forecast?latitude={loc['lat']}&longitude={loc['lon']}"
               f"&current=temperature_2m,relative_humidity_2m,wind_speed_10m,wind_gusts_10m,"
               f"precipitation,weather_code,cloud_cover"
               f"&hourly=precipitation_probability,wind_speed_10m&forecast_days=2&timezone=Africa/Harare")
        resp = req.get(url, timeout=10).json()
        cur  = resp.get('current',{})
        h    = resp.get('hourly',{})
        wind = cur.get('wind_speed_10m',0)
        temp = cur.get('temperature_2m',25)
        precip = cur.get('precipitation',0)
        alerts = []
        if wind > 40:   alerts.append(f'High winds {wind:.0f}km/h')
        if temp > 38:   alerts.append(f'Extreme heat {temp:.0f}C')
        if precip > 10: alerts.append(f'Heavy rain {precip:.1f}mm')
        return jsonify({'location':loc['name'],'temperature':temp,
            'humidity':cur.get('relative_humidity_2m',50),
            'wind_speed':wind,'wind_gusts':cur.get('wind_gusts_10m',0),
            'precipitation':precip,'weather_code':cur.get('weather_code',0),
            'cloud_cover':cur.get('cloud_cover',0),'alerts':alerts,
            'hourly_wind':h.get('wind_speed_10m',[])[:24],
            'hourly_precip_prob':h.get('precipitation_probability',[])[:24]})
    except Exception as e:
        return jsonify({'error':str(e),'location':loc['name']}), 500

@app.route('/api/shift-report')
@require_specialist
def shift_report():
    if not supabase: return jsonify({'error':'No DB'}), 503
    try:
        resp = supabase.table('metrics').select('*').order('created_at',desc=True).limit(500).execute()
        dm = {}
        for row in resp.data:
            if row['device_id'] not in dm: dm[row['device_id']] = row
        scores = [d['health_score'] for d in dm.values()]
        return jsonify({
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'total_devices': len(dm),
            'avg_health': round(sum(scores)/len(scores),1) if scores else 100,
            'critical': len([s for s in scores if s < 20]),
            'warning':  len([s for s in scores if 20 <= s < 50]),
            'healthy':  len([s for s in scores if s >= 50]),
        })
    except Exception as e:
        return jsonify({'error':str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not supabase: return jsonify({'success':False,'error':'No DB'}), 503
    try:
        result = supabase.table('specialists').select('*')\
            .eq('name',data.get('name','')).eq('password',data.get('password','')).execute()
        if result.data:
            s = result.data[0]
            return jsonify({'success':True,'token':data.get('password'),'name':s['name'],'role':s['role']})
        return jsonify({'success':False}), 401
    except Exception as e:
        return jsonify({'success':False,'error':str(e)}), 500

@app.route('/api/incidents')
@require_specialist
def get_incidents():
    if not supabase: return jsonify([])
    status = request.args.get('status','open')
    try:
        resp = supabase.table('incidents').select('*').eq('status',status)\
            .order('created_at',desc=True).limit(50).execute()
        return jsonify(resp.data)
    except: return jsonify([])

@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
@require_specialist
def assign_incident(incident_id):
    if not supabase: return jsonify({'success':False})
    data = request.json
    supabase.table('incidents').update({'assigned_to':data.get('assigned_to',''),
        'notes':data.get('notes',''),'status':'assigned'}).eq('id',incident_id).execute()
    return jsonify({'success':True})

@app.route('/api/incidents/<incident_id>/resolve', methods=['POST'])
@require_specialist
def resolve_incident(incident_id):
    if not supabase: return jsonify({'success':False})
    data = request.json
    supabase.table('incidents').update({'resolved_by':data.get('resolved_by',''),
        'notes':data.get('notes',''),'status':'resolved'}).eq('id',incident_id).execute()
    return jsonify({'success':True})

@app.route('/api/stream')
def sse_stream():
    import queue as _queue
    sub = _queue.Queue(maxsize=50)
    with _sse_lock: _sse_subs.append(sub)
    def generate():
        yield 'event: connected\ndata: {"ok":true}\n\n'
        while True:
            try: yield sub.get(timeout=25)
            except: yield ':heartbeat\n\n'
    return Response(stream_with_context(generate()), mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Access-Control-Allow-Origin':'*'})

@app.route('/api/export-pdf')
def export_pdf():
    try:
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from flask import send_file

        buf    = BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
                                   topMargin=20*mm, bottomMargin=18*mm)
        DARK   = colors.HexColor('#0c1122')
        ACCENT = colors.HexColor('#34c6f4')
        GREEN  = colors.HexColor('#20e07a')
        AMBER  = colors.HexColor('#f5a020')
        RED    = colors.HexColor('#ff3e50')
        MUTED  = colors.HexColor('#8592a8')
        ROW    = colors.HexColor('#f0f4fa')
        styles = getSampleStyleSheet()
        def sty(n='Normal',**kw): return ParagraphStyle(n,parent=styles[n],**kw)

        recent = {did: hist[-1] for did, hist in device_history.items() if hist}
        scores = list(recent.values())
        fhi_v  = fhi(scores)
        now_s  = datetime.now(timezone.utc).strftime('%d %B %Y %H:%M UTC')

        story = []
        story.append(Paragraph('IISentinel(TM)', sty('Title',fontName='Helvetica-Bold',fontSize=22,textColor=DARK)))
        story.append(Paragraph('Shift Report -- '+now_s, sty('Normal',fontName='Helvetica',fontSize=9,textColor=MUTED,spaceAfter=8)))
        story.append(HRFlowable(width='100%',thickness=1.5,color=ACCENT,spaceAfter=10))

        hdr = sty('Normal',fontName='Helvetica-Bold',fontSize=8,textColor=colors.white)
        cel = sty('Normal',fontName='Helvetica',fontSize=8,textColor=DARK)

        kpi = [
            [Paragraph(c,hdr) for c in ['Metric','Value','Status']],
            [Paragraph(c,cel) for c in ['Federated Health Index', f'{fhi_v:.1f}/100',
                'HEALTHY' if fhi_v>=70 else 'WARNING' if fhi_v>=40 else 'CRITICAL']],
            [Paragraph(c,cel) for c in ['Total Devices', str(len(recent)), '--']],
            [Paragraph(c,cel) for c in ['Critical (<20)', str(sum(1 for s in scores if s<20)), '--']],
            [Paragraph(c,cel) for c in ['Warning (20-50)', str(sum(1 for s in scores if 20<=s<50)), '--']],
        ]
        t = Table(kpi, colWidths=[75*mm,60*mm,40*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),DARK),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,ROW]),
            ('GRID',(0,0),(-1,-1),0.35,colors.HexColor('#d4daea')),
            ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
            ('LEFTPADDING',(0,0),(-1,-1),7),
        ]))
        story.append(Paragraph('Platform Summary', sty('Heading1',fontName='Helvetica-Bold',fontSize=12,textColor=DARK,spaceBefore=8,spaceAfter=5)))
        story.append(t)
        story.append(Spacer(1,14))
        story.append(HRFlowable(width='100%',thickness=0.7,color=MUTED,spaceAfter=5))
        story.append(Paragraph(f'IISentinel(TM) Confidential -- {now_s}',
            sty('Normal',fontName='Helvetica-Oblique',fontSize=7,textColor=MUTED)))

        doc.build(story)
        buf.seek(0)
        fname = f'IISentinel_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")}.pdf'
        return send_file(buf, as_attachment=True, download_name=fname, mimetype='application/pdf')
    except ImportError:
        return jsonify({'error':'pip install reportlab'}), 500

@app.route('/api/search')
def search_devices():
    q         = request.args.get('q','').lower()
    max_score = request.args.get('max_score')
    recent    = {did: hist[-1] for did, hist in device_history.items() if hist}
    results   = []
    for did, score in recent.items():
        if q and q not in did.lower(): continue
        if max_score and score > float(max_score): continue
        results.append({'device_id':did,'health_score':round(score,1),
            'status':'critical' if score<20 else 'warning' if score<50 else 'healthy',
            'failure_probability':failure_prob(did,score)})
    results.sort(key=lambda x: x['health_score'])
    return jsonify({'query':q,'total':len(results),'results':results})

if __name__ == '__main__':
    print('[IISentinel] Starting on http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=False)
