"""
IISentinel™ v3  —  app.py
Flask + Gunicorn + Supabase  |  Deploy: Render

START COMMAND:
  gunicorn app:app --workers 1 --worker-class gthread --threads 8 --timeout 120 --bind 0.0.0.0:$PORT

ENV VARS (Render → Environment):
  SUPABASE_URL    https://your-project.supabase.co
  SUPABASE_KEY    service_role key
  SECRET_KEY      any-random-32-char-string
  DEMO_MODE       true   (optional)

SUPABASE SQL (run once):
  CREATE TABLE IF NOT EXISTS metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT NOT NULL, device_type TEXT DEFAULT 'sensor',
    health_score FLOAT DEFAULT 100, metric_name TEXT DEFAULT 'health',
    metric_value FLOAT DEFAULT 0, ai_diagnosis TEXT,
    automation_command TEXT, anomaly_flag BOOLEAN DEFAULT false,
    integrity_score FLOAT, vibration_score FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT, health_score FLOAT, ai_diagnosis TEXT,
    automation_command TEXT, status TEXT DEFAULT 'open',
    assigned_to TEXT, resolved_by TEXT, notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host TEXT NOT NULL, label TEXT, sector TEXT DEFAULT 'net',
    status TEXT DEFAULT 'unknown', latency_ms FLOAT,
    loss_pct FLOAT DEFAULT 0, health_score FLOAT DEFAULT 0,
    last_check FLOAT, down_since FLOAT,
    down_count INT DEFAULT 0, total_checks INT DEFAULT 0,
    uptime_pct FLOAT DEFAULT 100, last_outage_secs INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  ALTER TABLE metrics   DISABLE ROW LEVEL SECURITY;
  ALTER TABLE incidents DISABLE ROW LEVEL SECURITY;
  ALTER TABLE nodes     DISABLE ROW LEVEL SECURITY;
"""

import os, json, time, uuid, hashlib, threading, socket, random, math
from datetime import datetime
from typing import Optional

from flask import (Flask, jsonify, request, Response,
                   send_from_directory, stream_with_context)
from flask_cors import CORS
import requests as http

def _h(pw):  return hashlib.sha256(pw.encode()).hexdigest()
def _uid():  return str(uuid.uuid4())
def _now():  return datetime.utcnow().isoformat()

# ── Supabase ──────────────────────────────────────────────────────────────────
_sb = None; USE_SB = False
try:
    from supabase import create_client
    _sb = create_client(os.environ['SUPABASE_URL'], os.environ['SUPABASE_KEY'])
    USE_SB = True; print("✓ Supabase connected")
except Exception as _e:
    print(f"⚠ Supabase unavailable ({_e}) — in-memory mode")

HAS_PDF = False
try:
    from fpdf import FPDF; HAS_PDF = True
except ImportError: pass

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)
DEMO_MODE  = os.environ.get('DEMO_MODE','false').lower() == 'true'
SECRET     = os.environ.get('SECRET_KEY','iis-sentinel-secret')
START_TIME = time.time()

_mem_metrics   = []
_mem_nodes     = {}
_mem_tokens    = {}
_mem_incidents = {}

SPECIALISTS = {
    'admin':    {'pw':_h('admin123'), 'role':'administrator','name':'Admin User'},
    'engineer': {'pw':_h('eng123'),   'role':'engineer',     'name':'Field Engineer'},
    'ops':      {'pw':_h('ops123'),   'role':'operations',   'name':'Ops Controller'},
}
for _k,_v in os.environ.items():
    if _k.startswith('SPECIALIST_'):
        _p = _v.split(':',2)
        if len(_p)==3:
            SPECIALISTS[_k[11:].lower()]={'name':_p[0],'role':_p[1],'pw':_h(_p[2])}

# ── DB helpers ────────────────────────────────────────────────────────────────
def db_insert_metric(rec):
    if USE_SB:
        try: _sb.table('metrics').insert(rec).execute(); return
        except Exception as e: print(f"SB insert: {e}")
    _mem_metrics.insert(0,rec)
    if len(_mem_metrics)>3000: _mem_metrics.pop()

def db_get_metrics(limit=300):
    if USE_SB:
        try:
            r=_sb.table('metrics').select('*').order('created_at',desc=True).limit(limit).execute()
            return r.data or []
        except Exception as e: print(f"SB select: {e}")
    return _mem_metrics[:limit]

def db_insert_incident(rec):
    if USE_SB:
        try: _sb.table('incidents').insert(rec).execute(); return
        except Exception as e: print(f"SB inc insert: {e}")
    _mem_incidents[rec['id']] = rec

def db_get_incidents(status=None):
    if USE_SB:
        try:
            q=_sb.table('incidents').select('*').order('created_at',desc=True)
            if status: q=q.eq('status',status)
            return q.execute().data or []
        except Exception as e: print(f"SB inc select: {e}")
    items=list(_mem_incidents.values())
    if status: items=[i for i in items if i.get('status')==status]
    return sorted(items,key=lambda x:x.get('created_at',''),reverse=True)

def db_update_incident(inc_id, updates):
    if USE_SB:
        try: _sb.table('incidents').update(updates).eq('id',inc_id).execute(); return
        except Exception as e: print(f"SB inc update: {e}")
    if inc_id in _mem_incidents: _mem_incidents[inc_id].update(updates)

def db_load_nodes():
    if USE_SB:
        try:
            r=_sb.table('nodes').select('*').execute()
            for n in (r.data or []): _mem_nodes[n['id']]=n
            print(f"✓ Loaded {len(_mem_nodes)} nodes")
        except Exception as e: print(f"SB node load: {e}")

def db_upsert_node(node):
    if USE_SB:
        try: _sb.table('nodes').upsert(node).execute()
        except: pass

def db_delete_node(node_id):
    if USE_SB:
        try: _sb.table('nodes').delete().eq('id',node_id).execute()
        except: pass

# ── Intelligence ──────────────────────────────────────────────────────────────
def compute_intelligence(metrics):
    if not metrics:
        return {'federated_index':100,'total_devices':0,'anomaly_count':0,
                'failure_probabilities':{},'uptime':{},'ttf_minutes':{},
                'retrain_needed':False,'retrain_in_progress':False}
    dm={}
    for m in metrics:
        if m['device_id'] not in dm: dm[m['device_id']]=m
    scores=[d['health_score'] for d in dm.values()]
    weighted=[s*.5 if s<20 else s*.8 if s<50 else s for s in scores]
    fhi=round(sum(weighted)/len(weighted)) if weighted else 100
    probs,upt,ttf={},{},{}
    for dev_id,d in dm.items():
        s=d['health_score']
        probs[dev_id]=max(0,min(99,round((100-s)**1.45/38)))
        upt[dev_id]=min(100,max(0,round(s*.98+random.uniform(-.5,.5))))
        if s<80: ttf[dev_id]=max(0,round((s/100)*480*(1-probs[dev_id]/220)))
    anom=sum(1 for d in dm.values() if d.get('anomaly_flag'))
    total=len(dm)
    # Only warn if anomaly rate > 25% AND at least 5 real devices with real data
    retrain=(total>=5) and (anom/total>0.25) if total>0 else False
    return {'federated_index':fhi,'total_devices':total,'anomaly_count':anom,
            'failure_probabilities':probs,'uptime':upt,'ttf_minutes':ttf,
            'retrain_needed':retrain,'retrain_in_progress':False}

# ── SSE ───────────────────────────────────────────────────────────────────────
import queue as _qm
_sse_listeners=[]; _sse_lock=threading.Lock()

def _sse_push(etype,data):
    with _sse_lock:
        dead=[]
        for q in _sse_listeners:
            try: q.put_nowait({'type':etype,'data':data})
            except: dead.append(q)
        for q in dead:
            try: _sse_listeners.remove(q)
            except: pass

# ── Node monitor + downtime tracking ─────────────────────────────────────────
def _poll_node(node_id):
    node=_mem_nodes.get(node_id)
    if not node: return
    host=node['host']
    prev_status=node.get('status','unknown')
    up=False; latency=None

    # Probe common ports
    for port in [80,443,22,8080,8443,161,23,21,25]:
        t0=time.time()
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(4)
            if s.connect_ex((host,port))==0:
                latency=round((time.time()-t0)*1000,1); up=True; s.close(); break
            s.close()
        except: pass

    # Packet loss: 3 extra probes
    if up:
        probe_port=80
        for p in [80,443,22]:
            try:
                s2=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s2.settimeout(2)
                if s2.connect_ex((host,p))==0: probe_port=p; s2.close(); break
                s2.close()
            except: pass
        miss=0
        for _ in range(3):
            try:
                s3=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s3.settimeout(2)
                if s3.connect_ex((host,probe_port))!=0: miss+=1
                s3.close()
            except: miss+=1
        loss_pct=round(miss/3*100)
    else:
        loss_pct=100

    now=time.time()
    total_checks=node.get('total_checks',0)+1
    down_count=node.get('down_count',0)

    # ── Downtime tracking ────────────────────────────────────────────────────
    if not up:
        down_count+=1
        # Stamp down_since only on the first down poll
        if prev_status in ('up','unknown','checking') or node.get('down_since') is None:
            node['down_since']=now
    else:
        # Coming back up: record last outage duration
        if prev_status=='down' and node.get('down_since'):
            node['last_outage_secs']=round(now-node['down_since'])
        node['down_since']=None

    node['status']        ='up' if up else 'down'
    node['latency_ms']    =latency
    node['loss_pct']      =loss_pct
    node['last_check']    =now
    node['total_checks']  =total_checks
    node['down_count']    =down_count
    node['uptime_pct']    =round((1-down_count/total_checks)*100,1) if total_checks>0 else 100
    node['health_score']  =max(0,min(100,round(100-math.log1p(latency)*8-loss_pct*0.5))) if up and latency else 0
    db_upsert_node(node)

    # SSE on status change
    if up!=(prev_status=='up'):
        _sse_push('node_status',{
            'id':node_id,'host':host,'label':node.get('label',host),
            'status':node['status'],'down_since':node.get('down_since'),
        })

def _node_poll_loop():
    time.sleep(5)
    while True:
        for nid in list(_mem_nodes.keys()):
            threading.Thread(target=_poll_node,args=(nid,),daemon=True).start()
        time.sleep(30)

# ── Demo data ─────────────────────────────────────────────────────────────────
_DEMO_DEVICES=[
    ('net-byo-router-01','router','BGP session stable — OSPF adjacencies nominal'),
    ('net-hre-switch-01','switch','High broadcast rate on GE0/1 — storm control active'),
    ('net-hre-fw-01','firewall','CPU load elevated — connection table at 74%'),
    ('net-mut-wan-01','wan_link','WAN link Mutare — latency spike 180 ms detected'),
    ('tc-byo-bs-01','base_station','LTE eNB BYO — RSRP nominal, PRB utilisation 68%'),
    ('tc-hre-tower-01','network_tower','Antenna bearing drift 3° detected — recalibrate'),
    ('tc-mut-mw-01','microwave_link','E-band SNR degrading — moisture in waveguide suspect'),
    ('mc-shaft1-pump-01','pump','Dewatering pump — bearing vibration 8.2 mm/s'),
    ('mc-shaft2-conv-01','conveyor','Shaft 2 conveyor — motor temperature 82°C'),
    ('mc-plant-vent-01','ventilation','Processing plant fan — VFD overcurrent fault'),
    ('mc-plant-plc-01','plc','Siemens S7-1200 — all I/O nominal'),
    ('mc-surface-pm-01','power_meter','Surface power meter — power factor 0.78 lagging'),
    ('mc-shaft1-sen-01','sensor','Shaft gas sensor — CH4 trace 12 ppm'),
    ('cbs-surface-ctrl-01','cbs_controller','CBS DNP3 controller — link integrity nominal'),
    ('mc-shaft2-scada-01','scada_node','SCADA WinCC — OPC-UA polling 15 tags/s'),
]
_demo_scores={d[0]:random.uniform(58,97) for d in _DEMO_DEVICES}
_demo_dirs={d[0]:random.choice([-1,-1,1]) for d in _DEMO_DEVICES}

def _demo_tick():
    ts=_now()
    for dev_id,dev_type,base_diag in _DEMO_DEVICES:
        s=_demo_scores[dev_id]
        s=max(8,min(98,s+_demo_dirs[dev_id]*random.uniform(.5,2.5)))
        _demo_scores[dev_id]=s
        if s<=11 or s>=97: _demo_dirs[dev_id]*=-1
        anom=s<36; auto=None; integ=None; vib=None
        if dev_type=='cbs_controller':
            integ=round(min(99,max(5,s*.97+random.uniform(-2,2))),1)
            vib=round(80+random.uniform(-5,12),1)
            if integ<90: auto=f'CBS BLAST HOLD issued — integrity {integ:.0f}% < 90%'
        elif s<25: auto=f'Auto: emergency restart {dev_type}; page on-call NOC'
        elif anom: auto=f'Auto: isolate {dev_type}; schedule maintenance'
        mv=round(random.uniform(8,340),1) if dev_type in ('router','switch','wan_link','firewall') else \
           round(52+(100-s)*.65+random.uniform(-2,2),1) if dev_type in ('pump','ventilation','conveyor') else 0.0
        diag=base_diag+(' — ANOMALY DETECTED' if anom else '')
        rec={'id':_uid(),'device_id':dev_id,'device_type':dev_type,
             'health_score':round(s,2),'metric_name':'health','metric_value':mv,
             'ai_diagnosis':diag,'automation_command':auto,'anomaly_flag':anom,
             'integrity_score':integ,'vibration_score':vib,'created_at':ts}
        db_insert_metric(rec)
        if s<35 and random.random()<.25:
            db_insert_incident({'id':_uid(),'device_id':dev_id,'health_score':round(s,2),
                                'ai_diagnosis':diag,'automation_command':auto,'status':'open','created_at':ts})
        if s<30 or dev_type=='cbs_controller':
            _sse_push('metric',{'device_id':dev_id,'health_score':round(s,2),
                                'is_cbs':dev_type=='cbs_controller',
                                'blast_hold':'HOLD' in (auto or ''),'anomaly_flag':anom})
        if dev_type=='cbs_controller' and integ and integ<90:
            _sse_push('cbs_hold',{'device_id':dev_id,'health_score':round(s,2),'integrity':integ})

def _demo_thread():
    time.sleep(5)
    while True:
        try: _demo_tick()
        except Exception as e: print(f"Demo tick: {e}")
        time.sleep(10)

# ── Weather ───────────────────────────────────────────────────────────────────
_WX_COORDS={'byo':(-20.15,28.58,'Bulawayo'),'hre':(-17.83,31.05,'Harare'),
            'mut':(-18.97,32.65,'Mutare'),'mine':(-20.50,28.45,'Mine Site')}
_wx_cache={}; _wx_ts={}

def _get_weather(loc):
    now=time.time()
    if loc in _wx_cache and now-_wx_ts.get(loc,0)<600: return _wx_cache[loc]
    lat,lon,label=_WX_COORDS.get(loc,_WX_COORDS['byo'])
    url=(f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}"
         f"&current=temperature_2m,relative_humidity_2m,wind_speed_10m,wind_gusts_10m,weather_code"
         f"&hourly=wind_speed_10m,precipitation_probability&forecast_days=1&timezone=Africa%2FHarare")
    try:
        resp=http.get(url,timeout=9); resp.raise_for_status()
        d=resp.json(); cur=d.get('current',{}); hrly=d.get('hourly',{})
        temp=cur.get('temperature_2m',26); ws=cur.get('wind_speed_10m',10)
        alerts=[]
        if temp>38: alerts.append(f'⚠ Extreme heat {temp}°C — verify outdoor equipment cooling')
        if ws>55:   alerts.append(f'⚠ High wind {ws} km/h — tower/antenna structural risk')
        if cur.get('weather_code',0) in (95,96,99): alerts.append('⚠ Thunderstorm — suspend outdoor ops')
        result={'location':label,'temperature':temp,'humidity':cur.get('relative_humidity_2m',55),
                'wind_speed':ws,'wind_gusts':cur.get('wind_gusts_10m',0),
                'weather_code':cur.get('weather_code',0),
                'hourly_wind':hrly.get('wind_speed_10m',[])[:24],
                'hourly_precip_prob':hrly.get('precipitation_probability',[])[:24],'alerts':alerts}
        _wx_cache[loc]=result; _wx_ts[loc]=now; return result
    except Exception as e:
        print(f"Weather [{loc}]: {e}"); return {'error':str(e)}

# ── Auth ──────────────────────────────────────────────────────────────────────
def _make_token(name,role):
    tok=hashlib.sha256(f"{name}{role}{time.time()}{SECRET}".encode()).hexdigest()[:40]
    _mem_tokens[tok]={'name':name,'role':role,'exp':time.time()+43200}; return tok

def _validate_token(tok):
    t=_mem_tokens.get(tok or ''); return t if (t and t['exp']>time.time()) else None

def _get_token():
    tok=request.headers.get('X-Specialist-Token','')
    if not tok:
        auth=request.headers.get('Authorization','')
        if auth.startswith('Bearer '): tok=auth[7:]
    return tok

# ── Flask routes ──────────────────────────────────────────────────────────────
@app.route('/')
def root(): return send_from_directory('.','index.html')

@app.after_request
def set_headers(resp):
    if request.path.startswith('/static/'):
        resp.headers['Cache-Control']='public, max-age=86400'
        resp.headers['Vary']='Accept-Encoding'
    return resp

@app.route('/api/metrics',methods=['POST'])
def ingest_metric():
    data=request.get_json(force=True,silent=True) or {}
    if 'device_id' not in data or 'health_score' not in data:
        return jsonify({'error':'device_id and health_score required'}),400
    rec={'id':_uid(),'device_id':data['device_id'],
         'device_type':data.get('device_type','sensor'),
         'health_score':float(data['health_score']),
         'metric_name':data.get('metric_name','health'),
         'metric_value':float(data.get('metric_value',0)),
         'ai_diagnosis':data.get('ai_diagnosis'),
         'automation_command':data.get('automation_command'),
         'anomaly_flag':bool(data.get('anomaly_flag',False)),
         'integrity_score':data.get('integrity_score'),
         'vibration_score':data.get('vibration_score'),
         'created_at':_now()}
    db_insert_metric(rec)
    if rec['health_score']<35:
        db_insert_incident({'id':_uid(),'device_id':rec['device_id'],
                            'health_score':rec['health_score'],
                            'ai_diagnosis':rec.get('ai_diagnosis'),
                            'automation_command':rec.get('automation_command'),
                            'status':'open','created_at':rec['created_at']})
    _sse_push('metric',{'device_id':rec['device_id'],'health_score':rec['health_score'],
                        'is_cbs':rec['device_type']=='cbs_controller',
                        'blast_hold':'HOLD' in (rec.get('automation_command') or ''),
                        'anomaly_flag':rec['anomaly_flag']})
    return jsonify({'ok':True,'id':rec['id']}),201

@app.route('/api/data')
def get_data(): return jsonify(db_get_metrics(400))

@app.route('/api/intelligence')
def get_intelligence(): return jsonify(compute_intelligence(db_get_metrics(400)))

@app.route('/api/weather')
def get_weather(): return jsonify(_get_weather(request.args.get('loc','byo')))

@app.route('/api/platform')
def get_platform():
    metrics=db_get_metrics(400); dm={}
    for m in metrics:
        if m['device_id'] not in dm: dm[m['device_id']]=m
    intel=compute_intelligence(metrics)
    return jsonify({'queue_depth':len(metrics),'cache_age_seconds':0,
                    'devices_tracked':len(dm),
                    'retrain_needed':intel.get('retrain_needed',False),
                    'retrain_in_progress':False,
                    'platform_uptime_h':round((time.time()-START_TIME)/3600,2),
                    'notifications':{'email_enabled':bool(os.environ.get('MAIL_SERVER')),
                                     'sms_enabled':bool(os.environ.get('TWILIO_SID')),
                                     'whatsapp_enabled':bool(os.environ.get('WA_TOKEN'))}})

@app.route('/api/twin/<path:device_id>')
def digital_twin(device_id):
    dev=[m for m in db_get_metrics(400) if m['device_id']==device_id]
    if len(dev)<3: return jsonify({'error':'Need 3+ readings'}),400
    scores=[m['health_score'] for m in dev[:12]]; current=scores[0]
    if len(scores)>=6:
        ra=sum(scores[:3])/3; ob=sum(scores[3:6])/3; diff=ra-ob
        direction='declining' if diff<-1.5 else 'improving' if diff>1.5 else 'stable'
        rtc=max(1,round((current-20)/abs(diff))) if diff<-1.5 and diff!=0 else None
    else: direction='insufficient data'; rtc=None
    scenarios=[]
    for pct,label in [(10,'+10%'),(25,'+25%'),(50,'+50%'),(100,'+100%')]:
        pred=max(0,min(100,round(current/(1+pct/100)+random.uniform(-1.5,1.5))))
        scenarios.append({'load_increase':label,'predicted_score':pred,
                          'risk':'safe' if pred>=70 else 'warning' if pred>=40 else 'critical',
                          'anomaly_predicted':pred<40})
    return jsonify({'device_id':device_id,'current_score':round(current,1),
                    'scenarios':scenarios,'trend':{'direction':direction,'readings_to_critical':rtc}})

@app.route('/api/stream')
def sse():
    listener=_qm.Queue(maxsize=60)
    with _sse_lock: _sse_listeners.append(listener)
    def generate():
        yield 'data: {"type":"connected"}\n\n'
        try:
            while True:
                try:
                    ev=listener.get(timeout=28)
                    yield f'event: {ev["type"]}\ndata: {json.dumps(ev["data"])}\n\n'
                except _qm.Empty: yield ': heartbeat\n\n'
        except GeneratorExit: pass
        finally:
            with _sse_lock:
                try: _sse_listeners.remove(listener)
                except: pass
    return Response(stream_with_context(generate()),mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Connection':'keep-alive'})

@app.route('/api/login',methods=['POST'])
def login():
    data=request.get_json(force=True,silent=True) or {}
    user=data.get('name','').lower().strip(); pw=data.get('password','').strip()
    if not user or not pw: return jsonify({'success':False,'error':'credentials required'}),400
    sp=SPECIALISTS.get(user)
    if sp and sp['pw']==_h(pw):
        tok=_make_token(sp['name'],sp['role'])
        return jsonify({'success':True,'token':tok,'name':sp['name'],'role':sp['role']})
    return jsonify({'success':False,'error':'Invalid credentials'}),401

@app.route('/api/incidents')
def get_incidents():
    if not _validate_token(_get_token()): return jsonify({'error':'Unauthorized'}),401
    return jsonify(db_get_incidents(request.args.get('status')))

@app.route('/api/incidents/<inc_id>/assign',methods=['POST'])
def assign_incident(inc_id):
    if not _validate_token(_get_token()): return jsonify({'error':'Unauthorized'}),401
    data=request.get_json(force=True,silent=True) or {}
    db_update_incident(inc_id,{'status':'assigned','assigned_to':data.get('assigned_to',''),'notes':data.get('notes','')})
    return jsonify({'ok':True})

@app.route('/api/incidents/<inc_id>/resolve',methods=['POST'])
def resolve_incident(inc_id):
    if not _validate_token(_get_token()): return jsonify({'error':'Unauthorized'}),401
    data=request.get_json(force=True,silent=True) or {}
    db_update_incident(inc_id,{'status':'resolved','resolved_by':data.get('resolved_by',''),'notes':data.get('notes','')})
    return jsonify({'ok':True})

@app.route('/api/shift-report')
def shift_report():
    if not _validate_token(_get_token()): return jsonify({'error':'Unauthorized'}),401
    metrics=db_get_metrics(400); dm={}
    for m in metrics:
        if m['device_id'] not in dm: dm[m['device_id']]=m
    devs=list(dm.values()); scores=[d['health_score'] for d in devs]
    avg_h=round(sum(scores)/len(scores)) if scores else 100
    risks=sorted(devs,key=lambda x:x['health_score'])[:6]
    return jsonify({'total_devices':len(devs),'avg_health':avg_h,
                    'critical_devices':sum(1 for s in scores if s<35),
                    'warning_devices':sum(1 for s in scores if 35<=s<70),
                    'healthy_devices':sum(1 for s in scores if s>=70),
                    'top_risks':[{'device':d['device_id'],'score':round(d['health_score']),
                                  'diagnosis':d.get('ai_diagnosis')} for d in risks],
                    'generated_at':_now()})

@app.route('/api/nodes',methods=['GET'])
def get_nodes(): return jsonify(_mem_nodes)

@app.route('/api/nodes',methods=['POST'])
def add_node():
    data=request.get_json(force=True,silent=True) or {}
    host=data.get('host','').strip()
    if not host: return jsonify({'error':'host required'}),400
    for n in _mem_nodes.values():
        if n['host']==host: return jsonify({'error':'already monitoring'}),409
    nid=_uid()
    node={'id':nid,'host':host,'label':data.get('label',host),
          'sector':data.get('sector','net'),'status':'checking',
          'latency_ms':None,'loss_pct':0,'health_score':0,
          'last_check':None,'down_since':None,'down_count':0,
          'total_checks':0,'uptime_pct':100,'last_outage_secs':None,
          'created_at':_now()}
    _mem_nodes[nid]=node
    threading.Thread(target=_poll_node,args=(nid,),daemon=True).start()
    return jsonify(node),201

@app.route('/api/nodes/<node_id>',methods=['DELETE'])
def delete_node(node_id):
    _mem_nodes.pop(node_id,None); db_delete_node(node_id)
    return jsonify({'ok':True})

@app.route('/api/nodes/<node_id>/poll',methods=['POST'])
def poll_node(node_id):
    if node_id not in _mem_nodes: return jsonify({'error':'not found'}),404
    threading.Thread(target=_poll_node,args=(node_id,),daemon=True).start()
    return jsonify({'ok':True})

@app.route('/api/export-pdf')
def export_pdf():
    metrics=db_get_metrics(200); dm={}
    for m in metrics:
        if m['device_id'] not in dm: dm[m['device_id']]=m
    devs=sorted(dm.values(),key=lambda x:x['health_score'])
    scores=[d['health_score'] for d in devs]
    avg_h=round(sum(scores)/len(scores)) if scores else 100
    if HAS_PDF:
        pdf=FPDF(); pdf.set_auto_page_break(auto=True,margin=15); pdf.add_page()
        pdf.set_font('Helvetica','B',18); pdf.cell(0,12,'IISentinel\u2122 Shift Report',ln=True)
        pdf.set_font('Helvetica','',10)
        pdf.cell(0,7,f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",ln=True)
        pdf.cell(0,7,f"Uptime: {round((time.time()-START_TIME)/3600,1)} h",ln=True); pdf.ln(4)
        pdf.set_font('Helvetica','B',13); pdf.cell(0,9,f'Fleet FHI: {avg_h}/100',ln=True)
        pdf.set_font('Helvetica','',10)
        pdf.cell(0,7,f"Devices: {len(devs)} | Critical: {sum(1 for s in scores if s<35)} | Warning: {sum(1 for s in scores if 35<=s<70)} | Healthy: {sum(1 for s in scores if s>=70)}",ln=True)
        pdf.ln(5); pdf.set_font('Helvetica','B',12); pdf.cell(0,8,'Device Status',ln=True)
        pdf.set_font('Helvetica','',9)
        for d in devs:
            s=round(d['health_score']); st='CRITICAL' if s<35 else 'WARNING' if s<70 else 'OK'
            pdf.cell(0,6,f"[{st}]  {d['device_id'][:38]}  {s}/100  {(d.get('ai_diagnosis') or '')[:55]}",ln=True)
        raw=pdf.output(dest='S')
        if isinstance(raw,str): raw=raw.encode('latin-1')
        return Response(raw,mimetype='application/pdf',
                        headers={'Content-Disposition':'attachment; filename=IISentinel_Report.pdf'})
    lines=['IISentinel(tm) Shift Report','='*48,f"Generated: {_now()}",
           f"Devices: {len(devs)}  FHI: {avg_h}/100",'']
    for d in devs:
        s=round(d['health_score'])
        lines.append(f"{'CRIT' if s<35 else 'WARN' if s<70 else ' OK '}  {d['device_id']}: {s}/100")
    return Response('\n'.join(lines).encode(),mimetype='text/plain',
                    headers={'Content-Disposition':'attachment; filename=IISentinel_Report.txt'})

# ── Boot ──────────────────────────────────────────────────────────────────────
db_load_nodes()
threading.Thread(target=_node_poll_loop,daemon=True).start()
if DEMO_MODE:
    print("🟢 DEMO_MODE — injecting synthetic data every 10 s")
    threading.Thread(target=_demo_thread,daemon=True).start()

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=False,threaded=True)
