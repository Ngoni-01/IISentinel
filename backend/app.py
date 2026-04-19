"""
IISentinel™ v3.0 — Intelligent Infrastructure Sentinel
========================================================
Run:  python app.py
Demo: DEMO_MODE=true python app.py
Open: http://localhost:5000

Install: pip install quart reportlab scikit-learn joblib numpy requests quart-cors
Production: pip install hypercorn && hypercorn app:app --bind 0.0.0.0:5000 --workers 4
"""
import os, re, json, time, random, threading, smtplib, sqlite3, uuid, asyncio
from collections import deque
from datetime import datetime, timezone
from io import BytesIO
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import numpy as np
import joblib
import requests as req
from quart import Quart, request, jsonify, send_file, Response, make_response

try:
    from quart_cors import cors as _quart_cors
    def _apply_cors(app):
        return _quart_cors(app, allow_origin="*",
                           allow_headers=["Content-Type","X-Specialist-Token"],
                           allow_methods=["GET","POST","DELETE","OPTIONS"])
except ImportError:
    def _apply_cors(app):
        @app.after_request
        async def _cors(r):
            r.headers['Access-Control-Allow-Origin']  = '*'
            r.headers['Access-Control-Allow-Headers'] = 'Content-Type,X-Specialist-Token'
            r.headers['Access-Control-Allow-Methods'] = 'GET,POST,DELETE,OPTIONS'
            return r
        return app

try:
    from supabase import create_client as _supa_create
    _SUPABASE_AVAILABLE = True
except ImportError:
    _SUPABASE_AVAILABLE = False

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'iisentinel.db')

def _db_init():
    con = sqlite3.connect(_DB_PATH); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS metrics (
        id TEXT PRIMARY KEY, device_id TEXT, device_type TEXT,
        metric_name TEXT, metric_value REAL, health_score REAL,
        anomaly_flag INTEGER, predicted_score REAL,
        ai_diagnosis TEXT, automation_command TEXT, created_at TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY, device_id TEXT, device_type TEXT,
        health_score REAL, ai_diagnosis TEXT, automation_command TEXT,
        status TEXT DEFAULT 'open', assigned_to TEXT, resolved_by TEXT,
        notes TEXT, created_at TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS specialists (
        id TEXT PRIMARY KEY, name TEXT, password TEXT, role TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY, host TEXT NOT NULL, label TEXT,
        sector TEXT DEFAULT 'net', created_at TEXT)""")
    cur.execute("INSERT OR IGNORE INTO specialists VALUES (?,?,?,?)",
                ('sp-001','Admin','admin123','engineer'))
    con.commit(); con.close()

_db_init()

class _SQLiteDB:
    def __init__(self): self._tb=None; self._filters=[]; self._lim=200; self._ins=None; self._upd=None
    def table(self,n): o=_SQLiteDB(); o._tb=n; return o
    def select(self,*a): return self
    def eq(self,c,v): self._filters.append((c,v)); return self
    def order(self,*a,**kw): return self
    def limit(self,n): self._lim=n; return self
    def insert(self,row): self._ins=row; return self
    def update(self,row): self._upd=row; return self
    def execute(self):
        R=lambda d: type('R',(),{'data':d})()
        try:
            con=sqlite3.connect(_DB_PATH); con.row_factory=sqlite3.Row; cur=con.cursor(); tb=self._tb
            if self._ins:
                row=self._ins; rid=str(uuid.uuid4()); ts=datetime.now(timezone.utc).isoformat()
                if tb=='metrics':
                    cur.execute("INSERT OR IGNORE INTO metrics VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (rid,row.get('device_id',''),row.get('device_type',''),row.get('metric_name',''),
                         float(row.get('metric_value',0)),float(row.get('health_score',50)),
                         int(row.get('anomaly_flag',0)),float(row.get('predicted_score',50)),
                         row.get('ai_diagnosis'),row.get('automation_command'),ts))
                elif tb=='incidents':
                    cur.execute("INSERT OR IGNORE INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (rid,row.get('device_id',''),row.get('device_type',''),float(row.get('health_score',50)),
                         row.get('ai_diagnosis'),row.get('automation_command'),row.get('status','open'),
                         None,None,None,ts))
                con.commit(); con.close(); return R([{**row,'id':rid,'created_at':ts}])
            if self._upd:
                for col,val in self._filters:
                    sets=', '.join(f"{k}=?" for k in self._upd)
                    cur.execute(f"UPDATE {tb} SET {sets} WHERE id=?",list(self._upd.values())+[val])
                con.commit(); con.close(); return R([])
            where=''; params=[]
            if self._filters:
                where='WHERE '+' AND '.join(f"{c}=?" for c,v in self._filters)
                params=[v for c,v in self._filters]
            cur.execute(f"SELECT * FROM {tb} {where} ORDER BY created_at DESC LIMIT ?",params+[self._lim])
            cols=[d[0] for d in cur.description]
            rows=[dict(zip(cols,r)) for r in cur.fetchall()]
            con.close(); return R(rows)
        except Exception as e: print(f'[DB] {e}'); return R([])

SUPABASE_URL=os.environ.get('SUPABASE_URL',''); SUPABASE_KEY=os.environ.get('SUPABASE_KEY','')
if _SUPABASE_AVAILABLE and SUPABASE_URL and SUPABASE_URL not in ('','local'):
    try:
        supabase=_supa_create(SUPABASE_URL,SUPABASE_KEY); print('[IISentinel] Supabase connected')
    except Exception as e:
        print(f'[IISentinel] Supabase failed ({e}) -- using SQLite'); supabase=_SQLiteDB()
else:
    supabase=_SQLiteDB(); print('[IISentinel] Using local SQLite (iisentinel.db)')

def _build_models():
    from sklearn.ensemble import RandomForestRegressor, IsolationForest
    print('[IISentinel] Building ML models...')
    rng=np.random.default_rng(42)
    X=rng.uniform([0,0,0,0,0,15,10],[100,1000,500,20,1000,80,100],size=(500,7))
    y=np.clip(100-(X[:,0]*0.3+X[:,2]*0.05+X[:,3]*2+np.maximum(0,80-X[:,6])*0.5+X[:,3]*1.5),0,100)
    rf=RandomForestRegressor(n_estimators=100,max_depth=10,random_state=42); rf.fit(X,y)
    iso=IsolationForest(n_estimators=100,contamination=0.08,random_state=42); iso.fit(X[y>=50])
    joblib.dump(rf,'health_model.pkl'); joblib.dump(iso,'anomaly_model.pkl')
    print('[IISentinel] ML models ready.'); return rf,iso,None

try:
    rf_model=joblib.load('health_model.pkl'); iso_model=joblib.load('anomaly_model.pkl')
    try: scaler=joblib.load('scaler.pkl')
    except: scaler=None
    print('[IISentinel] ML models loaded.')
except:
    rf_model,iso_model,scaler=_build_models()

app=Quart(__name__,template_folder='.',static_folder='static',static_url_path='/static')
app.secret_key=os.environ.get('SECRET_KEY','iisentinel-dev-2026')
app=_apply_cors(app)

NETWORK_TYPES=['router','switch','firewall','wan_link','workstation']
TELECOM_TYPES=['base_station','network_tower','microwave_link']
MINING_TYPES =['pump','conveyor','ventilation','power_meter','sensor','plc','scada_node']
CBS_TYPES    =['cbs_controller']
CBS_SAFETY_THRESHOLD=90.0; RETRAIN_THRESHOLD=50; CACHE_TTL=8

COST_RATES={'pump':150000,'conveyor':120000,'ventilation':180000,'plc':80000,'scada_node':60000,
            'cbs_controller':450000,'power_meter':100000,'sensor':40000,'base_station':25000,
            'network_tower':35000,'microwave_link':40000,'router':15000,'switch':10000,
            'firewall':20000,'wan_link':12000,'workstation':2000}

LOCATIONS={'byo':{'lat':-20.15,'lon':28.58,'name':'Bulawayo'},
           'hre':{'lat':-17.82,'lon':31.05,'name':'Harare'},
           'mut':{'lat':-18.97,'lon':32.67,'name':'Mutare'},
           'mine':{'lat':-17.65,'lon':29.85,'name':'Mine Site'}}

FIELD_BOUNDS={'cpu_load':(0,100),'bandwidth_mbps':(0,100000),'latency_ms':(0,60000),
              'packet_loss':(0,100),'connected_devices':(0,100000),
              'temperature':(-50,200),'signal_strength':(0,100),'metric_value':(-1e9,1e9)}

READING_INTERVALS_MIN={'pump':4,'conveyor':6,'ventilation':5,'cbs_controller':3,
                       'router':10,'switch':10,'firewall':10,'wan_link':8,
                       'base_station':8,'network_tower':10,'microwave_link':8,
                       'plc':4,'scada_node':5,'sensor':3,'power_meter':6}

metric_queue=deque(maxlen=500); queue_lock=threading.Lock()
_data_cache={'data':[],'ts':0}
scoring_queue=deque(maxlen=200); scoring_results={}; scoring_lock=threading.Lock()
device_history={}; device_uptime={}
reading_window=[]; anomaly_count=0
_retrain_lock=threading.Lock(); _retrain_in_progress=False
_sse_queues=[]; _sse_lock=threading.Lock()
notification_log=deque(maxlen=100)
_cbs_integrity_cache={}
platform_stats={'requests_total':0,'requests_failed':0,'cache_hits':0,'models_scored':0,
                'queue_depth':0,'last_flush':None,'last_retrain_attempt':None,
                'last_retrain_success':None,'retrain_count':0,'notifications_sent':0,
                'uptime_start':datetime.now(timezone.utc).isoformat()}

NOTIFY={'email_enabled':os.environ.get('NOTIFY_EMAIL_ENABLED','false').lower()=='true',
        'sms_enabled':bool(os.environ.get('AT_API_KEY') or os.environ.get('TWILIO_SID')),
        'whatsapp_enabled':bool(os.environ.get('WA_TOKEN')),
        'smtp_host':os.environ.get('SMTP_HOST','smtp.gmail.com'),
        'smtp_port':int(os.environ.get('SMTP_PORT','587')),
        'smtp_user':os.environ.get('SMTP_USER',''),'smtp_pass':os.environ.get('SMTP_PASS',''),
        'from_email':os.environ.get('SMTP_FROM','IISentinel alerts@iisentinel.io'),
        'to_emails':[e for e in os.environ.get('ALERT_EMAIL','').split(',') if e],
        'sms_numbers':[n for n in os.environ.get('ALERT_PHONE','').split(',') if n],
        'at_api_key':os.environ.get('AT_API_KEY',''),'at_username':os.environ.get('AT_USERNAME','sandbox'),
        'wa_token':os.environ.get('WA_TOKEN',''),'wa_phone_id':os.environ.get('WA_PHONE_ID',''),
        'wa_numbers':[n for n in os.environ.get('WA_TO','').split(',') if n],
        'sms_gateway':os.environ.get('SMS_GATEWAY','africastalking'),
        'twilio_sid':os.environ.get('TWILIO_SID',''),'twilio_token':os.environ.get('TWILIO_TOKEN',''),
        'twilio_from':os.environ.get('TWILIO_FROM','')}

def send_sms(message):
    if not NOTIFY['sms_enabled']: return
    try:
        if NOTIFY['sms_gateway']=='africastalking' and NOTIFY['at_api_key']:
            req.post('https://api.africastalking.com/version1/messaging',
                headers={'apiKey':NOTIFY['at_api_key'],'Accept':'application/json'},
                data={'username':NOTIFY['at_username'],'to':','.join(NOTIFY['sms_numbers']),
                      'message':f'IISentinel: {message}','from':'IISentinel'},timeout=8)
        elif NOTIFY['sms_gateway']=='twilio' and NOTIFY['twilio_sid']:
            from twilio.rest import Client
            Client(NOTIFY['twilio_sid'],NOTIFY['twilio_token']).messages.create(
                body=f'IISentinel: {message}',from_=NOTIFY['twilio_from'],
                to=NOTIFY['sms_numbers'][0] if NOTIFY['sms_numbers'] else '')
    except Exception as e: print(f'[SMS] {e}')

def send_whatsapp(message):
    if not NOTIFY['whatsapp_enabled'] or not NOTIFY['wa_token']: return
    try:
        for num in NOTIFY['wa_numbers']:
            req.post(f"https://graph.facebook.com/v19.0/{NOTIFY['wa_phone_id']}/messages",
                headers={'Authorization':f"Bearer {NOTIFY['wa_token']}",'Content-Type':'application/json'},
                json={'messaging_product':'whatsapp','to':num,'type':'text',
                      'text':{'body':f'IISentinel\n{message}'}},timeout=8)
    except Exception as e: print(f'[WhatsApp] {e}')

def send_email(subject,body,device_id=None,health_score=None,
               diagnosis=None,automation_command=None,severity='warning'):
    if not NOTIFY['email_enabled'] or not NOTIFY['smtp_user'] or not NOTIFY['to_emails']: return
    C={'critical':'#ff3e50','cbs':'#ff3e50','warning':'#f5a020','info':'#20e07a'}.get(severity,'#34c6f4')
    try:
        msg=MIMEMultipart('alternative')
        msg['Subject']=f'[IISentinel] {severity.upper()}: {subject}'
        msg['From']=NOTIFY['from_email']; msg['To']=', '.join(NOTIFY['to_emails'])
        msg.attach(MIMEText(body,'plain'))
        with smtplib.SMTP(NOTIFY['smtp_host'],NOTIFY['smtp_port']) as s:
            if NOTIFY['smtp_user']: s.starttls(); s.login(NOTIFY['smtp_user'],NOTIFY['smtp_pass'])
            s.send_message(msg)
    except Exception as e: print(f'[Email] {e}')

def notify_all(subject,message,level='critical',device_id=None,
               health_score=None,diagnosis=None,automation_command=None):
    notification_log.appendleft({'subject':subject,'message':message,'level':level,
        'device_id':device_id,'ts':datetime.now(timezone.utc).isoformat()})
    platform_stats['notifications_sent']+=1
    if level in ('critical','cbs'):
        threading.Thread(target=send_sms,args=(f'{subject}: {message}',),daemon=True).start()
        threading.Thread(target=send_whatsapp,args=(f'{subject}\n{message}',),daemon=True).start()
    threading.Thread(target=send_email,kwargs=dict(subject=subject,body=message,device_id=device_id,
        health_score=health_score,diagnosis=diagnosis,automation_command=automation_command,
        severity=level),daemon=True).start()

def sse_broadcast(event_type, payload):
    msg=f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
    dead=[]
    with _sse_lock:
        for q in _sse_queues:
            try: q.put_nowait(msg)
            except Exception: dead.append(q)
        for q in dead:
            try: _sse_queues.remove(q)
            except ValueError: pass

def flush_worker():
    while True:
        time.sleep(3)
        with queue_lock:
            if not metric_queue: continue
            batch=list(metric_queue); metric_queue.clear()
        for item in batch:
            try: supabase.table('metrics').insert(item).execute()
            except Exception as e: print(f'[Flush] {e}')
        platform_stats['last_flush']=datetime.now(timezone.utc).isoformat()
        platform_stats['queue_depth']=len(metric_queue)

def scorer_worker():
    while True:
        time.sleep(0.5)
        with scoring_lock:
            if not scoring_queue: continue
            item=scoring_queue.popleft()
        try:
            arr=np.array([item['features']])
            score=float(np.clip(rf_model.predict(arr)[0],0,100))
            anom=bool(iso_model.predict(arr)[0]==-1)
            scoring_results[item['device_id']]={'health_score':score,'anomaly_flag':anom,'ts':time.time()}
            platform_stats['models_scored']+=1
        except Exception as e: print(f'[Scorer] {e}')

def retrain_worker():
    global rf_model,iso_model,anomaly_count,_retrain_in_progress
    while True:
        time.sleep(60)
        if anomaly_count<RETRAIN_THRESHOLD: continue
        with _retrain_lock:
            if _retrain_in_progress: continue
            _retrain_in_progress=True
        try:
            from sklearn.ensemble import RandomForestRegressor,IsolationForest
            platform_stats['last_retrain_attempt']=datetime.now(timezone.utc).isoformat()
            resp=supabase.table('metrics').select('*').limit(2000).execute(); rows=resp.data
            if len(rows)<50: continue
            X,y=[],[]
            for r in rows:
                f=[r.get('cpu_load',50),r.get('bandwidth_mbps',100),r.get('latency_ms',10),
                   r.get('packet_loss',0),r.get('connected_devices',10),
                   r.get('temperature',40),r.get('signal_strength',80)]
                if None not in f and r.get('health_score') is not None:
                    X.append(f); y.append(r['health_score'])
            if len(X)<50: continue
            X=np.array(X); y=np.array(y)
            nrf=RandomForestRegressor(n_estimators=100,max_depth=10,random_state=42); nrf.fit(X,y)
            niso=IsolationForest(n_estimators=100,contamination=0.08,random_state=42); niso.fit(X[y>=50])
            joblib.dump(nrf,'health_model.pkl'); joblib.dump(niso,'anomaly_model.pkl')
            rf_model=nrf; iso_model=niso; anomaly_count=0
            platform_stats['last_retrain_success']=datetime.now(timezone.utc).isoformat()
            platform_stats['retrain_count']=platform_stats.get('retrain_count',0)+1
            print(f'[Retrain] Done -- {len(X)} samples')
        except Exception as e: print(f'[Retrain] {e}')
        finally:
            with _retrain_lock: _retrain_in_progress=False

for _fn in (flush_worker,scorer_worker,retrain_worker):
    threading.Thread(target=_fn,daemon=True).start()

def get_failure_probability(device_id,score):
    h=device_history.get(device_id,[])
    if len(h)<3: return 0.0
    r=h[-5:]; trend=r[-1]-r[0]
    if trend>=0: return max(0.0,round((100-score)*0.05,1))
    return min(99.0,round(abs(trend)/len(r)*3+(100-score)*0.3,1))

def get_ettf_minutes(device_id, score, device_type=''):
    h=device_history.get(device_id,[])
    if len(h)<3: return None
    window=h[-min(len(h),10):]
    if len(window)<2: return None
    slope=(window[-1]-window[0])/max(1,len(window)-1)
    if slope>=-0.4: return None
    critical_floor=18.0
    if score<=critical_floor: return 0
    readings_needed=(score-critical_floor)/abs(slope)
    interval=READING_INTERVALS_MIN.get(device_type,5)
    return max(1,round(readings_needed*interval))

def get_cbs_integrity_score(device_id, link_health, metric_data):
    h=device_history.get(device_id,[])
    volatility=0.0
    if len(h)>=3:
        diffs=[abs(h[i]-h[i-1]) for i in range(1,len(h))]
        volatility=sum(diffs)/max(1,len(diffs))
    vibration_score=max(0.0,min(100.0,100.0-volatility*2.8))
    temp=float(metric_data.get('temperature',35))
    temp_score=max(0.0,min(100.0,100.0-max(0.0,temp-45.0)*1.8))
    integrity=link_health*0.55+vibration_score*0.30+temp_score*0.15
    return round(min(100.0,max(0.0,integrity)),1),round(vibration_score,1)

def get_federated_health_index(scores):
    if not scores: return 100.0
    w=[s*0.5 if s<20 else s*0.8 if s<50 else s for s in scores]
    return round(sum(w)/len(w),1)

def get_diagnosis(dtype,protocol,mname,mval,score,anom,integrity_score=None):
    issues=[]; actions=[]
    if score<20: issues.append('critical system failure'); actions.append('immediate intervention required')
    elif score<35: issues.append('severe degradation'); actions.append('escalate to operations team')
    elif score<50: issues.append('moderate degradation'); actions.append('schedule maintenance within 24h')
    if dtype in TELECOM_TYPES+NETWORK_TYPES:
        if mval>100 and 'latency' in str(mname): issues.append(f'SNMP {mval:.1f}ms latency'); actions.append('inspect BGP routing')
        if mval>2 and 'packet' in str(mname): issues.append(f'packet loss {mval:.1f}%'); actions.append('run BERT test, check SFP')
        if mval<40 and 'signal' in str(mname): issues.append(f'signal at {mval:.1f}%'); actions.append('check microwave alignment')
    elif dtype in MINING_TYPES:
        if mval>75 and 'temp' in str(mname): issues.append(f'temperature {mval:.1f}C'); actions.append('check cooling, reduce duty cycle')
    elif dtype=='cbs_controller':
        if integrity_score is not None and integrity_score<CBS_SAFETY_THRESHOLD:
            if score>=CBS_SAFETY_THRESHOLD:
                issues.append(f'CBS integrity {integrity_score:.1f}% below threshold -- vibration or thermal degradation')
                actions.append('BLAST HOLD -- check vibration sensors and enclosure temperature')
            else:
                issues.append(f'CBS DNP3 link {score:.1f}% and integrity {integrity_score:.1f}% below blast threshold')
                actions.append('BLAST HOLD -- notify blasting officer, inspect DNP3 cable')
        elif score<CBS_SAFETY_THRESHOLD:
            issues.append(f'CBS DNP3 link {score:.1f}% below blast threshold')
            actions.append('BLAST HOLD -- notify blasting officer')
    if anom: issues.append('AI anomaly detected'); actions.append('cross-reference event log')
    if not issues: return f'Device normal via {protocol or "Ethernet"}. Score {score:.1f}/100.'
    return f'{"; ".join(issues).capitalize()}. Action: {"; ".join(actions).capitalize()}.'

def get_auto_cmd(device_id,dtype,score,blast_hold=False,integrity_score=None):
    eff_hold=(blast_hold or (dtype=='cbs_controller' and (
        score<CBS_SAFETY_THRESHOLD or (integrity_score is not None and integrity_score<CBS_SAFETY_THRESHOLD))))
    if dtype=='cbs_controller' and eff_hold:
        integ=f'{integrity_score:.1f}' if integrity_score is not None else f'{score:.1f}'
        return f'CBS SAFETY INTERLOCK: BLAST HOLD on {device_id} -- link {score:.1f}% / integrity {integ}%'
    if dtype in ['ventilation','pump'] and score<20:
        return f'EMERGENCY: Safety shutdown {device_id} -- underground evacuation alert'
    if score<20: return f'CRITICAL: Emergency restart for {device_id}'
    if score<35: return f'WARNING: Isolate {device_id} -- reduce load'
    if score<50: return f'CAUTION: Schedule maintenance for {device_id}'
    return None

def update_uptime(did,score):
    device_uptime.setdefault(did,{'total':0,'healthy':0})
    device_uptime[did]['total']+=1
    if score>=50: device_uptime[did]['healthy']+=1

def get_uptime_pct(did):
    d=device_uptime.get(did,{'total':0,'healthy':0})
    return 100.0 if d['total']==0 else round(d['healthy']/d['total']*100,1)

def sanitize_metric(data):
    if not isinstance(data,dict): return {},'Payload must be JSON'
    for f in ['device_id','device_type']:
        if not data.get(f): return {},f'Missing: {f}'
    did=str(data['device_id'])
    if not re.match(r'^[a-zA-Z0-9_\-]{1,80}$',did): return {},'Invalid device_id'
    cleaned=dict(data); cleaned['device_id']=did
    for field,(lo,hi) in FIELD_BOUNDS.items():
        if field in cleaned:
            try: cleaned[field]=float(max(lo,min(hi,float(cleaned[field]))))
            except: cleaned[field]=(lo+hi)/2
    return cleaned,None

def get_cached_data():
    now=time.time()
    if now-_data_cache['ts']<CACHE_TTL and _data_cache['data']:
        platform_stats['cache_hits']+=1; return _data_cache['data']
    try:
        resp=supabase.table('metrics').select('*').limit(200).execute()
        data=resp.data
        for item in data:
            did=item.get('device_id','')
            if did in _cbs_integrity_cache: item.update(_cbs_integrity_cache[did])
        _data_cache['data']=data; _data_cache['ts']=now; return data
    except Exception as e:
        print(f'[Cache] {e}'); return _data_cache['data']

def require_specialist(f):
    @wraps(f)
    async def decorated(*args,**kwargs):
        token=request.headers.get('X-Specialist-Token','')
        if not token: return jsonify({'error':'Unauthorised'}),401
        try:
            r=supabase.table('specialists').select('*').eq('password',token).execute()
            if not r.data: return jsonify({'error':'Invalid token'}),401
        except Exception as e: return jsonify({'error':f'Auth error: {e}'}),401
        return await f(*args,**kwargs)
    return decorated

DEMO_DEVICES=[
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
    global anomaly_count
    did=payload['device_id']; dtype=payload['device_type']
    features=[payload.get('cpu_load',50),payload.get('bandwidth_mbps',100),
              payload.get('latency_ms',10),payload.get('packet_loss',0),
              payload.get('connected_devices',10),payload.get('temperature',40),
              payload.get('signal_strength',80)]
    arr=np.array([features])
    score=float(np.clip(rf_model.predict(arr)[0],0,100))
    if dtype=='cbs_controller': score=min(score,payload.get('signal_strength',score))
    anom=bool(iso_model.predict(arr)[0]==-1)
    if anom: anomaly_count+=1
    device_history.setdefault(did,[]).append(score)
    if len(device_history[did])>20: device_history[did].pop(0)
    update_uptime(did,score)
    integrity_score=None; vibration_score=None
    if dtype=='cbs_controller':
        integrity_score,vibration_score=get_cbs_integrity_score(did,score,payload)
        _cbs_integrity_cache[did]={'integrity_score':integrity_score,'vibration_score':vibration_score}
    eff_hold=(dtype=='cbs_controller' and (score<CBS_SAFETY_THRESHOLD or
              (integrity_score is not None and integrity_score<CBS_SAFETY_THRESHOLD)))
    ai=get_diagnosis(dtype,payload.get('protocol',''),payload.get('metric_name',''),
                     payload.get('metric_value',0),score,anom,integrity_score) if (anom or score<50 or eff_hold) else None
    cmd=get_auto_cmd(did,dtype,score,integrity_score=integrity_score)
    rec={'device_id':did,'device_type':dtype,'metric_name':payload.get('metric_name',''),
         'metric_value':float(payload.get('metric_value',0)),'health_score':score,
         'anomaly_flag':anom,'predicted_score':score,'ai_diagnosis':ai,'automation_command':cmd}
    if integrity_score is not None: rec['integrity_score']=integrity_score; rec['vibration_score']=vibration_score
    with queue_lock: metric_queue.append(rec)
    if eff_hold:
        sse_broadcast('cbs_hold',{'device_id':did,'health_score':round(score,1),
                                   'integrity_score':integrity_score,'blast_hold':True})

def demo_worker():
    in_event={d['id']:0 for d in DEMO_DEVICES}
    print('[Demo] Injection active -- 15 devices, 4 sites')
    while True:
        for dev in DEMO_DEVICES:
            did=dev['id']; dtype=dev['type']
            if in_event[did]>0: in_event[did]-=1
            elif random.random()<0.08: in_event[did]=random.randint(4,12)
            if dtype=='cbs_controller' and random.random()<0.008: in_event[did]=random.randint(6,10)
            sev=in_event[did]/12.0
            sig=max(20,dev['bsig']*(1-sev*0.45)+random.gauss(0,4))
            lat=max(1,dev['blat']*(1+sev*3.0)+random.gauss(0,dev['blat']*0.1))
            bw=max(1,dev['bbw']*(1-sev*0.6)+random.gauss(0,dev['bbw']*0.08))
            temp=dev['btemp']*(1+sev*0.5)+random.gauss(0,3)
            cpu=min(98,20+sev*75+random.gauss(0,8)); loss=max(0,sev*8+random.gauss(0,0.8))
            if dtype in MINING_TYPES: mn,mv='temperature',round(temp,1)
            elif dtype in TELECOM_TYPES+CBS_TYPES: mn,mv='signal_strength',round(sig,1)
            else: mn,mv='latency_ms',round(lat,1)
            proto=('DNP3/Ethernet' if dtype=='cbs_controller' else
                   'Profinet/EtherNet-IP' if dtype in MINING_TYPES else 'SNMP/Ethernet-802.3')
            try:
                _demo_ingest({'device_id':did,'device_type':dtype,'metric_name':mn,'metric_value':mv,
                    'cpu_load':round(cpu,1),'bandwidth_mbps':round(bw,1),'latency_ms':round(lat,1),
                    'packet_loss':round(loss,2),'connected_devices':max(1,int(10*(1-sev*0.4))),
                    'temperature':round(temp,1),'signal_strength':round(sig,1),'protocol':proto})
            except Exception as e: print(f'[Demo] {e}')
        time.sleep(random.uniform(3.0,5.0))

if os.environ.get('DEMO_MODE','false').lower()=='true':
    threading.Thread(target=demo_worker,daemon=True).start()

@app.route('/')
async def index():
    try:
        path=os.path.join(os.path.dirname(os.path.abspath(__file__)),'dashboard.html')
        with open(path,encoding='utf-8') as f:
            return f.read(),200,{'Content-Type':'text/html; charset=utf-8'}
    except FileNotFoundError:
        return '<h1>dashboard.html not found</h1>',404

@app.route('/health')
async def health_check():
    q=len(metric_queue); age=round(time.time()-_data_cache['ts'],1)
    up=(datetime.now(timezone.utc)-datetime.fromisoformat(
        platform_stats['uptime_start'].replace('Z','+00:00')
        if platform_stats['uptime_start'].endswith('Z')
        else platform_stats['uptime_start'])).total_seconds()
    deg=q>450 or (age>300 and _data_cache['ts']>0)
    return jsonify({'status':'degraded' if deg else 'ok','uptime_h':round(up/3600,2),
        'queue_depth':q,'cache_age_s':age,'devices':len(device_history),
        'version':'3.0','platform':'IISentinel'}),503 if deg else 200

@app.route('/api/data')
async def get_data():
    platform_stats['requests_total']+=1
    return jsonify(get_cached_data())

@app.route('/api/metrics',methods=['POST','OPTIONS'])
async def receive_metrics():
    if request.method=='OPTIONS': return '',204
    global anomaly_count
    platform_stats['requests_total']+=1
    try: raw=await request.get_json(force=True,silent=True) or {}
    except Exception: raw={}
    if not raw: platform_stats['requests_failed']+=1; return jsonify({'error':'Empty payload'}),400
    data,err=sanitize_metric(raw)
    if err: platform_stats['requests_failed']+=1; return jsonify({'error':err}),400
    did=data['device_id']; dtype=data['device_type']; proto=data.get('protocol','Ethernet')
    features=[data.get('cpu_load',50),data.get('bandwidth_mbps',100),data.get('latency_ms',10),
              data.get('packet_loss',0),data.get('connected_devices',10),
              data.get('temperature',40),data.get('signal_strength',80)]
    arr=np.array([features]); score=float(np.clip(rf_model.predict(arr)[0],0,100))
    if dtype=='cbs_controller': score=min(score,data.get('signal_strength',score))
    anom=bool(iso_model.predict(arr)[0]==-1)
    if anom: anomaly_count+=1
    with scoring_lock: scoring_queue.append({'features':features,'device_id':did})
    device_history.setdefault(did,[]).append(score)
    if len(device_history[did])>20: device_history[did].pop(0)
    reading_window.append(score)
    if len(reading_window)>10: reading_window.pop(0)
    predicted=max(0,min(100,score+(reading_window[-1]-reading_window[0]))) if len(reading_window)>=3 else score
    fail_prob=get_failure_probability(did,score)
    fhi=get_federated_health_index([h[-1] for h in device_history.values() if h])
    update_uptime(did,score)
    integrity_score=None; vibration_score=None
    if dtype=='cbs_controller':
        integrity_score,vibration_score=get_cbs_integrity_score(did,score,data)
        _cbs_integrity_cache[did]={'integrity_score':integrity_score,'vibration_score':vibration_score}
    eff_hold=(data.get('blast_hold',False) or (dtype=='cbs_controller' and (
        score<CBS_SAFETY_THRESHOLD or (integrity_score is not None and integrity_score<CBS_SAFETY_THRESHOLD))))
    ai_diag=None; auto_cmd=None
    if anom or score<50 or eff_hold:
        ai_diag=get_diagnosis(dtype,proto,data.get('metric_name',''),data.get('metric_value',0),score,anom,integrity_score)
        auto_cmd=get_auto_cmd(did,dtype,score,eff_hold,integrity_score)
    rec={'device_id':did,'device_type':dtype,'metric_name':data.get('metric_name','unknown'),
         'metric_value':float(data.get('metric_value',0)),'health_score':score,'anomaly_flag':anom,
         'predicted_score':predicted,'ai_diagnosis':ai_diag,'automation_command':auto_cmd}
    if integrity_score is not None: rec['integrity_score']=integrity_score; rec['vibration_score']=vibration_score
    with queue_lock: metric_queue.append(rec)
    if score<50 or anom:
        try: supabase.table('incidents').insert({'device_id':did,'device_type':dtype,
                 'health_score':score,'ai_diagnosis':ai_diag,'automation_command':auto_cmd,'status':'open'}).execute()
        except: pass
    if eff_hold:
        sse_broadcast('cbs_hold',{'device_id':did,'health_score':round(score,1),
                                   'integrity_score':integrity_score,'blast_hold':True,'automation_command':auto_cmd})
        ig_str=f'{integrity_score:.1f}' if integrity_score is not None else f'{score:.1f}'
        notify_all(f'CBS BLAST HOLD -- {did}',f'Link {score:.1f}% / integrity {ig_str}%.',
                   level='cbs',device_id=did,health_score=score,diagnosis=ai_diag,automation_command=auto_cmd)
    elif score<20 and dtype in ['ventilation','pump']:
        notify_all(f'EMERGENCY: {did}',f'{dtype} at {score:.1f}%.',
                   level='critical',device_id=did,health_score=score,diagnosis=ai_diag,automation_command=auto_cmd)
    return jsonify({'status':'ok','health_score':round(score,1),'anomaly_flag':anom,
        'predicted_score':round(predicted,1),'failure_probability':fail_prob,'ai_diagnosis':ai_diag,
        'automation_command':auto_cmd,'federated_index':fhi,'uptime_pct':get_uptime_pct(did),
        'blast_hold':eff_hold,'integrity_score':integrity_score,'vibration_score':vibration_score,
        'protocol':proto,'retrain_needed':anomaly_count>=RETRAIN_THRESHOLD,
        'ettf_minutes':get_ettf_minutes(did,score,dtype)})

@app.route('/api/platform')
async def platform_api():
    up=(datetime.now(timezone.utc)-datetime.fromisoformat(
        platform_stats['uptime_start'].replace('Z','+00:00')
        if platform_stats['uptime_start'].endswith('Z')
        else platform_stats['uptime_start'])).total_seconds()
    return jsonify({'queue_depth':len(metric_queue),'scoring_queue':len(scoring_queue),
        'cache_age_seconds':round(time.time()-_data_cache['ts'],1),'devices_tracked':len(device_history),
        'anomaly_count':anomaly_count,'retrain_needed':anomaly_count>=RETRAIN_THRESHOLD,
        'retrain_in_progress':_retrain_in_progress,'platform_uptime_h':round(up/3600,2),
        'platform_stats':platform_stats,'demo_mode':os.environ.get('DEMO_MODE','false').lower()=='true',
        'notifications':{'email_enabled':NOTIFY['email_enabled'],'sms_enabled':NOTIFY['sms_enabled'],
            'whatsapp_enabled':NOTIFY['whatsapp_enabled'],'recent':list(notification_log)[:5]}})

@app.route('/api/intelligence')
async def get_intelligence():
    recent={d:h[-1] for d,h in device_history.items() if h}
    all_d=get_cached_data(); dtype_map={r['device_id']:r.get('device_type','') for r in all_d}
    ttf_data={}
    for d,score in recent.items():
        ttf=get_ettf_minutes(d,score,dtype_map.get(d,''))
        if ttf is not None: ttf_data[d]=ttf
    return jsonify({'federated_index':get_federated_health_index(list(recent.values())),
        'device_scores':recent,'uptime':{d:get_uptime_pct(d) for d in device_uptime},
        'failure_probabilities':{d:get_failure_probability(d,recent[d]) for d in recent},
        'ttf_minutes':ttf_data,
        'retrain_needed':anomaly_count>=RETRAIN_THRESHOLD,'anomaly_count':anomaly_count,
        'total_devices':len(device_history)})

@app.route('/api/twin/<device_id>')
async def digital_twin(device_id):
    h=device_history.get(device_id,[])
    if not h: return jsonify({'error':'No history'}),404
    cur=h[-1]; scenarios=[]
    for mult in [1.1,1.2,1.5,2.0]:
        arr=np.array([[min(100,50*mult),min(1000,100*mult),min(500,10*mult),min(20,mult*.5),10,40,80]])
        sim=float(np.clip(rf_model.predict(arr)[0],0,100)); anom=bool(iso_model.predict(arr)[0]==-1)
        scenarios.append({'load_increase':f'+{int((mult-1)*100)}%','predicted_score':round(sim,1),
            'anomaly_predicted':anom,'risk':'critical' if sim<30 else 'warning' if sim<60 else 'safe'})
    trend={'slope_per_reading':0,'direction':'insufficient data'}
    if len(h)>=5:
        slope=(h[-1]-h[-5])/4; rtc=round((cur-20)/abs(slope)) if slope<0 and cur>20 else None
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
async def get_weather():
    loc_key=request.args.get('loc','byo'); loc=LOCATIONS.get(loc_key,LOCATIONS['byo'])
    try:
        url=(f"https://api.open-meteo.com/v1/forecast?latitude={loc['lat']}&longitude={loc['lon']}"
             f"&current=temperature_2m,relative_humidity_2m,wind_speed_10m,wind_gusts_10m,"
             f"precipitation,weather_code,cloud_cover&hourly=wind_speed_10m,precipitation_probability"
             f"&forecast_days=2&timezone=Africa/Harare")
        r=req.get(url,timeout=10).json(); cur=r.get('current',{}); hrly=r.get('hourly',{})
        wind=cur.get('wind_speed_10m',0); gusts=cur.get('wind_gusts_10m',0)
        precip=cur.get('precipitation',0); temp=cur.get('temperature_2m',25)
        alerts=[]
        if wind>40: alerts.append(f'High winds {wind:.0f}km/h -- microwave at risk')
        if gusts>60: alerts.append(f'Dangerous gusts {gusts:.0f}km/h -- tower stability risk')
        if precip>10: alerts.append(f'Heavy precipitation {precip:.1f}mm -- pump load increasing')
        if temp>38: alerts.append(f'Extreme heat {temp:.0f}C -- thermal stress elevated')
        pp24=hrly.get('precipitation_probability',[])[:24]
        return jsonify({'location':loc['name'],'temperature':temp,'humidity':cur.get('relative_humidity_2m',50),
            'wind_speed':wind,'wind_gusts':gusts,'precipitation':precip,
            'weather_code':cur.get('weather_code',0),'cloud_cover':cur.get('cloud_cover',0),
            'alerts':alerts,'equipment_impact':[],'max_precip_probability_24h':max(pp24) if pp24 else 0,
            'hourly_wind':hrly.get('wind_speed_10m',[])[:24],'hourly_precip_prob':pp24})
    except Exception as e:
        return jsonify({'error':str(e),'location':loc['name'],'temperature':25,'humidity':50,
            'wind_speed':0,'wind_gusts':0,'precipitation':0,'weather_code':0,'cloud_cover':0,
            'alerts':[],'equipment_impact':[],'max_precip_probability_24h':0,
            'hourly_wind':[],'hourly_precip_prob':[]}),200

@app.route('/api/login',methods=['POST','OPTIONS'])
async def login():
    if request.method=='OPTIONS': return '',204
    try: data=await request.get_json(force=True,silent=True) or {}
    except Exception: data={}
    try:
        r=supabase.table('specialists').select('*').eq('name',data.get('name','')).eq('password',data.get('password','')).execute()
        if r.data:
            s=r.data[0]; return jsonify({'success':True,'token':data.get('password'),'name':s['name'],'role':s.get('role','engineer')})
        return jsonify({'success':False}),401
    except Exception as e: return jsonify({'success':False,'error':str(e)}),500

@app.route('/api/incidents')
@require_specialist
async def get_incidents():
    status=request.args.get('status','open')
    return jsonify(supabase.table('incidents').select('*').eq('status',status).limit(50).execute().data)

@app.route('/api/incidents/<inc_id>/assign',methods=['POST'])
@require_specialist
async def assign_incident(inc_id):
    try: data=await request.get_json(force=True,silent=True) or {}
    except Exception: data={}
    supabase.table('incidents').update({'assigned_to':data.get('assigned_to',''),
        'notes':data.get('notes',''),'status':'assigned'}).eq('id',inc_id).execute()
    return jsonify({'success':True})

@app.route('/api/incidents/<inc_id>/resolve',methods=['POST'])
@require_specialist
async def resolve_incident(inc_id):
    try: data=await request.get_json(force=True,silent=True) or {}
    except Exception: data={}
    supabase.table('incidents').update({'resolved_by':data.get('resolved_by',''),
        'notes':data.get('notes',''),'status':'resolved'}).eq('id',inc_id).execute()
    return jsonify({'success':True})

@app.route('/api/shift-report')
@require_specialist
async def shift_report():
    try:
        resp=supabase.table('metrics').select('*').limit(500).execute()
        inc=supabase.table('incidents').select('*').limit(100).execute()
        dm={}
        for row in resp.data:
            if row['device_id'] not in dm: dm[row['device_id']]=row
        crit=[d for d in dm.values() if d['health_score']<20]
        warn=[d for d in dm.values() if 20<=d['health_score']<50]
        ok  =[d for d in dm.values() if d['health_score']>=50]
        oi  =[i for i in inc.data if i['status']=='open']
        scores=[d['health_score'] for d in dm.values()]
        return jsonify({'generated_at':datetime.now(timezone.utc).isoformat(),
            'total_devices':len(dm),'avg_health':round(sum(scores)/len(scores),1) if scores else 100,
            'critical_devices':len(crit),'warning_devices':len(warn),'healthy_devices':len(ok),
            'open_incidents':len(oi),
            'top_risks':[{'device':d['device_id'],'score':round(d['health_score'],1),'diagnosis':d.get('ai_diagnosis','')}
                for d in sorted(crit+warn,key=lambda x:x['health_score'])[:5]],
            'automation_commands':[{'device':d['device_id'],'command':d['automation_command']}
                for d in dm.values() if d.get('automation_command')]})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/notify/test',methods=['POST'])
@require_specialist
async def test_notify():
    try: data=await request.get_json(force=True,silent=True) or {}
    except Exception: data={}
    ch=data.get('channel','all'); msg='IISentinel test notification -- channels operational'
    if ch in ('sms','all'): threading.Thread(target=send_sms,args=(msg,),daemon=True).start()
    if ch in ('whatsapp','all'): threading.Thread(target=send_whatsapp,args=(msg,),daemon=True).start()
    if ch in ('email','all'): threading.Thread(target=send_email,kwargs=dict(subject='Test',body=msg,severity='info'),daemon=True).start()
    return jsonify({'ok':True,'channel':ch})

@app.route('/api/stream')
async def sse_stream():
    q=asyncio.Queue(maxsize=60)
    with _sse_lock: _sse_queues.append(q)
    async def generate():
        try:
            yield 'event: connected\ndata: {"ok":true}\n\n'
            while True:
                try:
                    msg=await asyncio.wait_for(q.get(),timeout=25)
                    yield msg
                except asyncio.TimeoutError:
                    yield ':heartbeat\n\n'
        finally:
            with _sse_lock:
                try: _sse_queues.remove(q)
                except ValueError: pass
    return Response(generate(),mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Connection':'keep-alive'})

@app.route('/api/export-pdf')
async def export_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,HRFlowable
    except ImportError:
        return jsonify({'error':'pip install reportlab'}),500
    buf=BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=20*mm,bottomMargin=18*mm)
    DARK=colors.HexColor('#0c1122'); ACCENT=colors.HexColor('#34c6f4')
    GREEN=colors.HexColor('#20e07a'); AMBER=colors.HexColor('#f5a020')
    RED=colors.HexColor('#ff3e50'); MUTED=colors.HexColor('#8592a8'); ROW=colors.HexColor('#f0f4fa')
    styles=getSampleStyleSheet()
    def sty(n='Normal',**kw): return ParagraphStyle(n,parent=styles['Normal'],**kw)
    hdr=sty(fontName='Helvetica-Bold',fontSize=8,textColor=colors.white)
    cel=sty(fontName='Helvetica',fontSize=8,textColor=DARK)
    recent={d:h[-1] for d,h in device_history.items() if h}; scores=list(recent.values())
    fhi=get_federated_health_index(scores)
    crit=sum(1 for s in scores if s<20); warn=sum(1 for s in scores if 20<=s<50); ok=sum(1 for s in scores if s>=50)
    probs={d:get_failure_probability(d,recent[d]) for d in recent}
    all_d=get_cached_data(); dtype_map={r['device_id']:r.get('device_type','') for r in all_d}
    total_exp=sum(round(COST_RATES.get('sensor',8000)*(0.95 if s<20 else 0.6 if s<35 else 0.25 if s<50 else 0)) for s in scores)
    now_s=datetime.now(timezone.utc).strftime('%d %B %Y  %H:%M UTC')
    story=[]
    story.append(Paragraph('IISentinel',sty(fontName='Helvetica-Bold',fontSize=22,textColor=DARK,spaceAfter=2)))
    story.append(Paragraph('Intelligent Infrastructure Sentinel -- Shift Report',sty(fontName='Helvetica',fontSize=10,textColor=MUTED,spaceAfter=4)))
    story.append(Paragraph(f'Generated: {now_s}',sty(fontName='Helvetica',fontSize=9,textColor=MUTED,spaceAfter=8)))
    story.append(HRFlowable(width='100%',thickness=1.5,color=ACCENT,spaceAfter=10))
    story.append(Paragraph('Platform Summary',sty(fontName='Helvetica-Bold',fontSize=12,textColor=DARK,spaceBefore=4,spaceAfter=6)))
    kpi=[[Paragraph(c,hdr) for c in ['Metric','Value','Status']],
         [Paragraph(c,cel) for c in ['Federated Health Index',f'{fhi:.1f}/100','HEALTHY' if fhi>=70 else 'WARNING' if fhi>=40 else 'CRITICAL']],
         [Paragraph(c,cel) for c in ['Total Devices',str(len(recent)),'--']],
         [Paragraph(c,cel) for c in ['Critical (<20)',str(crit),'ALERT' if crit else 'NONE']],
         [Paragraph(c,cel) for c in ['Warning (20-50)',str(warn),'MONITOR' if warn else 'NONE']],
         [Paragraph(c,cel) for c in ['Healthy (>=50)',str(ok),'OK']],
         [Paragraph(c,cel) for c in ['Anomalies',str(anomaly_count),'HIGH' if anomaly_count>=RETRAIN_THRESHOLD else 'NORMAL']],
         [Paragraph(c,cel) for c in ['Hourly Risk Exposure',f'${total_exp:,}/hr','ELEVATED' if total_exp>50000 else 'MANAGED']]]
    kt=Table(kpi,colWidths=[75*mm,60*mm,40*mm])
    kt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),DARK),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,ROW]),
        ('GRID',(0,0),(-1,-1),0.35,colors.HexColor('#d4daea')),
        ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),('LEFTPADDING',(0,0),(-1,-1),7)]))
    story.append(kt); story.append(Spacer(1,8))
    if recent:
        story.append(Paragraph('Device Health Register + Estimated Time to Failure',
            sty(fontName='Helvetica-Bold',fontSize=9,textColor=ACCENT,spaceBefore=8,spaceAfter=4)))
        drows=[[Paragraph(c,hdr) for c in ['Device','Score','Risk','ETTF','Status']]]
        for did,s in sorted(recent.items(),key=lambda x:x[1])[:20]:
            p2=probs.get(did,0); stat='CRITICAL' if s<20 else 'WARNING' if s<50 else 'OK'
            col=RED if s<20 else AMBER if s<50 else GREEN
            dtype=dtype_map.get(did,''); ttf=get_ettf_minutes(did,s,dtype)
            ttf_str=(f'{ttf}min' if ttf is not None and ttf<60 else
                     f'{ttf//60}h {ttf%60}m' if ttf is not None else 'N/A')
            drows.append([Paragraph(did[-36:],cel),
                Paragraph(f'{s:.0f}',sty(fontName='Helvetica-Bold',fontSize=8,textColor=col)),
                Paragraph(f'{p2:.0f}%',cel),Paragraph(ttf_str,cel),
                Paragraph(stat,sty(fontName='Helvetica-Bold',fontSize=8,textColor=col))])
        dt=Table(drows,colWidths=[68*mm,18*mm,22*mm,28*mm,22*mm])
        dt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),DARK),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,ROW]),
            ('GRID',(0,0),(-1,-1),0.35,colors.HexColor('#d4daea')),
            ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),('LEFTPADDING',(0,0),(-1,-1),5)]))
        story.append(dt)
    story.append(Spacer(1,14)); story.append(HRFlowable(width='100%',thickness=0.7,color=MUTED,spaceAfter=5))
    story.append(Paragraph(f'IISentinel Confidential -- {now_s}',
        sty(fontName='Helvetica-Oblique',fontSize=7,textColor=MUTED)))
    doc.build(story); buf.seek(0)
    response=await make_response(buf.getvalue())
    response.headers['Content-Type']='application/pdf'
    ts=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')
    response.headers['Content-Disposition']=f'attachment; filename="IISentinel_Report_{ts}.pdf"'
    return response

import socket as _socket
import ipaddress as _ipaddress
from collections import deque as _deque

_nodes={}; _nodes_lock=threading.Lock()
_PORTS=[80,443,22,161,8080,23,21]

def _tcp_probe(host,timeout=1.2):
    for port in _PORTS:
        try:
            t0=time.time(); s=_socket.create_connection((host,port),timeout=timeout); s.close()
            return True,round((time.time()-t0)*1000)
        except Exception: continue
    try:
        t0=time.time(); _socket.getaddrinfo(host,None,_socket.AF_INET,_socket.SOCK_STREAM)
        return True,round((time.time()-t0)*1000)
    except Exception: return False,None

def _poll_node(node_id):
    with _nodes_lock:
        if node_id not in _nodes: return
        node=dict(_nodes[node_id])
    reachable,latency=_tcp_probe(node['host']); now=time.time()
    loss_count=sum(1 for _ in range(3) if not _tcp_probe(node['host'],timeout=0.6)[0])
    loss_pct=round((loss_count/3)*100)
    health=0 if not reachable else max(0,round(100-min(50,(latency or 0)/10)-loss_pct*0.6))
    status='up' if reachable else 'down'
    with _nodes_lock:
        if node_id not in _nodes: return
        _nodes[node_id].update({'status':status,'latency_ms':latency,'loss_pct':loss_pct,
                                 'last_check':now,'health_score':health})
        hist=_nodes[node_id].get('history',_deque(maxlen=20))
        hist.append({'ts':now,'status':status,'latency':latency,'health':health})
        _nodes[node_id]['history']=hist
        sector=_nodes[node_id].get('sector','net')
        label=_nodes[node_id].get('label',node['host'])
        did=f"{sector}-node-{node_id[:8]}"
    try:
        features=[min(100,(latency or 0)/5),max(0,100-loss_pct*2),min(500,latency or 0),loss_pct,1,35,health]
        arr=np.array([features]); score=float(np.clip(rf_model.predict(arr)[0],0,100))
        anom=bool(iso_model.predict(arr)[0]==-1)
        device_history.setdefault(did,[]).append(score)
        if len(device_history[did])>20: device_history[did].pop(0)
        update_uptime(did,score)
        rec={'device_id':did,'device_type':'router' if sector=='net' else 'base_station' if sector=='tc' else 'sensor',
             'metric_name':'latency_ms','metric_value':float(latency or 0),
             'health_score':score,'anomaly_flag':anom,'predicted_score':score,
             'ai_diagnosis':(f'Node {label} unreachable -- 100% packet loss. Dispatch field engineer.'
                             if not reachable else (f'High latency {latency}ms on probe. Inspect uplink.'
                             if (latency or 0)>120 else None)),
             'automation_command':(f'ALERT: Node {label} ({node["host"]}) is DOWN.' if not reachable else None)}
        with queue_lock: metric_queue.append(rec)
    except Exception as e: print(f'[NodePoll] {e}')

def _background_poller():
    while True:
        time.sleep(30)
        with _nodes_lock: ids=list(_nodes.keys())
        for nid in ids: threading.Thread(target=_poll_node,args=(nid,),daemon=True).start()

threading.Thread(target=_background_poller,daemon=True).start()

def _restore_nodes_from_db():
    time.sleep(2)
    try:
        con=sqlite3.connect(_DB_PATH)
        rows=con.execute("SELECT id,host,label,sector FROM nodes").fetchall(); con.close()
        for row in rows:
            nid,host,label,sector=row
            with _nodes_lock:
                if nid not in _nodes:
                    _nodes[nid]={'host':host,'label':label,'sector':sector,'status':'checking',
                                 'latency_ms':None,'loss_pct':0,'last_check':None,'health_score':0,
                                 'hops':[],'history':_deque(maxlen=20)}
            threading.Thread(target=_poll_node,args=(nid,),daemon=True).start()
        if rows: print(f'[Nodes] Restored {len(rows)} nodes')
    except Exception as e: print(f'[Nodes] Restore: {e}')

threading.Thread(target=_restore_nodes_from_db,daemon=True).start()

@app.route('/api/nodes',methods=['GET'])
async def get_nodes():
    sector=request.args.get('sector',None)
    with _nodes_lock:
        result={}
        for nid,node in _nodes.items():
            if sector and node.get('sector')!=sector: continue
            result[nid]={'id':nid,'host':node['host'],'label':node['label'],
                'sector':node.get('sector','net'),'status':node.get('status','unknown'),
                'latency_ms':node.get('latency_ms'),'loss_pct':node.get('loss_pct',0),
                'health_score':node.get('health_score',0),'last_check':node.get('last_check'),
                'hops':node.get('hops',[]),'history':list(node.get('history',[]))}
    return jsonify(result)

@app.route('/api/nodes',methods=['POST'])
async def add_node():
    try: data=await request.get_json(force=True,silent=True) or {}
    except Exception: data={}
    host=str(data.get('host','')).strip(); label=str(data.get('label',host)).strip()[:60]
    sector=str(data.get('sector','net')).strip()
    if not host or len(host)>253: return jsonify({'error':'Invalid host'}),400
    if sector not in ('net','tc','mc'): sector='net'
    import hashlib
    node_id=hashlib.md5(f"{sector}:{host}".encode()).hexdigest()[:12]
    with _nodes_lock:
        if node_id in _nodes: return jsonify({'error':'Node already registered','id':node_id}),409
        _nodes[node_id]={'host':host,'label':label,'sector':sector,'status':'checking',
                         'latency_ms':None,'loss_pct':0,'last_check':None,'health_score':0,
                         'hops':[],'history':_deque(maxlen=20)}
    try:
        con=sqlite3.connect(_DB_PATH)
        con.execute("INSERT OR REPLACE INTO nodes (id,host,label,sector,created_at) VALUES (?,?,?,?,?)",
                    (node_id,host,label,sector,datetime.utcnow().isoformat()))
        con.commit(); con.close()
    except Exception as e: print(f'[Nodes] persist: {e}')
    threading.Thread(target=_poll_node,args=(node_id,),daemon=True).start()
    return jsonify({'id':node_id,'host':host,'label':label,'sector':sector,'status':'checking'})

@app.route('/api/nodes/<node_id>',methods=['DELETE'])
async def delete_node(node_id):
    with _nodes_lock:
        if node_id not in _nodes: return jsonify({'error':'Not found'}),404
        del _nodes[node_id]
    try:
        con=sqlite3.connect(_DB_PATH); con.execute("DELETE FROM nodes WHERE id=?",(node_id,))
        con.commit(); con.close()
    except Exception as e: print(f'[Nodes] delete: {e}')
    return jsonify({'ok':True})

@app.route('/api/nodes/<node_id>/poll',methods=['POST'])
async def poll_node_now(node_id):
    with _nodes_lock:
        if node_id not in _nodes: return jsonify({'error':'Not found'}),404
        _nodes[node_id]['status']='checking'
    threading.Thread(target=_poll_node,args=(node_id,),daemon=True).start()
    return jsonify({'ok':True,'status':'checking'})

@app.route('/api/check-node',methods=['POST'])
async def check_node_legacy():
    try: data=await request.get_json(force=True,silent=True) or {}
    except Exception: data={}
    host=str(data.get('host','')).strip()
    if not host: return jsonify({'error':'Invalid host'}),400
    reachable,latency=_tcp_probe(host)
    return jsonify({'host':host,'reachable':reachable,'latency_ms':latency})

_scan_results={}

@app.route('/api/nodes/scan',methods=['POST'])
async def scan_subnet():
    try: data=await request.get_json(force=True,silent=True) or {}
    except Exception: data={}
    cidr=str(data.get('cidr','')).strip(); sector=str(data.get('sector','net')).strip()
    try: net=_ipaddress.ip_network(cidr,strict=False)
    except ValueError: return jsonify({'error':'Invalid CIDR. Use format: 192.168.1.0/24'}),400
    hosts=list(net.hosts())
    if len(hosts)>254: return jsonify({'error':'Subnet too large -- use /24 or smaller'}),400
    scan_id=f"scan-{int(time.time())}"
    def _do_scan():
        found=[]
        for ip in hosts:
            ok,lat=_tcp_probe(str(ip),timeout=0.8)
            if ok: found.append({'host':str(ip),'latency':lat})
            if len(found)>=30: break
        _scan_results[scan_id]={'done':True,'found':found,'sector':sector}
    _scan_results[scan_id]={'done':False,'found':[],'sector':sector}
    threading.Thread(target=_do_scan,daemon=True).start()
    return jsonify({'scan_id':scan_id,'hosts_to_scan':len(hosts)})

@app.route('/api/nodes/scan-status/<scan_id>',methods=['GET'])
async def scan_status(scan_id):
    return jsonify(_scan_results.get(scan_id,{'done':False,'found':[]}))

if __name__=='__main__':
    demo=os.environ.get('DEMO_MODE','false').lower()=='true'
    print("""
  +------------------------------------------------------+
  |  IISentinel v3.0  --  Intelligent Infrastructure    |
  +------------------------------------------------------+
  |  Dashboard  ->  http://localhost:5000                |
  |  Health     ->  http://localhost:5000/health         |
  |  PDF Report ->  http://localhost:5000/api/export-pdf |
  |                                                      |
  |  Production: hypercorn app:app --bind 0.0.0.0:5000   |
  +------------------------------------------------------+""")
    if demo: print('  [DEMO MODE] 15 devices, 4 sites -- auto-injecting data')
    print('  Specialist login: Admin / admin123\n')
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=False)
