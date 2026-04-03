
from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_cors import CORS
import random, math, time, uuid, os, json
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='static')
CORS(app)

# ═══════════════════════════════════════════════════════
#  DATA SIMULATION ENGINE
# ═══════════════════════════════════════════════════════

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
    "wan_link":     ["Latency nominal at 12ms — BGP prefix count stable",
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
                      "Comms restored after 4-minute outage"],
}

AUTOMATION = {
    "router":       "Auto: BGP route refresh triggered on {id}",
    "switch":       "Auto: Port gi0/4 quarantined on {id} — SNMP trap sent",
    "firewall":     "Auto: Rate limiting applied to WAN — {id}",
    "wan_link":     "Auto: Failover to backup link initiated — {id}",
    "base_station": "Auto: Power boost applied sector B — {id}",
    "network_tower":"Auto: Alignment alert raised — engineer dispatched",
    "microwave_link":"Auto: ACM downshift to QPSK applied — {id}",
    "pump":         "Auto: Pump load reduced 20% — engineer alerted — {id}",
    "conveyor":     "Auto: Emergency stop triggered — {id} — maintenance paged",
    "ventilation":  "Auto: Secondary fan engaged — {id} — gas monitor active",
    "plc":          "Auto: PLC watchdog reset — backup program loaded — {id}",
    "scada_node":   "Auto: Historian reconnect attempted — {id}",
    "power_meter":  "Auto: Load shedding relay triggered — {id}",
    "cbs_controller":"CBS SAFETY INTERLOCK: BLAST HOLD on {id} — DNP3 link below threshold",
}

# In-memory state
_device_scores = {}
_incidents = {}
_injected = []

def _base_score(dev_id):
    """Deterministic base score per device so they don't all move identically"""
    h = sum(ord(c) for c in dev_id) % 40
    return 62 + h   # 62–101 range, capped later

def _current_score(dev_id, dev_type):
    """Return a slightly drifting score, stable between calls"""
    base = _device_scores.get(dev_id, _base_score(dev_id))
    # Small random walk ±4 per fetch, stays in realistic range
    delta = random.uniform(-4, 4)
    score = max(8, min(99, base + delta))
    # CBS must stay high unless deliberately degraded
    if dev_type == "cbs_controller":
        score = max(85, score)
    _device_scores[dev_id] = score
    return round(score, 1)

def _metric_for(dev_type, score):
    if dev_type in ("router","wan_link"):
        # latency: low when healthy
        return round(max(2, (100-score)*3 + random.uniform(-5,8)), 1)
    if dev_type in ("switch",):
        return round(random.uniform(50,900), 1)   # bandwidth mbps
    if dev_type in ("firewall",):
        return round(max(5, (100-score)*0.8 + random.uniform(0,10)), 1)  # cpu %
    if dev_type in ("pump","conveyor","ventilation","plc"):
        return round(30 + (100-score)*0.7 + random.uniform(-3,5), 1)  # temp C
    if dev_type in ("base_station","network_tower","microwave_link"):
        return round(score + random.uniform(-5,5), 1)  # signal %
    if dev_type == "cbs_controller":
        return round(score, 1)
    return round(random.uniform(10, 90), 1)

def _metric_name_for(dev_type):
    m = {"router":"latency_ms","wan_link":"latency_ms","switch":"bandwidth_mbps",
         "firewall":"cpu_load","pump":"temperature","conveyor":"temperature",
         "ventilation":"temperature","plc":"temperature","scada_node":"cpu_load",
         "power_meter":"voltage","base_station":"signal_strength",
         "network_tower":"signal_strength","microwave_link":"signal_strength",
         "cbs_controller":"link_health","workstation":"cpu_load"}
    return m.get(dev_type, "metric")

def _diagnosis(dev_type, score):
    options = DIAGNOSES.get(dev_type, ["System operating within parameters"])
    if score >= 70:
        return options[0]
    elif score >= 40:
        return options[min(1, len(options)-1)]
    else:
        return options[min(2, len(options)-1)]

def _auto_cmd(dev_id, dev_type, score):
    if score >= 55:
        return None
    tmpl = AUTOMATION.get(dev_type, "Auto: Alert raised for {id}")
    return tmpl.format(id=dev_id.split("-")[-1]+"-"+dev_id.split("-")[-2] if len(dev_id.split("-"))>2 else dev_id)

def _build_reading(dev):
    did = dev["id"]; dtype = dev["type"]
    score = _current_score(did, dtype)
    mv = _metric_for(dtype, score)
    anom = score < 35 and random.random() < 0.4
    pred = round(max(0, min(100, score + random.uniform(-8,8))), 1)
    diag = _diagnosis(dtype, score)
    auto = _auto_cmd(did, dtype, score)
    return {
        "device_id": did,
        "device_type": dtype,
        "health_score": score,
        "metric_name": _metric_name_for(dtype),
        "metric_value": mv,
        "cpu_load": round(random.uniform(10,95) if score < 50 else random.uniform(5,55), 1),
        "bandwidth_mbps": round(random.uniform(10,950), 1),
        "latency_ms": round(max(1,(100-score)*2.5 + random.uniform(-2,10)),1),
        "packet_loss": round(max(0,(100-score)*0.15 + random.uniform(-0.5,1)),2),
        "connected_devices": random.randint(1, 80),
        "temperature": round(25 + (100-score)*0.6 + random.uniform(-3,5), 1),
        "signal_strength": round(score + random.uniform(-8,8), 1),
        "anomaly_flag": anom,
        "predicted_score": pred,
        "ai_diagnosis": diag,
        "automation_command": auto,
        "created_at": (datetime.utcnow() - timedelta(seconds=random.randint(0,60))).isoformat() + "Z",
    }

# ═══════════════════════════════════════════════════════
#  ROUTES — Static files
# ═══════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_file('dashboard.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# ═══════════════════════════════════════════════════════
#  API — Core data
# ═══════════════════════════════════════════════════════

@app.route('/api/data')
def api_data():
    readings = [_build_reading(d) for d in DEVICE_CATALOG]
    # Append any injected events
    readings.extend(_injected[-10:])
    return jsonify(readings)

@app.route('/api/intelligence')
def api_intelligence():
    all_scores = [_device_scores.get(d["id"], _base_score(d["id"])) for d in DEVICE_CATALOG]
    w = [s * (0.5 if s < 20 else 0.8 if s < 50 else 1) for s in all_scores]
    fed = round(sum(w)/len(w))
    probs = {}
    uptimes = {}
    lifecycles = {}
    for d in DEVICE_CATALOG:
        s = _device_scores.get(d["id"], _base_score(d["id"]))
        prob = max(0, round((100-s)*0.9 + random.uniform(-5,5)))
        probs[d["id"]] = min(95, prob)
        uptimes[d["id"]] = round(min(100, s*0.98 + random.uniform(0,2)), 1)
        base_life = {"pump":8000,"conveyor":12000,"ventilation":15000,
                     "cbs_controller":20000,"router":25000}.get(d["type"], 10000)
        lifecycles[d["id"]] = round(base_life * (s/100) + random.uniform(-200,200))
    anom_count = sum(1 for s in all_scores if s < 35)
    return jsonify({
        "federated_index": fed,
        "total_devices": len(DEVICE_CATALOG),
        "anomaly_count": anom_count,
        "retrain_needed": anom_count > 4,
        "failure_probabilities": probs,
        "uptime": uptimes,
        "lifecycles": lifecycles,
    })

# ═══════════════════════════════════════════════════════
#  API — Metrics injection (sim buttons)
# ═══════════════════════════════════════════════════════

@app.route('/api/metrics', methods=['POST'])
def api_metrics():
    data = request.get_json()
    dev_id = data.get("device_id","sim-device")
    dev_type = data.get("device_type","sensor")
    # Compute a score from incoming metrics
    mv = data.get("metric_value", 50)
    cpu = data.get("cpu_load", 50)
    sig = data.get("signal_strength", 70)
    score = round(max(5, min(99, (sig*0.4 + (100-cpu)*0.4 + (100-min(mv,100))*0.2))))
    # Override for blast
    if data.get("blast_hold"):
        score = round(mv)  # link_health value
    anom = score < 35
    diag = _diagnosis(dev_type, score)
    auto = data.get("automation_override") or _auto_cmd(dev_id, dev_type, score)
    reading = {
        "device_id": dev_id,
        "device_type": dev_type,
        "health_score": score,
        "metric_name": _metric_name_for(dev_type),
        "metric_value": mv,
        "cpu_load": cpu,
        "bandwidth_mbps": data.get("bandwidth_mbps",100),
        "latency_ms": data.get("latency_ms",20),
        "packet_loss": data.get("packet_loss",0),
        "connected_devices": data.get("connected_devices",10),
        "temperature": data.get("temperature",35),
        "signal_strength": sig,
        "anomaly_flag": anom,
        "predicted_score": round(score + random.uniform(-10,10)),
        "ai_diagnosis": diag,
        "automation_command": auto,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    _injected.append(reading)
    _device_scores[dev_id] = score
    # Also create incident if critical
    if score < 40:
        inc_id = str(uuid.uuid4())[:8]
        _incidents[inc_id] = {
            "id": inc_id,
            "device_id": dev_id,
            "device_type": dev_type,
            "health_score": score,
            "ai_diagnosis": diag,
            "automation_command": auto,
            "status": "open",
            "assigned_to": None,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
    return jsonify(reading)

# ═══════════════════════════════════════════════════════
#  API — Weather (Open-Meteo, free, no key)
# ═══════════════════════════════════════════════════════

LOCATIONS = {
    "byo":  {"lat":-20.15, "lon":28.58, "name":"Bulawayo"},
    "hre":  {"lat":-17.83, "lon":31.05, "name":"Harare"},
    "mut":  {"lat":-18.97, "lon":32.65, "name":"Mutare"},
    "mine": {"lat":-19.50, "lon":29.80, "name":"Mine Site"},
}

@app.route('/api/weather')
def api_weather():
    loc_key = request.args.get("loc","byo")
    loc = LOCATIONS.get(loc_key, LOCATIONS["byo"])
    try:
        import urllib.request
        url = (f"https://api.open-meteo.com/v1/forecast?"
               f"latitude={loc['lat']}&longitude={loc['lon']}"
               f"&current=temperature_2m,relative_humidity_2m,precipitation,"
               f"weather_code,wind_speed_10m,wind_gusts_10m,cloud_cover"
               f"&hourly=wind_speed_10m,precipitation_probability"
               f"&forecast_days=1&timezone=Africa%2FHarare")
        with urllib.request.urlopen(url, timeout=6) as r:
            d = json.loads(r.read())
        cur = d["current"]
        hourly = d.get("hourly",{})
        wind    = cur.get("wind_speed_10m",0)
        gusts   = cur.get("wind_gusts_10m",0)
        temp    = cur.get("temperature_2m",28)
        humidity= cur.get("relative_humidity_2m",60)
        precip  = cur.get("precipitation",0)
        wcode   = cur.get("weather_code",0)
        cloud   = cur.get("cloud_cover",20)
        h_wind  = hourly.get("wind_speed_10m",[wind]*24)[:24]
        h_prec  = hourly.get("precipitation_probability",[0]*24)[:24]
        max_pp  = max(h_prec) if h_prec else 0
        alerts  = []
        impact  = []
        if wind > 40:
            alerts.append(f"⚠ High wind {wind}km/h — microwave link degradation likely")
            impact.append({"impact":f"Microwave links: RSL drop expected — reduce modulation order"})
        if temp > 36:
            alerts.append(f"🌡 Heat advisory {temp}°C — equipment cooling critical")
            impact.append({"impact":f"Mining equipment: Pump motor temps +{round(temp-30)}°C above baseline"})
        if max_pp > 60:
            alerts.append(f"🌧 Heavy rain risk {max_pp}% — underground water ingress alert")
            impact.append({"impact":f"Shaft pumps: Expected load increase 35% — pre-stage backup"})
        return jsonify({
            "location": loc["name"],
            "temperature": temp, "humidity": humidity, "precipitation": precip,
            "weather_code": wcode, "wind_speed": wind, "wind_gusts": gusts,
            "cloud_cover": cloud, "max_precip_probability_24h": max_pp,
            "hourly_wind": h_wind, "hourly_precip_prob": h_prec,
            "alerts": alerts, "equipment_impact": impact,
        })
    except Exception as e:
        # Fallback simulated weather if Open-Meteo unreachable
        temp = round(random.uniform(22,38),1)
        wind = round(random.uniform(8,45),1)
        return jsonify({
            "location": loc["name"],
            "temperature": temp, "humidity": random.randint(40,85),
            "precipitation": round(random.uniform(0,5),1),
            "weather_code": random.choice([0,1,2,3,61]),
            "wind_speed": wind, "wind_gusts": round(wind*1.4,1),
            "cloud_cover": random.randint(10,80),
            "max_precip_probability_24h": random.randint(10,70),
            "hourly_wind": [round(wind+random.uniform(-5,5),1) for _ in range(24)],
            "hourly_precip_prob": [random.randint(5,65) for _ in range(24)],
            "alerts": [], "equipment_impact": [],
        })

# ═══════════════════════════════════════════════════════
#  API — Digital twin
# ═══════════════════════════════════════════════════════

@app.route('/api/twin/<path:device_id>')
def api_twin(device_id):
    base = _device_scores.get(device_id, 65)
    scenarios = []
    for load, pct in [("×1.1",10),("×1.2",20),("×1.5",50),("×2.0",100)]:
        score = round(max(5, base - pct*0.7 + random.uniform(-3,3)))
        risk  = "safe" if score>=70 else "warning" if score>=40 else "critical"
        anom  = score < 38
        scenarios.append({"load_increase":load,"predicted_score":score,"risk":risk,"anomaly_predicted":anom})
    slope = round(random.uniform(-2.5,1.2),2)
    rtc   = round(abs(base-20)/max(0.1,abs(slope))) if slope < -0.3 else None
    return jsonify({
        "device_id": device_id, "current_score": round(base),
        "scenarios": scenarios,
        "trend": {"direction":"declining" if slope<-0.3 else "improving" if slope>0.3 else "stable",
                  "slope_per_reading":slope, "readings_to_critical":rtc}
    })

# ═══════════════════════════════════════════════════════
#  API — Platform observability
# ═══════════════════════════════════════════════════════

@app.route('/api/platform')
def api_platform():
    return jsonify({
        "queue_depth": random.randint(0,30),
        "cache_age_seconds": random.randint(3,25),
        "devices_tracked": len(DEVICE_CATALOG) + len(_injected),
        "model_version": "v2.1.4",
        "ingest_rate_per_min": random.randint(180,320),
    })

# ═══════════════════════════════════════════════════════
#  API — Specialist / Auth
# ═══════════════════════════════════════════════════════

USERS = {
    "admin":    {"password":"sentinel2025","role":"administrator","name":"Admin"},
    "engineer": {"password":"iisengineer", "role":"engineer",     "name":"Site Engineer"},
    "ops":      {"password":"opsops",      "role":"ops_manager",  "name":"Ops Manager"},
}
_tokens = {}

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.get_json()
    name = d.get("name","").strip().lower()
    pwd  = d.get("password","").strip()
    user = USERS.get(name)
    if user and user["password"] == pwd:
        token = str(uuid.uuid4())
        _tokens[token] = name
        return jsonify({"success":True,"token":token,"name":user["name"],"role":user["role"]})
    return jsonify({"success":False})

def _check_token():
    return request.headers.get("X-Specialist-Token","") in _tokens

# ═══════════════════════════════════════════════════════
#  API — Incidents
# ═══════════════════════════════════════════════════════

def _seed_incidents():
    """Pre-populate a couple of realistic incidents"""
    if not _incidents:
        for dev in random.sample(DEVICE_CATALOG, 3):
            s = random.uniform(15,45)
            _device_scores[dev["id"]] = s
            inc_id = str(uuid.uuid4())[:8]
            _incidents[inc_id] = {
                "id": inc_id,
                "device_id": dev["id"],
                "device_type": dev["type"],
                "health_score": round(s,1),
                "ai_diagnosis": _diagnosis(dev["type"], s),
                "automation_command": _auto_cmd(dev["id"], dev["type"], s),
                "status": random.choice(["open","assigned"]),
                "assigned_to": "T.Moyo" if random.random()>0.5 else None,
                "created_at": (datetime.utcnow()-timedelta(minutes=random.randint(5,120))).isoformat()+"Z",
            }

_seed_incidents()

@app.route('/api/incidents')
def api_incidents():
    if not _check_token():
        return jsonify({"error":"Unauthorised"}), 401
    status = request.args.get("status")
    result = [v for v in _incidents.values() if not status or v["status"]==status]
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify(result)

@app.route('/api/incidents/<inc_id>/assign', methods=['POST'])
def api_assign(inc_id):
    if not _check_token(): return jsonify({"error":"Unauthorised"}), 401
    d = request.get_json()
    if inc_id in _incidents:
        _incidents[inc_id]["status"]      = "assigned"
        _incidents[inc_id]["assigned_to"] = d.get("assigned_to")
    return jsonify({"ok":True})

@app.route('/api/incidents/<inc_id>/resolve', methods=['POST'])
def api_resolve(inc_id):
    if not _check_token(): return jsonify({"error":"Unauthorised"}), 401
    d = request.get_json()
    if inc_id in _incidents:
        _incidents[inc_id]["status"]      = "resolved"
        _incidents[inc_id]["resolved_by"] = d.get("resolved_by")
    return jsonify({"ok":True})

# ═══════════════════════════════════════════════════════
#  API — Shift report
# ═══════════════════════════════════════════════════════

@app.route('/api/shift-report')
def api_shift_report():
    if not _check_token(): return jsonify({"error":"Unauthorised"}), 401
    scores = [_device_scores.get(d["id"], _base_score(d["id"])) for d in DEVICE_CATALOG]
    crit   = [d for d,s in zip(DEVICE_CATALOG,scores) if s<35]
    warn   = [d for d,s in zip(DEVICE_CATALOG,scores) if 35<=s<70]
    good   = [d for d,s in zip(DEVICE_CATALOG,scores) if s>=70]
    open_i = [v for v in _incidents.values() if v["status"]=="open"]
    top_risks = sorted(
        [{"device":d["id"],"score":round(_device_scores.get(d["id"],80),1),
          "diagnosis":_diagnosis(d["type"],_device_scores.get(d["id"],80))}
         for d in DEVICE_CATALOG],
        key=lambda x: x["score"]
    )[:5]
    return jsonify({
        "total_devices": len(DEVICE_CATALOG),
        "avg_health": round(sum(scores)/len(scores),1),
        "critical_devices": len(crit),
        "warning_devices":  len(warn),
        "healthy_devices":  len(good),
        "open_incidents":   len(open_i),
        "top_risks": top_risks,
        "generated_at": datetime.utcnow().isoformat()+"Z",
    })

# ═══════════════════════════════════════════════════════
#  RUN
# ═══════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"""
  ██████████████████████████████████████████
  ██  IISentinel™ Backend — Starting up   ██
  ██  http://localhost:{port}                ██
  ██  Ctrl+C to stop                      ██
  ██████████████████████████████████████████

  Login credentials:
    admin    / sentinel2025
    engineer / iisengineer
    ops      / opsops

  Place your PNG files in ./static/:
    server-room.png
    tc-tower.png
    mine-plant.png
""")
    app.run(host='0.0.0.0', port=port, debug=False)