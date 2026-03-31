import os
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from supabase import create_client
from functools import wraps
from datetime import datetime, timezone
from autonomous_trainer import start_autonomous_trainer, ingest_reading

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel-secret-2026')

rf_model = joblib.load('health_model.pkl')
iso_model = joblib.load('anomaly_model.pkl')
scaler = joblib.load('scaler.pkl')

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

reading_window = []
device_history = {}
device_uptime = {}
anomaly_count = 0
RETRAIN_THRESHOLD = 50
CBS_SAFETY_THRESHOLD = 90.0

NETWORK_TYPES = ['router', 'switch', 'firewall', 'wan_link', 'workstation']
TELECOM_TYPES = ['base_station', 'network_tower', 'microwave_link']
MINING_TYPES = ['pump', 'conveyor', 'ventilation', 'power_meter', 'sensor',
                'plc', 'scada_node', 'cbs_controller']
PROTOCOL_MAP = {
    'SNMP/Ethernet-802.3': 'SNMP over IEEE 802.3 Ethernet',
    'Profinet/EtherNet-IP': 'Profinet real-time industrial Ethernet',
    'DNP3/Ethernet': 'DNP3 safety-critical control protocol',
    'Modbus-TCP/OPC-UA': 'Modbus TCP with OPC-UA data exchange',
}

def require_specialist(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Specialist-Token')
        if not token:
            return jsonify({'error': 'Unauthorised'}), 401
        try:
            result = supabase.table('specialists')\
                .select('*').eq('password', token).execute()
            if not result.data:
                return jsonify({'error': 'Invalid token'}), 401
        except:
            return jsonify({'error': 'Auth error'}), 401
        return f(*args, **kwargs)
    return decorated

def get_failure_probability(device_id, current_score):
    history = device_history.get(device_id, [])
    if len(history) < 3:
        return 0.0
    recent = history[-5:]
    trend = recent[-1] - recent[0]
    if trend >= 0:
        return max(0.0, round((100 - current_score) * 0.05, 1))
    decline_rate = abs(trend) / len(recent)
    return min(99.0, round(decline_rate * 3 + (100 - current_score) * 0.3, 1))

def get_cross_correlation(device_id, current_score, all_recent):
    correlations = [
        oid for oid, oscore in all_recent.items()
        if oid != device_id and oscore < 50 and current_score < 50
    ]
    if correlations:
        return (f"Correlated degradation across: {', '.join(correlations[:3])}. "
                f"Possible shared root cause — inspect common network segment.")
    return None

def get_federated_health_index(all_scores):
    if not all_scores:
        return 100.0
    weights = [s * 0.5 if s < 20 else s * 0.8 if s < 50 else s for s in all_scores]
    return round(sum(weights) / len(weights), 1)

def get_digital_twin_simulation(device_id, features, current_score):
    load_increase = features.copy()
    load_increase[0] = min(100, features[0] * 1.2)
    load_increase[1] = min(1000, features[1] * 1.2)
    sim_score = float(rf_model.predict(np.array([load_increase]))[0])
    sim_score = max(0, min(100, sim_score))
    if sim_score < current_score - 10:
        return (f"Digital twin: 20% load increase would drop health score "
                f"to {sim_score:.0f}/100 — preemptive action recommended.")
    return None

def get_protocol_diagnosis(device_type, protocol, metric_name,
                           metric_value, health_score, anomaly):
    issues = []
    actions = []
    proto_label = PROTOCOL_MAP.get(protocol, protocol or 'Ethernet')

    if health_score < 20:
        issues.append("critical system failure detected")
        actions.append("immediate intervention required")
    elif health_score < 35:
        issues.append("severe performance degradation")
        actions.append("escalate to operations team")
    elif health_score < 50:
        issues.append("moderate performance degradation")
        actions.append("schedule maintenance within 24 hours")

    if device_type in TELECOM_TYPES:
        if 'latency' in metric_name and metric_value > 100:
            issues.append(f"SNMP reports {metric_value:.1f}ms latency on backhaul link")
            actions.append("inspect BGP routing tables and check fibre link integrity")
        if 'packet' in metric_name and metric_value > 2:
            issues.append(f"packet loss {metric_value:.1f}% detected on {proto_label}")
            actions.append("run BERT test on physical layer and check SFP modules")
        if 'bandwidth' in metric_name and metric_value > 800:
            issues.append(f"bandwidth at {metric_value:.1f}Mbps approaching capacity")
            actions.append("implement NetFlow analysis and consider QoS reprioritisation")
        if 'signal' in metric_name and metric_value < 40:
            issues.append(f"signal strength at {metric_value:.1f}% — link degraded")
            actions.append("inspect microwave alignment or antenna orientation")

    elif device_type in MINING_TYPES:
        if 'temperature' in metric_name and metric_value > 75:
            issues.append(
                f"Profinet reports {metric_value:.1f}C on PLC thermal sensor — "
                f"approaching shutdown threshold")
            actions.append(
                "check cooling fan status via EtherNet/IP diagnostic register "
                "and reduce duty cycle")
        if 'motor' in metric_name and metric_value < 500:
            issues.append(
                f"motor speed at {metric_value:.0f}RPM via Modbus register 101 — "
                f"below minimum operating threshold")
            actions.append(
                "inspect variable frequency drive parameters and check for "
                "overcurrent protection trip")
        if 'vibration' in metric_name and metric_value > 3:
            issues.append(
                f"vibration at {metric_value:.2f}g via OPC-UA node — "
                f"bearing wear indicated")
            actions.append(
                "schedule predictive maintenance inspection within 4 hours")
        if 'pressure' in metric_name and metric_value > 8:
            issues.append(
                f"pressure at {metric_value:.1f}bar via Modbus — "
                f"above safe operating limit")
            actions.append(
                "open bypass valve and alert hydraulics engineer immediately")

    if device_type == 'cbs_controller':
        if health_score < CBS_SAFETY_THRESHOLD:
            issues.append(
                f"CBS DNP3 link health at {health_score:.1f}% — "
                f"below blast safety threshold {CBS_SAFETY_THRESHOLD}%")
            actions.append(
                "BLAST HOLD maintained — notify blasting officer and "
                "inspect DNP3 communication link integrity")

    if anomaly:
        issues.append(
            f"Isolation Forest anomaly on {proto_label} — "
            f"pattern deviates from learned baseline")
        actions.append("cross-reference with device event log")

    if not issues:
        return (f"Device operating within normal parameters via {proto_label}. "
                f"Health score {health_score:.1f}/100.")

    return (f"{'; '.join(issues).capitalize()}. "
            f"Recommended actions: {'; '.join(actions).capitalize()}.")

def get_automation_command(device_id, device_type, health_score,
                           blast_hold=False, automation_override=None):
    if automation_override:
        return automation_override
    if device_type == 'cbs_controller' and health_score < CBS_SAFETY_THRESHOLD:
        return (f"CBS SAFETY INTERLOCK ACTIVE: BLAST HOLD on {device_id} — "
                f"DNP3 link health {health_score:.1f}% below threshold. "
                f"All detonation circuits locked.")
    if device_type in ['ventilation', 'pump'] and health_score < 20:
        return (f"EMERGENCY: Safety shutdown initiated for {device_id} — "
                f"underground personnel evacuation alert triggered via PA system")
    if health_score < 20:
        return f"CRITICAL: Emergency restart sequence for {device_id}"
    if health_score < 35:
        return f"WARNING: Isolate {device_id} from network and reduce load"
    if health_score < 50:
        return f"CAUTION: Schedule maintenance check for {device_id}"
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

@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    global anomaly_count
    data = request.json
    device_id = data.get('device_id', 'unknown')
    device_type = data.get('device_type', 'unknown')
    protocol = data.get('protocol', 'Ethernet')
    blast_hold = data.get('blast_hold', False)
    automation_override = data.get('automation_override', None)

    features = [
        data.get('cpu_load', 50),
        data.get('bandwidth_mbps', 100),
        data.get('latency_ms', 10),
        data.get('packet_loss', 0),
        data.get('connected_devices', 10),
        data.get('temperature', 40),
        data.get('signal_strength', 80)
    ]
    features_arr = np.array([features])

    health_score = float(rf_model.predict(features_arr)[0])
    health_score = max(0, min(100, health_score))

    if device_type == 'cbs_controller':
        health_score = min(health_score, data.get('signal_strength', 100))

    anomaly_result = iso_model.predict(features_arr)[0]
    anomaly_flag = bool(anomaly_result == -1)
    if anomaly_flag:
        anomaly_count += 1

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

    failure_prob = get_failure_probability(device_id, health_score)

    digital_twin = get_digital_twin_simulation(device_id, features, health_score)

    recent_scores = {
        did: hist[-1] for did, hist in device_history.items() if hist
    }
    correlation = get_cross_correlation(device_id, health_score, recent_scores)

    federated_index = get_federated_health_index(list(recent_scores.values()))

    update_uptime(device_id, health_score)
    uptime_pct = get_uptime_pct(device_id)

    ai_diagnosis = None
    if anomaly_flag or health_score < 50 or device_type == 'cbs_controller':
        ai_diagnosis = get_protocol_diagnosis(
            device_type, protocol,
            data.get('metric_name', 'unknown'),
            data.get('metric_value', 0),
            health_score, anomaly_flag
        )

    automation_command = get_automation_command(
        device_id, device_type, health_score,
        blast_hold, automation_override
    )

    supabase.table('metrics').insert({
        'device_type': device_type,
        'device_id': device_id,
        'metric_name': data.get('metric_name', 'unknown'),
        'metric_value': float(data.get('metric_value', 0)),
        'health_score': health_score,
        'anomaly_flag': anomaly_flag,
        'predicted_score': predicted_score,
        'ai_diagnosis': ai_diagnosis,
        'automation_command': automation_command
    }).execute()

    if health_score < 50 or anomaly_flag or blast_hold:
        supabase.table('incidents').insert({
            'device_id': device_id,
            'device_type': device_type,
            'health_score': health_score,
            'ai_diagnosis': ai_diagnosis,
            'automation_command': automation_command,
            'status': 'open'
        }).execute()
    ingest_reading(data)
    return jsonify({
        'status': 'ok',
        'health_score': round(health_score, 1),
        'anomaly_flag': anomaly_flag,
        'predicted_score': round(predicted_score, 1),
        'failure_probability': failure_prob,
        'ai_diagnosis': ai_diagnosis,
        'automation_command': automation_command,
        'digital_twin_insight': digital_twin,
        'correlation_alert': correlation,
        'federated_index': federated_index,
        'uptime_pct': uptime_pct,
        'retrain_needed': anomaly_count >= RETRAIN_THRESHOLD,
        'anomaly_count': anomaly_count,
        'protocol': protocol,
        'blast_hold': blast_hold
    })

@app.route('/api/data', methods=['GET'])
def get_data():
    sector = request.args.get('sector', None)
    query = supabase.table('metrics').select('*')\
        .order('created_at', desc=True).limit(200)
    response = query.execute()
    data = response.data
    if sector == 'telecom':
        data = [r for r in data if r['device_type'] in TELECOM_TYPES]
    elif sector == 'mining':
        data = [r for r in data if r['device_type'] in MINING_TYPES]
    return jsonify(data[:100])

@app.route('/api/intelligence', methods=['GET'])
def get_intelligence():
    recent_scores = {
        did: hist[-1] for did, hist in device_history.items() if hist
    }
    return jsonify({
        'federated_index': get_federated_health_index(list(recent_scores.values())),
        'device_scores': recent_scores,
        'uptime': {did: get_uptime_pct(did) for did in device_uptime},
        'failure_probabilities': {
            did: get_failure_probability(did, hist[-1])
            for did, hist in device_history.items() if hist
        },
        'retrain_needed': anomaly_count >= RETRAIN_THRESHOLD,
        'anomaly_count': anomaly_count,
        'total_devices': len(device_history),
        'cbs_devices': [
            did for did, hist in device_history.items()
            if hist and did.startswith('cbs')
        ]
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    try:
        result = supabase.table('specialists')\
            .select('*')\
            .eq('name', data.get('name', ''))\
            .eq('password', data.get('password', '')).execute()
        if result.data:
            s = result.data[0]
            return jsonify({
                'success': True, 'token': data.get('password'),
                'name': s['name'], 'role': s['role']
            })
        return jsonify({'success': False}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/incidents', methods=['GET'])
@require_specialist
def get_incidents():
    status = request.args.get('status', 'open')
    response = supabase.table('incidents').select('*')\
        .eq('status', status)\
        .order('created_at', desc=True).limit(50).execute()
    return jsonify(response.data)

@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
@require_specialist
def assign_incident(incident_id):
    data = request.json
    supabase.table('incidents').update({
        'assigned_to': data.get('assigned_to', ''),
        'notes': data.get('notes', ''),
        'status': 'assigned'
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})

@app.route('/api/incidents/<incident_id>/resolve', methods=['POST'])
@require_specialist
def resolve_incident(incident_id):
    data = request.json
    supabase.table('incidents').update({
        'resolved_by': data.get('resolved_by', ''),
        'notes': data.get('notes', ''),
        'status': 'resolved'
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})

@app.route('/')
def dashboard():
    return render_template('dashboard.html')
start_autonomous_trainer()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)