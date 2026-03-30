import os
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from supabase import create_client
from functools import wraps
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel-secret-2026')

# Load AI models
rf_model = joblib.load('health_model.pkl')
iso_model = joblib.load('anomaly_model.pkl')
scaler = joblib.load('scaler.pkl')

# Supabase setup
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# In-memory stores
reading_window = []
device_history = {}
device_uptime = {}
anomaly_count = 0
RETRAIN_THRESHOLD = 50

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
    prob = min(99.0, round(decline_rate * 3 + (100 - current_score) * 0.3, 1))
    return prob

def get_cross_correlation(device_id, current_score, all_recent):
    correlations = []
    for other_id, other_score in all_recent.items():
        if other_id != device_id and other_score < 50 and current_score < 50:
            correlations.append(other_id)
    if correlations:
        return f"Correlated degradation detected across: {', '.join(correlations[:3])}. Possible shared root cause — check common infrastructure."
    return None

def get_federated_health_index(all_scores):
    if not all_scores:
        return 100.0
    weights = []
    for score in all_scores:
        if score < 20:
            weights.append(score * 0.5)
        elif score < 50:
            weights.append(score * 0.8)
        else:
            weights.append(score)
    return round(sum(weights) / len(weights), 1)

def get_digital_twin_simulation(device_id, device_type, current_score, features):
    simulations = []
    load_increase = features.copy()
    load_increase[0] = min(100, features[0] * 1.2)
    load_increase[1] = min(1000, features[1] * 1.2)
    sim_features = np.array([load_increase])
    sim_score = float(rf_model.predict(sim_features)[0])
    sim_score = max(0, min(100, sim_score))
    if sim_score < current_score - 10:
        simulations.append(
            f"Digital twin predicts score drops to {sim_score:.0f} "
            f"if load increases 20%"
        )
    return simulations[0] if simulations else None

def get_ai_diagnosis(device_id, device_type, metric_name,
                     metric_value, health_score, anomaly):
    issues = []
    actions = []
    if health_score < 20:
        issues.append("critical system failure detected")
        actions.append("immediate intervention required")
    elif health_score < 35:
        issues.append("severe performance degradation")
        actions.append("escalate to network operations team")
    elif health_score < 50:
        issues.append("moderate performance issues detected")
        actions.append("schedule maintenance within 24 hours")
    if 'cpu' in metric_name.lower() and metric_value > 80:
        issues.append(f"CPU load at {metric_value:.1f}% exceeding safe threshold")
        actions.append("check for runaway processes or schedule reboot")
    if 'latency' in metric_name.lower() and metric_value > 100:
        issues.append(f"network latency at {metric_value:.1f}ms indicating congestion")
        actions.append("inspect routing tables and bandwidth allocation")
    if 'packet' in metric_name.lower() and metric_value > 2:
        issues.append(f"packet loss at {metric_value:.1f}% suggesting link instability")
        actions.append("inspect physical connections and switch ports")
    if 'temperature' in metric_name.lower() and metric_value > 75:
        issues.append(f"device temperature at {metric_value:.1f}C approaching thermal limit")
        actions.append("check cooling systems and reduce load immediately")
    if 'bandwidth' in metric_name.lower() and metric_value > 800:
        issues.append(f"bandwidth utilisation at {metric_value:.1f}Mbps near capacity")
        actions.append("implement QoS policies and identify high-traffic sources")
    if anomaly:
        issues.append("statistical anomaly detected by Isolation Forest model")
        actions.append("cross-reference with historical baseline data")
    if not issues:
        return (f"Device {device_id} operating within normal parameters. "
                f"Health score {health_score:.1f}/100. Continue routine monitoring.")
    return (f"{'; '.join(issues).capitalize()}. "
            f"Recommended actions: {'; '.join(actions).capitalize()}.")

def get_automation_command(device_id, device_type, health_score):
    if device_type in ['ventilation', 'pump'] and health_score < 20:
        return (f"EMERGENCY: Initiate safety shutdown for {device_id} "
                f"— underground personnel alert triggered")
    elif health_score < 20:
        return f"CRITICAL: Initiate emergency restart sequence for {device_id}"
    elif health_score < 35:
        return f"WARNING: Reduce load and isolate {device_id} from network"
    elif health_score < 50:
        return f"CAUTION: Schedule maintenance check for {device_id}"
    return None

def update_uptime(device_id, health_score):
    if device_id not in device_uptime:
        device_uptime[device_id] = {'total': 0, 'healthy': 0}
    device_uptime[device_id]['total'] += 1
    if health_score >= 50:
        device_uptime[device_id]['healthy'] += 1

def get_uptime_pct(device_id):
    if device_id not in device_uptime:
        return 100.0
    d = device_uptime[device_id]
    if d['total'] == 0:
        return 100.0
    return round((d['healthy'] / d['total']) * 100, 1)

@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    global anomaly_count
    data = request.json
    device_id = data.get('device_id', 'unknown')
    device_type = data.get('device_type', 'unknown')

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

    # Model 1: Health score
    health_score = float(rf_model.predict(features_arr)[0])
    health_score = max(0, min(100, health_score))

    # Model 2: Anomaly detection
    anomaly_result = iso_model.predict(features_arr)[0]
    anomaly_flag = bool(anomaly_result == -1)
    if anomaly_flag:
        anomaly_count += 1

    # Update device history
    if device_id not in device_history:
        device_history[device_id] = []
    device_history[device_id].append(health_score)
    if len(device_history[device_id]) > 20:
        device_history[device_id].pop(0)

    # Predictive score
    reading_window.append(health_score)
    if len(reading_window) > 10:
        reading_window.pop(0)
    if len(reading_window) >= 3:
        trend = reading_window[-1] - reading_window[0]
        predicted_score = max(0, min(100, health_score + trend))
    else:
        predicted_score = health_score

    # Failure probability
    failure_prob = get_failure_probability(device_id, health_score)

    # Digital twin simulation
    digital_twin_insight = get_digital_twin_simulation(
        device_id, device_type, health_score, features
    )

    # Cross device correlation
    recent_scores = {
        did: hist[-1]
        for did, hist in device_history.items()
        if hist
    }
    correlation_alert = get_cross_correlation(
        device_id, health_score, recent_scores
    )

    # Federated health index
    all_scores = list(recent_scores.values())
    federated_index = get_federated_health_index(all_scores)

    # Uptime tracking
    update_uptime(device_id, health_score)
    uptime_pct = get_uptime_pct(device_id)

    # Auto retrain flag
    retrain_needed = anomaly_count >= RETRAIN_THRESHOLD

    # AI diagnosis
    ai_diagnosis = None
    if anomaly_flag or health_score < 50:
        ai_diagnosis = get_ai_diagnosis(
            device_id, device_type,
            data.get('metric_name', 'unknown'),
            data.get('metric_value', 0),
            health_score, anomaly_flag
        )

    # Automation command
    automation_command = get_automation_command(
        device_id, device_type, health_score
    )

    # Store in Supabase
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

    # Create incident if needed
    if health_score < 50 or anomaly_flag:
        supabase.table('incidents').insert({
            'device_id': device_id,
            'device_type': device_type,
            'health_score': health_score,
            'ai_diagnosis': ai_diagnosis,
            'automation_command': automation_command,
            'status': 'open'
        }).execute()

    return jsonify({
        'status': 'ok',
        'health_score': round(health_score, 1),
        'anomaly_flag': anomaly_flag,
        'predicted_score': round(predicted_score, 1),
        'failure_probability': failure_prob,
        'ai_diagnosis': ai_diagnosis,
        'automation_command': automation_command,
        'digital_twin_insight': digital_twin_insight,
        'correlation_alert': correlation_alert,
        'federated_index': federated_index,
        'uptime_pct': uptime_pct,
        'retrain_needed': retrain_needed,
        'anomaly_count': anomaly_count
    })

@app.route('/api/data', methods=['GET'])
def get_data():
    response = supabase.table('metrics').select('*')\
        .order('created_at', desc=True).limit(100).execute()
    return jsonify(response.data)

@app.route('/api/intelligence', methods=['GET'])
def get_intelligence():
    recent_scores = {
        did: hist[-1]
        for did, hist in device_history.items()
        if hist
    }
    all_scores = list(recent_scores.values())
    return jsonify({
        'federated_index': get_federated_health_index(all_scores),
        'device_scores': recent_scores,
        'uptime': {did: get_uptime_pct(did) for did in device_uptime},
        'failure_probabilities': {
            did: get_failure_probability(did, hist[-1])
            for did, hist in device_history.items() if hist
        },
        'retrain_needed': anomaly_count >= RETRAIN_THRESHOLD,
        'anomaly_count': anomaly_count,
        'total_devices': len(device_history)
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    name = data.get('name', '')
    password = data.get('password', '')
    try:
        result = supabase.table('specialists')\
            .select('*').eq('name', name).eq('password', password).execute()
        if result.data:
            specialist = result.data[0]
            return jsonify({
                'success': True,
                'token': password,
                'name': specialist['name'],
                'role': specialist['role']
            })
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)