import os
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template
from supabase import create_client

app = Flask(__name__)

# Load AI models
rf_model = joblib.load('health_model.pkl')
iso_model = joblib.load('anomaly_model.pkl')
scaler = joblib.load('scaler.pkl')

# Supabase setup
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Rolling window for prediction
reading_window = []

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

    issue_str = "; ".join(issues).capitalize()
    action_str = "; ".join(actions).capitalize()
    return f"{issue_str}. Recommended actions: {action_str}."

def get_automation_command(device_id, health_score):
    if health_score < 20:
        return f"CRITICAL: Initiate emergency restart sequence for {device_id}"
    elif health_score < 35:
        return f"WARNING: Reduce load and isolate {device_id} from network"
    elif health_score < 50:
        return f"CAUTION: Schedule maintenance check for {device_id}"
    return None

@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    data = request.json

    features = np.array([[
        data.get('cpu_load', 50),
        data.get('bandwidth_mbps', 100),
        data.get('latency_ms', 10),
        data.get('packet_loss', 0),
        data.get('connected_devices', 10),
        data.get('temperature', 40),
        data.get('signal_strength', 80)
    ]])

    # Model 1: Health score
    health_score = float(rf_model.predict(features)[0])
    health_score = max(0, min(100, health_score))

    # Model 2: Anomaly detection
    anomaly_result = iso_model.predict(features)[0]
    anomaly_flag = bool(anomaly_result == -1)

    # Predictive score using rolling window
    reading_window.append(health_score)
    if len(reading_window) > 10:
        reading_window.pop(0)
    if len(reading_window) >= 3:
        trend = reading_window[-1] - reading_window[0]
        predicted_score = max(0, min(100, health_score + trend))
    else:
        predicted_score = health_score

    # AI diagnosis
    ai_diagnosis = None
    if anomaly_flag or health_score < 50:
        ai_diagnosis = get_ai_diagnosis(
            data.get('device_id', 'unknown'),
            data.get('device_type', 'unknown'),
            data.get('metric_name', 'unknown'),
            data.get('metric_value', 0),
            health_score,
            anomaly_flag
        )

    # Automation command
    automation_command = get_automation_command(
        data.get('device_id', 'unknown'), health_score
    )

    # Store in Supabase
    supabase.table('metrics').insert({
        'device_type': data.get('device_type', 'unknown'),
        'device_id': data.get('device_id', 'unknown'),
        'metric_name': data.get('metric_name', 'unknown'),
        'metric_value': float(data.get('metric_value', 0)),
        'health_score': health_score,
        'anomaly_flag': anomaly_flag,
        'predicted_score': predicted_score,
        'ai_diagnosis': ai_diagnosis,
        'automation_command': automation_command
    }).execute()

    return jsonify({
        'status': 'ok',
        'health_score': round(health_score, 1),
        'anomaly_flag': anomaly_flag,
        'predicted_score': round(predicted_score, 1),
        'ai_diagnosis': ai_diagnosis,
        'automation_command': automation_command
    })

@app.route('/api/data', methods=['GET'])
def get_data():
    response = supabase.table('metrics').select('*')\
        .order('created_at', desc=True).limit(100).execute()
    return jsonify(response.data)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)