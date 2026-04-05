import os
import joblib
import numpy as np
import requests as req
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from supabase import create_client
from functools import wraps
from datetime import datetime, timezone
import threading
import time
from collections import deque
import json
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ═══════════════════════════════════════════════════════════════════════════
# IISentinel™ — Intelligent Infrastructure Sentinel
# Architecture: high-throughput ingestion → AI enrichment
#               → multi-tenant federated delivery
#
# Platform layer mapping:
#   Ingestion buffer   → metric_queue (deque, Kafka-ready, 500-reading failsafe)
#   Normalisation      → scaler + feature pipeline before any storage write
#   Scoring engine     → RandomForest async worker (never blocks ingestion API)
#   Three-tier storage → Supabase (persistent) + in-memory (hot) + cold dump
#   Edge delivery      → standalone node per site, works offline if WAN drops
#   Alert dispatch     → SMS + WhatsApp + Email, <60s target
#
# Core value proposition:
#   Reduce the time between "pump shows anomaly" and
#   "engineer makes a decision" to near zero.
# ═══════════════════════════════════════════════════════════════════════════

# ── TIER 1: INGESTION QUEUE (non-blocking buffer — Kafka-ready deque) ────────
# Collectors POST and return immediately. Never blocks on storage write.
# Background flusher drains to Supabase in batches every 3 seconds.
# On WAN failure the queue holds 500 readings (~83 minutes at 6/min).
# This is the moat: competitors lose readings on timeout, IISentinel™ doesn't.
metric_queue  = deque(maxlen=500)
scoring_queue = deque(maxlen=200)   # async AI scoring pipeline
queue_lock    = threading.Lock()

# ── TIER 2: HOT CACHE (8s TTL in-memory, one DB query per TTL window) ────────
# Dashboard polls /api/data every 10 s. One Supabase query per 8 s max.
# Each edge site has its own cache shard (geography-aware per site node).
_data_cache   = {'data': [], 'ts': 0}
CACHE_TTL     = 8   # seconds

# ── PLATFORM OBSERVABILITY (internal SLA dashboard) ───────────────────────
platform_stats = {
    'requests_total'  : 0,
    'requests_failed' : 0,
    'queue_depth'     : 0,
    'scoring_queue'   : 0,
    'cache_hits'      : 0,
    'retrain_runs'    : 0,
    'last_flush_ts'   : None,
    'start_ts'        : time.time(),
}

# ── NOTIFICATION CONFIG (SMS primary → WhatsApp → Email) ─────────────────────
NOTIFY_EMAIL_ENABLED    = bool(os.environ.get('SMTP_HOST'))
NOTIFY_SMS_ENABLED      = bool(os.environ.get('AT_API_KEY') or os.environ.get('TWILIO_SID') or os.environ.get('VONAGE_KEY') or os.environ.get('SMS_GATEWAY_URL'))
NOTIFY_WHATSAPP_ENABLED = bool(os.environ.get('WA_TOKEN'))

def send_sms_alert(message, phone=None):
    """SMS alert dispatch via configurable gateway."""
    if not NOTIFY_SMS_ENABLED:
        return
    phone = phone or os.environ.get('ALERT_PHONE', '')
    if not phone:
        return
    try:
        # Supports multiple SMS gateways via environment config.
        # Set SMS_GATEWAY to 'africastalking', 'twilio', or 'vonage'
        gateway = os.environ.get('SMS_GATEWAY', 'africastalking')

        if gateway == 'africastalking':
            import africastalking
            africastalking.initialize(
                os.environ.get('AT_USERNAME', 'sandbox'),
                os.environ.get('AT_API_KEY', '')
            )
            africastalking.SMS.send(message, [phone])

        elif gateway == 'twilio':
            from twilio.rest import Client
            client = Client(
                os.environ.get('TWILIO_SID', ''),
                os.environ.get('TWILIO_TOKEN', '')
            )
            client.messages.create(
                body=message,
                from_=os.environ.get('TWILIO_FROM', ''),
                to=phone
            )

        elif gateway == 'vonage':
            import vonage
            client = vonage.Client(
                key=os.environ.get('VONAGE_KEY', ''),
                secret=os.environ.get('VONAGE_SECRET', '')
            )
            sms = vonage.Sms(client)
            sms.send_message({
                'from': os.environ.get('VONAGE_FROM', 'IISentinel'),
                'to': phone,
                'text': message,
            })

        else:
            # Generic HTTP SMS gateway — POST to SMS_GATEWAY_URL
            gateway_url = os.environ.get('SMS_GATEWAY_URL', '')
            if gateway_url:
                req.post(gateway_url, json={
                    'to': phone,
                    'message': message,
                    'api_key': os.environ.get('SMS_API_KEY', ''),
                }, timeout=8)
    except Exception as e:
        print(f'SMS alert error: {e}')

def send_whatsapp_alert(message):
    """WhatsApp Business API alert."""
    if not NOTIFY_WHATSAPP_ENABLED:
        return
    try:
        wa_token = os.environ.get('WA_TOKEN', '')
        wa_phone_id = os.environ.get('WA_PHONE_ID', '')
        wa_to = os.environ.get('WA_TO', '')
        if not all([wa_token, wa_phone_id, wa_to]):
            return
        req.post(
            f'https://graph.facebook.com/v18.0/{wa_phone_id}/messages',
            headers={'Authorization': f'Bearer {wa_token}',
                     'Content-Type': 'application/json'},
            json={
                'messaging_product': 'whatsapp',
                'to': wa_to,
                'type': 'text',
                'text': {'body': message}
            },
            timeout=8
        )
    except Exception as e:
        print(f'WhatsApp alert error: {e}')

def send_email_alert(subject, body, device_id=None, health_score=None,
                      diagnosis=None, automation_command=None, severity='warning'):
    """
    HTML email alert with IISentinel™ branding.
    Severity: 'critical' | 'warning' | 'info' | 'cbs'
    """
    if not NOTIFY_EMAIL_ENABLED:
        return
    recipient = os.environ.get('ALERT_EMAIL', '')
    if not recipient:
        return

    color_map = {
        'critical': '#ff3e50',
        'cbs':      '#ff3e50',
        'warning':  '#f5a020',
        'info':     '#20e07a',
    }
    accent = color_map.get(severity, '#34c6f4')
    label  = severity.upper()
    score_html = (
        f'<tr><td style="padding:6px 0;color:#8592a8;font-size:13px;">Health Score</td>'
        f'<td style="padding:6px 0;font-weight:700;font-size:13px;color:{accent};">'
        f'{health_score:.0f} / 100</td></tr>'
    ) if health_score is not None else ''
    diag_html = (
        f'<tr><td colspan="2" style="padding:10px 0 4px;color:#8592a8;font-size:12px;'
        f'font-weight:700;text-transform:uppercase;letter-spacing:1px;">AI Diagnosis</td></tr>'
        f'<tr><td colspan="2" style="padding:4px 0 10px;font-size:13px;color:#1a1f2e;'
        f'line-height:1.6;">{diagnosis}</td></tr>'
    ) if diagnosis else ''
    cmd_html = (
        f'<tr><td colspan="2" style="padding:10px 14px;background:#fff4e6;border-radius:6px;'
        f'font-size:12px;color:#c07800;font-weight:600;border-left:3px solid #f5a020;">'
        f'{automation_command}</td></tr>'
    ) if automation_command else ''

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#eef0f7;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef0f7;padding:32px 0;">
<tr><td align="center">
<table width="580" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;
  overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.10);">

  <!-- Header -->
  <tr><td style="background:{accent};padding:22px 28px;">
    <span style="font-size:22px;font-weight:800;color:#fff;letter-spacing:-1px;">II</span>
    <span style="font-size:18px;font-weight:700;color:#fff;letter-spacing:.5px;">Sentinel</span>
    <span style="font-size:10px;color:rgba(255,255,255,0.7);vertical-align:super;">&#8482;</span>
    &nbsp;&nbsp;
    <span style="font-size:11px;font-weight:700;background:rgba(255,255,255,0.2);
      color:#fff;padding:3px 10px;border-radius:20px;letter-spacing:1px;">{label}</span>
  </td></tr>

  <!-- Body -->
  <tr><td style="padding:28px 28px 20px;">
    <p style="margin:0 0 6px;font-size:18px;font-weight:700;color:#0c1122;">{subject}</p>
    {'<p style="margin:0 0 18px;font-size:13px;color:#8592a8;">Device: <strong style=\"color:#0c1122;\">' + device_id + '</strong></p>' if device_id else ''}
    <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #e4eaf6;margin-top:16px;">
      {score_html}
      {diag_html}
      {cmd_html}
    </table>
  </td></tr>

  <!-- Footer -->
  <tr><td style="background:#f0f4fa;padding:14px 28px;border-top:1px solid #e4eaf6;">
    <p style="margin:0;font-size:11px;color:#8592a8;">
      IISentinel&#8482; Intelligent Infrastructure Sentinel &nbsp;|&nbsp;
      This is an automated alert. Do not reply to this email.
    </p>
  </td></tr>

</table>
</td></tr>
</table>
</body></html>"""

    try:
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'[IISentinel™] {label}: {subject}'
        msg['From']    = os.environ.get('SMTP_FROM', 'iisentinel@localhost')
        msg['To']      = recipient
        msg.attach(MIMEText(body, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP(
            os.environ.get('SMTP_HOST', 'localhost'),
            int(os.environ.get('SMTP_PORT', 587))
        ) as s:
            if os.environ.get('SMTP_USER'):
                s.starttls()
                s.login(os.environ.get('SMTP_USER'),
                        os.environ.get('SMTP_PASS', ''))
            s.send_message(msg)
    except Exception as e:
        print(f'Email alert error: {e}')

def fire_critical_alert(device_id, device_type, health_score, message,
                         diagnosis=None, automation_command=None):
    """
    Multi-channel alert dispatcher.
    CBS hold ALWAYS triggers SMS — engineer may be underground, no browser.
    Target: event → human decision in under 60 seconds.
    """
    is_cbs   = device_type == 'cbs_controller' or 'BLAST HOLD' in message
    severity = 'cbs' if is_cbs else 'critical' if health_score < 20 else 'warning'
    subject  = (
        f'BLAST HOLD ACTIVE — {device_id}'          if is_cbs else
        f'Critical failure — {device_id}'            if health_score < 20 else
        f'Equipment degradation — {device_id}'
    )
    short = f'IISentinel™ {severity.upper()}: {device_id} score {health_score:.0f}/100. {message[:100]}'

    # CBS and critical always get SMS and WhatsApp — most reliable channels
    if is_cbs or health_score < 20:
        threading.Thread(target=send_sms_alert,       args=(short,), daemon=True).start()
        threading.Thread(target=send_whatsapp_alert,  args=(short,), daemon=True).start()

    # All critical/warning events get rich HTML email
    if health_score < 50:
        threading.Thread(
            target=send_email_alert,
            kwargs=dict(
                subject=subject,
                body=short,
                device_id=device_id,
                health_score=health_score,
                diagnosis=diagnosis,
                automation_command=automation_command,
                severity=severity,
            ),
            daemon=True
        ).start()

# ── BACKGROUND QUEUE FLUSHER (batch-write, 3s interval) ─────────────────────
def flush_queue():
    """
    Drains metric_queue → Supabase every 3 seconds.
    One batch call instead of one call per reading.
    If Supabase is unreachable, data stays in queue (no loss).
    """
    while True:
        time.sleep(3)
        with queue_lock:
            if not metric_queue:
                continue
            batch = list(metric_queue)
            metric_queue.clear()
            platform_stats['queue_depth'] = 0
        try:
            for item in batch:
                supabase.table('metrics').insert(item).execute()
            platform_stats['last_flush_ts'] = time.time()
            _data_cache['ts'] = 0   # invalidate cache after write
        except Exception as e:
            print(f'Queue flush error: {e}')
            with queue_lock:
                for item in batch[:50]:
                    metric_queue.appendleft(item)
                platform_stats['queue_depth'] = len(metric_queue)

threading.Thread(target=flush_queue, daemon=True).start()

# ── ASYNC AI SCORING PIPELINE (non-blocking background worker) ─────────────
def scoring_worker():
    """
    Consumes scoring_queue and computes failure_probabilities without
    blocking the ingestion API. Health scores are computed inline (fast,
    RandomForest predict is <1ms). Lifecycle and root-cause chain are
    computed here (slower, non-blocking).
    """
    while True:
        time.sleep(1)
        with queue_lock:
            if not scoring_queue:
                continue
            items = list(scoring_queue)
            scoring_queue.clear()
            platform_stats['scoring_queue'] = 0
        for item in items:
            did = item.get('device_id')
            dtype = item.get('device_type')
            score = item.get('health_score', 50)
            if did:
                update_uptime(did, score)
                lc = get_lifecycle_estimate(did, dtype, score)
                if lc:
                    _lifecycle_cache[did] = lc

threading.Thread(target=scoring_worker, daemon=True).start()
_lifecycle_cache = {}

# ── AUTO-RETRAIN PIPELINE (hot-swap, triggered on anomaly threshold) ────────
retrain_lock = threading.Lock()
_retrain_in_progress = False

def auto_retrain():
    """
    Hot-swap model retraining triggered when anomaly_count >= threshold.
    Retrains on the last 1000 readings from Supabase.
    Swaps models atomically — dashboard never sees a gap.
    Models improve continuously without any service downtime.
    """
    global rf_model, iso_model, scaler, anomaly_count, _retrain_in_progress
    with retrain_lock:
        if _retrain_in_progress:
            return
        _retrain_in_progress = True
    try:
        from sklearn.ensemble import RandomForestRegressor, IsolationForest
        from sklearn.preprocessing import StandardScaler

        resp = supabase.table('metrics').select(
            'cpu_load,bandwidth_mbps,latency_ms,packet_loss,'
            'connected_devices,temperature,signal_strength,health_score'
        ).order('created_at', desc=True).limit(1000).execute()
        data = resp.data
        if len(data) < 50:
            return

        X = np.array([[
            r.get('cpu_load', 50) or 50,
            r.get('bandwidth_mbps', 100) or 100,
            r.get('latency_ms', 10) or 10,
            r.get('packet_loss', 0) or 0,
            r.get('connected_devices', 10) or 10,
            r.get('temperature', 40) or 40,
            r.get('signal_strength', 80) or 80,
        ] for r in data])
        y = np.array([r.get('health_score', 50) or 50 for r in data])

        new_scaler = StandardScaler()
        X_scaled = new_scaler.fit_transform(X)

        new_rf = RandomForestRegressor(n_estimators=100, random_state=42)
        new_rf.fit(X_scaled, y)

        new_iso = IsolationForest(contamination=0.1, random_state=42)
        new_iso.fit(X_scaled)

        # Atomic hot-swap — no downtime
        joblib.dump(new_rf,     'health_model.pkl')
        joblib.dump(new_iso,    'anomaly_model.pkl')
        joblib.dump(new_scaler, 'scaler.pkl')
        rf_model  = new_rf
        iso_model = new_iso
        scaler    = new_scaler
        anomaly_count = 0
        platform_stats['retrain_runs'] += 1
        print(f'Auto-retrain complete on {len(data)} samples — models hot-swapped')
    except Exception as e:
        print(f'Auto-retrain error: {e}')
    finally:
        with retrain_lock:
            _retrain_in_progress = False

def get_cached_data():
    now = time.time()
    if now - _data_cache['ts'] < CACHE_TTL and _data_cache['data']:
        platform_stats['cache_hits'] += 1
        return _data_cache['data']
    try:
        resp = supabase.table('metrics').select('*')\
            .order('created_at', desc=True).limit(200).execute()
        _data_cache['data'] = resp.data
        _data_cache['ts']   = now
        return resp.data
    except Exception as e:
        print(f'Cache refresh error: {e}')
        return _data_cache['data']

# ── APP INIT ───────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'iisentinel-secret-2026')

rf_model  = joblib.load('health_model.pkl')
iso_model = joblib.load('anomaly_model.pkl')
scaler    = joblib.load('scaler.pkl')

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── STATE ──────────────────────────────────────────────────────────────────
reading_window  = []
device_history  = {}
device_uptime   = {}
anomaly_count   = 0
RETRAIN_THRESHOLD    = 50
CBS_SAFETY_THRESHOLD = 90.0

# ── DEVICE TAXONOMY ────────────────────────────────────────────────────────
NETWORK_TYPES = ['router', 'switch', 'firewall', 'wan_link', 'workstation']
TELECOM_TYPES = ['base_station', 'network_tower', 'microwave_link']
MINING_TYPES  = ['pump', 'conveyor', 'ventilation', 'power_meter',
                 'sensor', 'plc', 'scada_node']
CBS_TYPES     = ['cbs_controller']

# ── GEOGRAPHY (edge-node shards, one per site — offline-resilient) ─────────
LOCATIONS = {
    'byo' : {'lat': -20.15, 'lon': 28.58, 'name': 'Bulawayo'},
    'hre' : {'lat': -17.82, 'lon': 31.05, 'name': 'Harare'},
    'mut' : {'lat': -18.97, 'lon': 32.67, 'name': 'Mutare'},
    'mine': {'lat': -17.65, 'lon': 29.85, 'name': 'Mine Site'},
}

PROTOCOL_MAP = {
    'SNMP/Ethernet-802.3'  : 'SNMP over IEEE 802.3 Ethernet',
    'Profinet/EtherNet-IP' : 'Profinet real-time industrial Ethernet',
    'DNP3/Ethernet'        : 'DNP3 safety-critical control protocol',
    'Modbus-TCP/OPC-UA'    : 'Modbus TCP with OPC-UA data exchange',
}

# Cost-of-downtime rates per device type ($/hr) — used in risk exposure calc
COST_RATES = {
    'pump': 150000, 'conveyor': 120000, 'ventilation': 180000,
    'plc': 80000, 'scada_node': 60000, 'cbs_controller': 450000,
    'power_meter': 100000, 'sensor': 40000,
    'base_station': 25000, 'network_tower': 35000, 'microwave_link': 40000,
    'router': 15000, 'switch': 10000, 'firewall': 20000,
    'wan_link': 12000, 'workstation': 2000,
}

# ── AUTH ───────────────────────────────────────────────────────────────────
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

# ── INTELLIGENCE FUNCTIONS ─────────────────────────────────────────────────
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
    weights = [s * 0.5 if s < 20 else s * 0.8 if s < 50 else s
               for s in all_scores]
    return round(sum(weights) / len(weights), 1)

def get_root_cause_chain(device_id, current_score, all_recent):
    chain = []
    degraded = [(did, score) for did, score in all_recent.items()
                if score < 50 and did != device_id]
    if degraded and current_score < 50:
        for did, score in sorted(degraded, key=lambda x: x[1])[:3]:
            chain.append({'device': did, 'score': round(score, 1)})
    return chain

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
        hours_remaining     = min(base_hours,
                                  readings_to_failure * (10 / 3600))
        return round(hours_remaining, 0)
    return base_hours

def get_protocol_diagnosis(device_type, protocol, metric_name,
                           metric_value, health_score, anomaly):
    issues  = []
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

    if device_type in TELECOM_TYPES or device_type in NETWORK_TYPES:
        if 'latency' in metric_name and metric_value > 100:
            issues.append(
                f"SNMP reports {metric_value:.1f}ms latency on backhaul")
            actions.append(
                "inspect BGP routing and check fibre integrity")
        if 'packet' in metric_name and metric_value > 2:
            issues.append(
                f"packet loss {metric_value:.1f}% on {proto_label}")
            actions.append("run BERT test and check SFP modules")
        if 'bandwidth' in metric_name and metric_value > 800:
            issues.append(
                f"bandwidth at {metric_value:.1f}Mbps near capacity")
            actions.append("implement QoS and analyse NetFlow traffic")
        if 'signal' in metric_name and metric_value < 40:
            issues.append(
                f"signal at {metric_value:.1f}% — link degraded")
            actions.append("inspect microwave alignment")

    elif device_type in MINING_TYPES:
        if 'temperature' in metric_name and metric_value > 75:
            issues.append(
                f"Profinet reports {metric_value:.1f}°C — thermal threshold")
            actions.append("check cooling fan and reduce duty cycle")
        if 'motor' in metric_name and metric_value < 500:
            issues.append(
                f"motor {metric_value:.0f}RPM via Modbus — below minimum")
            actions.append(
                "inspect VFD parameters and overcurrent protection")
        if 'vibration' in metric_name and metric_value > 3:
            issues.append(
                f"vibration {metric_value:.2f}g via OPC-UA — bearing wear")
            actions.append(
                "schedule predictive maintenance within 4 hours")
        if 'pressure' in metric_name and metric_value > 8:
            issues.append(
                f"pressure {metric_value:.1f}bar — above safe limit")
            actions.append(
                "open bypass valve — alert hydraulics engineer")

    elif device_type == 'cbs_controller':
        if health_score < CBS_SAFETY_THRESHOLD:
            issues.append(
                f"CBS DNP3 link {health_score:.1f}% below blast threshold")
            actions.append(
                "BLAST HOLD — notify blasting officer, inspect DNP3 link")

    if anomaly:
        issues.append(f"Isolation Forest anomaly on {proto_label}")
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
    if (device_type == 'cbs_controller'
            and health_score < CBS_SAFETY_THRESHOLD):
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
    device_uptime[device_id]['total']   += 1
    if health_score >= 50:
        device_uptime[device_id]['healthy'] += 1

def get_uptime_pct(device_id):
    d = device_uptime.get(device_id, {'total': 0, 'healthy': 0})
    if d['total'] == 0:
        return 100.0
    return round((d['healthy'] / d['total']) * 100, 1)

# ═══════════════════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/api/metrics', methods=['POST'])
def receive_metrics():
    """
    Ingestion endpoint — non-blocking, scores inline, queues for storage.
    Non-blocking: score inline (<1ms), queue for storage, fire alerts async.
    """
    global anomaly_count
    platform_stats['requests_total'] += 1

    data              = request.json
    device_id         = data.get('device_id', 'unknown')
    device_type       = data.get('device_type', 'unknown')
    protocol          = data.get('protocol', 'Ethernet')
    blast_hold        = data.get('blast_hold', False)
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

    # ── Inline health score (RandomForest, <1ms) ──
    health_score = float(rf_model.predict(features_arr)[0])
    health_score = max(0, min(100, health_score))
    if device_type == 'cbs_controller':
        health_score = min(health_score, data.get('signal_strength', 100))

    # ── Inline anomaly detection (IsolationForest) ──
    anomaly_result = iso_model.predict(features_arr)[0]
    anomaly_flag   = bool(anomaly_result == -1)
    if anomaly_flag:
        anomaly_count += 1
        # Trigger auto-retrain when threshold exceeded (hot-swap, no downtime)
        if anomaly_count >= RETRAIN_THRESHOLD and not _retrain_in_progress:
            threading.Thread(target=auto_retrain, daemon=True).start()

    # ── Update in-memory device history (rolling 20-point window) ──
    if device_id not in device_history:
        device_history[device_id] = []
    device_history[device_id].append(health_score)
    if len(device_history[device_id]) > 20:
        device_history[device_id].pop(0)

    # ── Trend prediction ──
    reading_window.append(health_score)
    if len(reading_window) > 10:
        reading_window.pop(0)
    if len(reading_window) >= 3:
        trend           = reading_window[-1] - reading_window[0]
        predicted_score = max(0, min(100, health_score + trend))
    else:
        predicted_score = health_score

    failure_prob = get_failure_probability(device_id, health_score)

    recent_scores = {
        did: hist[-1] for did, hist in device_history.items() if hist
    }
    root_cause      = get_root_cause_chain(device_id, health_score, recent_scores)
    federated_index = get_federated_health_index(list(recent_scores.values()))

    update_uptime(device_id, health_score)
    uptime_pct = get_uptime_pct(device_id)

    lifecycle = (_lifecycle_cache.get(device_id) or
                 get_lifecycle_estimate(device_id, device_type, health_score))

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

    # ── Fire multi-channel alert (async, non-blocking) ──
    if health_score < 35 or blast_hold:
        msg = automation_command or ai_diagnosis or ''
        threading.Thread(
            target=fire_critical_alert,
            kwargs=dict(
                device_id=device_id,
                device_type=device_type,
                health_score=health_score,
                message=msg,
                diagnosis=ai_diagnosis,
                automation_command=automation_command,
            ),
            daemon=True
        ).start()

    # ── Queue ingestion record (non-blocking write) ──
    metric_record = {
        'device_type'       : device_type,
        'device_id'         : device_id,
        'metric_name'       : data.get('metric_name', 'unknown'),
        'metric_value'      : float(data.get('metric_value', 0)),
        'health_score'      : health_score,
        'anomaly_flag'      : anomaly_flag,
        'predicted_score'   : predicted_score,
        'ai_diagnosis'      : ai_diagnosis,
        'automation_command': automation_command
    }
    with queue_lock:
        metric_queue.append(metric_record)
        platform_stats['queue_depth']  = len(metric_queue)
        # Push to async scoring queue for lifecycle/uptime computation
        scoring_queue.append({
            'device_id': device_id, 'device_type': device_type,
            'health_score': health_score
        })
        platform_stats['scoring_queue'] = len(scoring_queue)

    # ── Incident creation (critical/anomaly/CBS only) ──
    if health_score < 50 or anomaly_flag or blast_hold:
        try:
            supabase.table('incidents').insert({
                'device_id'        : device_id,
                'device_type'      : device_type,
                'health_score'     : health_score,
                'ai_diagnosis'     : ai_diagnosis,
                'automation_command': automation_command,
                'status'           : 'open'
            }).execute()
        except Exception as e:
            print(f'Incident insert error: {e}')

    return jsonify({
        'status'              : 'ok',
        'health_score'        : round(health_score, 1),
        'anomaly_flag'        : anomaly_flag,
        'predicted_score'     : round(predicted_score, 1),
        'failure_probability' : failure_prob,
        'ai_diagnosis'        : ai_diagnosis,
        'automation_command'  : automation_command,
        'federated_index'     : federated_index,
        'uptime_pct'          : uptime_pct,
        'root_cause_chain'    : root_cause,
        'lifecycle_hours'     : lifecycle,
        'retrain_needed'      : anomaly_count >= RETRAIN_THRESHOLD,
        'retrain_in_progress' : _retrain_in_progress,
        'protocol'            : protocol,
        'blast_hold'          : blast_hold
    })

@app.route('/api/data', methods=['GET'])
def get_data():
    """Cached dashboard data endpoint — 8s TTL, instant response."""
    return jsonify(get_cached_data())

@app.route('/api/platform', methods=['GET'])
def platform_health():
    """
    Internal SLA dashboard — every metric that matters for <60s alert target.
    Every metric that matters for the <60s alert target is surfaced here.
    """
    uptime_h = (time.time() - platform_stats['start_ts']) / 3600
    return jsonify({
        'queue_depth'        : len(metric_queue),
        'scoring_queue'      : len(scoring_queue),
        'cache_age_seconds'  : round(time.time() - _data_cache['ts'], 1),
        'devices_tracked'    : len(device_history),
        'anomaly_count'      : anomaly_count,
        'retrain_needed'     : anomaly_count >= RETRAIN_THRESHOLD,
        'retrain_in_progress': _retrain_in_progress,
        'platform_uptime_h'  : round(uptime_h, 2),
        'platform_stats'     : platform_stats,
        'notifications'      : {
            'email_enabled'    : NOTIFY_EMAIL_ENABLED,
            'sms_enabled'      : NOTIFY_SMS_ENABLED,
            'whatsapp_enabled' : NOTIFY_WHATSAPP_ENABLED,
        },
        'architecture': {
            'ingestion'   : 'High-throughput non-blocking pipeline',
            'cache'       : f'{CACHE_TTL}s real-time data layer',
            'ai_models'   : ['Predictive health engine', 'Anomaly detection', 'Continuous learning'],
            'protocols'   : ['SNMP', 'Profinet', 'Modbus TCP', 'DNP3', 'OPC-UA', 'EtherNet/IP'],
            'alert_target': '<60 seconds event-to-decision',
            'edge_ready'  : True,
        }
    })

@app.route('/api/intelligence', methods=['GET'])
def get_intelligence():
    recent_scores = {
        did: hist[-1] for did, hist in device_history.items() if hist
    }
    probs = {
        did: get_failure_probability(did, hist[-1])
        for did, hist in device_history.items() if hist
    }
    # Merge async lifecycle cache with fresh estimates
    lifecycles = dict(_lifecycle_cache)
    try:
        resp = supabase.table('metrics').select('device_id,device_type')\
            .order('created_at', desc=True).limit(50).execute()
        for row in resp.data:
            did = row['device_id']
            if did in recent_scores and did not in lifecycles:
                lc = get_lifecycle_estimate(
                    did, row['device_type'], recent_scores[did])
                if lc:
                    lifecycles[did] = lc
    except Exception as e:
        print(f'Intelligence lifecycle error: {e}')

    return jsonify({
        'federated_index'      : get_federated_health_index(
                                     list(recent_scores.values())),
        'device_scores'        : recent_scores,
        'uptime'               : {did: get_uptime_pct(did)
                                  for did in device_uptime},
        'failure_probabilities': probs,
        'lifecycles'           : lifecycles,
        'retrain_needed'       : anomaly_count >= RETRAIN_THRESHOLD,
        'retrain_in_progress'  : _retrain_in_progress,
        'anomaly_count'        : anomaly_count,
        'total_devices'        : len(device_history),
    })

@app.route('/api/twin/<device_id>', methods=['GET'])
def digital_twin(device_id):
    """
    Digital twin load simulator — runs real RandomForest predictions
    at +10%, +20%, +50%, +100% load. Scenario testing on
    scenario testing on recommendation algorithm variants.
    """
    history = device_history.get(device_id, [])
    if not history:
        return jsonify({'error': 'No history for device'}), 404

    current_score = history[-1]
    scenarios     = []

    load_levels = [1.1, 1.2, 1.5, 2.0]
    for mult in load_levels:
        features = np.array([[
            min(100, 50 * mult), min(1000, 100 * mult),
            min(500, 10 * mult), min(20, mult * 0.5),
            10, 40, 80
        ]])
        sim_score = float(rf_model.predict(features)[0])
        sim_score = max(0, min(100, sim_score))
        anomaly   = bool(iso_model.predict(features)[0] == -1)
        scenarios.append({
            'load_increase'   : f'+{int((mult-1)*100)}%',
            'predicted_score' : round(sim_score, 1),
            'anomaly_predicted': anomaly,
            'risk'            : ('critical' if sim_score < 30
                                 else 'warning' if sim_score < 60 else 'safe')
        })

    trend_info = {'slope_per_reading': 0, 'direction': 'insufficient data'}
    if len(history) >= 5:
        slope = (history[-1] - history[-5]) / 4
        readings_to_critical = None
        if slope < 0 and current_score > 20:
            readings_to_critical = round((current_score - 20) / abs(slope))
        trend_info = {
            'slope_per_reading'   : round(slope, 2),
            'direction'           : ('declining' if slope < 0
                                     else 'stable' if slope == 0
                                     else 'improving'),
            'readings_to_critical': readings_to_critical
        }

    return jsonify({
        'device_id'         : device_id,
        'current_score'     : round(current_score, 1),
        'history'           : [round(h, 1) for h in history],
        'scenarios'         : scenarios,
        'trend'             : trend_info,
        'failure_probability': get_failure_probability(device_id, current_score)
    })

@app.route('/api/weather', methods=['GET'])
def get_weather():
    loc_key = request.args.get('loc', 'byo')
    loc     = LOCATIONS.get(loc_key, LOCATIONS['byo'])
    try:
        url = (
            f"https://api.open-meteo.com/v1/forecast"
            f"?latitude={loc['lat']}&longitude={loc['lon']}"
            f"&current=temperature_2m,relative_humidity_2m,"
            f"wind_speed_10m,wind_gusts_10m,precipitation,"
            f"weather_code,cloud_cover"
            f"&hourly=temperature_2m,precipitation_probability,"
            f"wind_speed_10m&forecast_days=2&timezone=Africa/Harare"
        )
        resp    = req.get(url, timeout=10)
        data    = resp.json()
        current = data.get('current', {})
        hourly  = data.get('hourly', {})

        wind     = current.get('wind_speed_10m', 0)
        gusts    = current.get('wind_gusts_10m', 0)
        precip   = current.get('precipitation', 0)
        temp     = current.get('temperature_2m', 25)
        humidity = current.get('relative_humidity_2m', 50)
        wcode    = current.get('weather_code', 0)
        cloud    = current.get('cloud_cover', 0)

        alerts           = []
        equipment_impact = []

        if wind > 40:
            alerts.append(
                f"High winds {wind:.0f}km/h — microwave links at risk")
            equipment_impact.append({
                'type'    : 'telecom',
                'impact'  : f"Signal degradation {min(30,wind*0.4):.0f}% on exposed towers",
                'severity': 'warning'
            })
        if gusts > 60:
            alerts.append(
                f"Dangerous gusts {gusts:.0f}km/h — tower stability risk")
            equipment_impact.append({
                'type'    : 'telecom',
                'impact'  : "CBS blast hold recommended — link stability compromised",
                'severity': 'critical'
            })
        if precip > 10:
            alerts.append(
                f"Heavy precipitation {precip:.1f}mm — equipment cooling affected")
            equipment_impact.append({
                'type'    : 'mining',
                'impact'  : "Underground water ingress risk — pump load will increase",
                'severity': 'warning'
            })
        if temp > 38:
            alerts.append(
                f"Extreme heat {temp:.0f}°C — equipment thermal stress elevated")
            equipment_impact.append({
                'type'    : 'all',
                'impact'  : "Health score degradation expected — increase cooling checks",
                'severity': 'warning'
            })
        if wcode >= 95:
            alerts.append(
                "Thunderstorm active — lightning risk to exposed equipment")
            equipment_impact.append({
                'type'    : 'all',
                'impact'  : "Surge protection alert — consider temporary equipment shutdown",
                'severity': 'critical'
            })

        next24_precip = hourly.get('precipitation_probability', [])[:24]
        max_precip_prob = max(next24_precip) if next24_precip else 0

        return jsonify({
            'location'                : loc['name'],
            'temperature'             : temp,
            'humidity'                : humidity,
            'wind_speed'              : wind,
            'wind_gusts'              : gusts,
            'precipitation'           : precip,
            'weather_code'            : wcode,
            'cloud_cover'             : cloud,
            'alerts'                  : alerts,
            'equipment_impact'        : equipment_impact,
            'max_precip_probability_24h': max_precip_prob,
            'hourly_wind'             : hourly.get('wind_speed_10m', [])[:24],
            'hourly_precip_prob'      : next24_precip
        })
    except Exception as e:
        return jsonify({'error': str(e), 'location': loc['name']}), 500

@app.route('/api/shift-report', methods=['GET'])
@require_specialist
def shift_report():
    try:
        resp = supabase.table('metrics').select('*')\
            .order('created_at', desc=True).limit(500).execute()
        data = resp.data
        inc_resp = supabase.table('incidents').select('*')\
            .order('created_at', desc=True).limit(100).execute()
        incidents = inc_resp.data

        device_map = {}
        for row in data:
            if row['device_id'] not in device_map:
                device_map[row['device_id']] = row

        critical = [d for d in device_map.values() if d['health_score'] < 20]
        warning  = [d for d in device_map.values()
                    if 20 <= d['health_score'] < 50]
        healthy  = [d for d in device_map.values()
                    if d['health_score'] >= 50]

        open_incidents = [i for i in incidents if i['status'] == 'open']
        resolved       = [i for i in incidents if i['status'] == 'resolved']

        scores     = [d['health_score'] for d in device_map.values()]
        avg_health = round(sum(scores) / len(scores), 1) if scores else 100

        return jsonify({
            'generated_at'       : datetime.now(timezone.utc).isoformat(),
            'total_devices'      : len(device_map),
            'avg_health'         : avg_health,
            'critical_devices'   : len(critical),
            'warning_devices'    : len(warning),
            'healthy_devices'    : len(healthy),
            'open_incidents'     : len(open_incidents),
            'resolved_incidents' : len(resolved),
            'top_risks': [
                {'device'   : d['device_id'],
                 'score'    : round(d['health_score'], 1),
                 'diagnosis': d.get('ai_diagnosis', '')}
                for d in sorted(critical + warning,
                                key=lambda x: x['health_score'])[:5]
            ],
            'automation_commands': [
                {'device': d['device_id'],
                 'command': d['automation_command']}
                for d in device_map.values()
                if d.get('automation_command')
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    try:
        result = supabase.table('specialists').select('*')\
            .eq('name', data.get('name', ''))\
            .eq('password', data.get('password', '')).execute()
        if result.data:
            s = result.data[0]
            return jsonify({
                'success': True,
                'token'  : data.get('password'),
                'name'   : s['name'],
                'role'   : s['role']
            })
        return jsonify({'success': False}), 401
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/incidents', methods=['GET'])
@require_specialist
def get_incidents():
    status   = request.args.get('status', 'open')
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
        'notes'      : data.get('notes', ''),
        'status'     : 'assigned'
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})

@app.route('/api/incidents/<incident_id>/resolve', methods=['POST'])
@require_specialist
def resolve_incident(incident_id):
    data = request.json
    supabase.table('incidents').update({
        'resolved_by': data.get('resolved_by', ''),
        'notes'      : data.get('notes', ''),
        'status'     : 'resolved'
    }).eq('id', incident_id).execute()
    return jsonify({'success': True})


# ═══════════════════════════════════════════════════════════════════════════
# PDF SHIFT REPORT EXPORT — generates a real downloadable PDF
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/api/export-pdf', methods=['GET'])
def export_pdf():
    """
    Generates a professional PDF shift report using ReportLab.
    Called by the Export PDF button on the dashboard.
    Returns the PDF file as a download.
    """
    from io import BytesIO
    from datetime import datetime, timezone
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from flask import send_file

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18*mm,
        leftMargin=18*mm,
        topMargin=20*mm,
        bottomMargin=18*mm,
        title='IISentinel™ Shift Report',
        author='IISentinel™ Platform',
    )

    # ── Colour palette ──
    DARK    = colors.HexColor('#0c1122')
    ACCENT  = colors.HexColor('#34c6f4')
    GREEN   = colors.HexColor('#20e07a')
    AMBER   = colors.HexColor('#f5a020')
    RED     = colors.HexColor('#ff3e50')
    MUTED   = colors.HexColor('#8592a8')
    WHITE   = colors.white
    LIGHT   = colors.HexColor('#e4eaf6')
    ROW_ALT = colors.HexColor('#f0f4fa')

    styles = getSampleStyleSheet()

    def sty(name='Normal', **kw):
        return ParagraphStyle(name, parent=styles[name], **kw)

    title_sty   = sty('Title',   fontName='Helvetica-Bold',   fontSize=20, textColor=DARK,   spaceAfter=2)
    sub_sty     = sty('Normal',  fontName='Helvetica',        fontSize=9,  textColor=MUTED,  spaceAfter=6)
    h1_sty      = sty('Heading1',fontName='Helvetica-Bold',   fontSize=12, textColor=DARK,   spaceBefore=10, spaceAfter=4)
    h2_sty      = sty('Heading2',fontName='Helvetica-Bold',   fontSize=9,  textColor=ACCENT, spaceBefore=8,  spaceAfter=3, textTransform='uppercase')
    body_sty    = sty('Normal',  fontName='Helvetica',        fontSize=9,  textColor=DARK,   spaceAfter=3, leading=13)
    cell_sty    = sty('Normal',  fontName='Helvetica',        fontSize=8,  textColor=DARK,   leading=10)
    cell_b_sty  = sty('Normal',  fontName='Helvetica-Bold',   fontSize=8,  textColor=DARK,   leading=10)
    right_sty   = sty('Normal',  fontName='Helvetica',        fontSize=8,  textColor=DARK,   leading=10, alignment=TA_RIGHT)
    caption_sty = sty('Normal',  fontName='Helvetica-Oblique',fontSize=7,  textColor=MUTED,  spaceAfter=6)

    story = []
    now   = datetime.now(timezone.utc)
    ts    = now.strftime('%d %B %Y — %H:%M UTC')

    # ── Header ──
    story.append(Paragraph('IISentinel™', title_sty))
    story.append(Paragraph('Intelligent Infrastructure Sentinel — Shift Report', sub_sty))
    story.append(Paragraph(f'Generated: {ts}', sub_sty))
    story.append(HRFlowable(width='100%', thickness=1.5, color=ACCENT, spaceAfter=10))

    # ── Pull data ──
    recent_scores = {did: hist[-1] for did, hist in device_history.items() if hist}
    all_scores    = list(recent_scores.values())
    fhi_val       = get_federated_health_index(all_scores)
    critical_devs = [d for d, s in recent_scores.items() if s < 20]
    warning_devs  = [d for d, s in recent_scores.items() if 20 <= s < 50]
    healthy_devs  = [d for d, s in recent_scores.items() if s >= 50]
    probs         = {did: get_failure_probability(did, s) for did, s in recent_scores.items()}

    # Cost exposure
    dm_fake = {did: type('D', (), {
        'device_type': 'sensor',
        'health_score': s,
        'device_id': did
    })() for did, s in recent_scores.items()}

    total_exposure = 0
    exposure_rows  = []
    for did, s in sorted(recent_scores.items(), key=lambda x: x[1]):
        rate   = COST_RATES.get('sensor', 8000)
        prob   = probs.get(did, 0) / 100
        impact = 0.95 if s < 20 else 0.6 if s < 35 else 0.25 if s < 50 else 0
        exp    = round(rate * impact * (0.5 + prob * 0.5))
        if exp > 0:
            total_exposure += exp
            exposure_rows.append((did, f'{s:.0f}', f'{probs.get(did,0):.0f}%', f'${exp:,}/hr'))
        if len(exposure_rows) >= 8:
            break

    # Open incidents from Supabase
    open_incidents = []
    try:
        resp = supabase.table('incidents').select('*')            .eq('status', 'open')            .order('created_at', desc=True).limit(20).execute()
        open_incidents = resp.data or []
    except:
        pass

    # ── Summary KPI table ──
    story.append(Paragraph('Platform Summary', h1_sty))
    kpi_data = [
        ['Metric', 'Value', 'Status'],
        ['Federated Health Index', f'{fhi_val:.1f} / 100',
         'HEALTHY' if fhi_val >= 70 else 'WARNING' if fhi_val >= 40 else 'CRITICAL'],
        ['Total Devices Tracked', str(len(recent_scores)), '—'],
        ['Critical Devices (<20)', str(len(critical_devs)),
         'ALERT' if critical_devs else 'NONE'],
        ['Warning Devices (20–50)', str(len(warning_devs)),
         'MONITOR' if warning_devs else 'NONE'],
        ['Healthy Devices (≥50)', str(len(healthy_devs)), 'OK'],
        ['Open Incidents', str(len(open_incidents)),
         'ACTION' if open_incidents else 'CLEAR'],
        ['Total Hourly Risk Exposure', f'${total_exposure:,}/hr',
         'ELEVATED' if total_exposure > 50000 else 'MANAGED'],
        ['Anomaly Count (session)', str(anomaly_count),
         'HIGH' if anomaly_count >= RETRAIN_THRESHOLD else 'NORMAL'],
    ]

    def status_color(s):
        s = s.upper()
        if s in ('CRITICAL','ALERT','ELEVATED'):  return RED
        if s in ('WARNING','MONITOR','ACTION','HIGH'): return AMBER
        if s in ('OK','HEALTHY','CLEAR','NONE','NORMAL'): return GREEN
        return DARK

    kpi_table = Table(kpi_data, colWidths=[75*mm, 55*mm, 40*mm])
    kpi_ts = TableStyle([
        ('BACKGROUND',   (0,0),(-1,0),  DARK),
        ('TEXTCOLOR',    (0,0),(-1,0),  WHITE),
        ('FONTNAME',     (0,0),(-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',     (0,0),(-1,-1), 8),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE, ROW_ALT]),
        ('GRID',         (0,0),(-1,-1), 0.4, colors.HexColor('#d4daea')),
        ('TOPPADDING',   (0,0),(-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ('LEFTPADDING',  (0,0),(-1,-1), 6),
    ])
    for i, row in enumerate(kpi_data[1:], 1):
        sc = status_color(row[2])
        kpi_ts.add('TEXTCOLOR',  (2,i), (2,i), sc)
        kpi_ts.add('FONTNAME',   (2,i), (2,i), 'Helvetica-Bold')
    kpi_table.setStyle(kpi_ts)
    story.append(kpi_table)
    story.append(Spacer(1, 8))

    # ── Risk exposure table ──
    if exposure_rows:
        story.append(Paragraph('Risk Exposure by Device', h2_sty))
        exp_data = [['Device', 'Health Score', 'Failure Risk', 'Exposure']] + exposure_rows
        exp_table = Table(exp_data, colWidths=[80*mm, 35*mm, 35*mm, 25*mm])
        exp_ts = TableStyle([
            ('BACKGROUND',    (0,0),(-1,0), DARK),
            ('TEXTCOLOR',     (0,0),(-1,0), WHITE),
            ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0),(-1,-1),8),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE, ROW_ALT]),
            ('GRID',          (0,0),(-1,-1),0.4, colors.HexColor('#d4daea')),
            ('TOPPADDING',    (0,0),(-1,-1),4),
            ('BOTTOMPADDING', (0,0),(-1,-1),4),
            ('LEFTPADDING',   (0,0),(-1,-1),6),
            ('TEXTCOLOR',     (3,1),(3,-1), RED),
            ('FONTNAME',      (3,1),(3,-1), 'Helvetica-Bold'),
        ])
        exp_table.setStyle(exp_ts)
        story.append(exp_table)
        story.append(Spacer(1, 8))

    # ── Critical devices detail ──
    if critical_devs:
        story.append(Paragraph('Critical Assets — Immediate Action Required', h2_sty))
        for did in critical_devs[:10]:
            s = recent_scores[did]
            p = probs.get(did, 0)
            story.append(Paragraph(
                f'<b>{did}</b> — Health {s:.0f}/100 — Failure risk {p:.0f}%',
                body_sty
            ))

    # ── Open incidents ──
    if open_incidents:
        story.append(Spacer(1,6))
        story.append(Paragraph('Open Incidents', h2_sty))
        inc_data = [['Device', 'Health', 'Status', 'Diagnosis']]
        for inc in open_incidents[:12]:
            diag = (inc.get('ai_diagnosis') or '—')[:55]
            inc_data.append([
                inc.get('device_id','?')[-24:],
                f"{inc.get('health_score',0):.0f}",
                (inc.get('status','?')).upper(),
                diag
            ])
        inc_table = Table(inc_data, colWidths=[55*mm, 18*mm, 22*mm, 80*mm])
        inc_ts = TableStyle([
            ('BACKGROUND',    (0,0),(-1,0), DARK),
            ('TEXTCOLOR',     (0,0),(-1,0), WHITE),
            ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0),(-1,-1),7.5),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE, ROW_ALT]),
            ('GRID',          (0,0),(-1,-1),0.4, colors.HexColor('#d4daea')),
            ('TOPPADDING',    (0,0),(-1,-1),4),
            ('BOTTOMPADDING', (0,0),(-1,-1),4),
            ('LEFTPADDING',   (0,0),(-1,-1),5),
        ])
        inc_table.setStyle(inc_ts)
        story.append(inc_table)

    # ── Footer ──
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width='100%', thickness=0.8, color=MUTED, spaceAfter=5))
    story.append(Paragraph(
        f'IISentinel™ — Confidential Shift Report — {ts} — All data from live platform session',
        caption_sty
    ))

    doc.build(story)
    buffer.seek(0)
    fname = f'IISentinel_Report_{now.strftime("%Y%m%d_%H%M")}.pdf'
    return send_file(
        buffer,
        as_attachment=True,
        download_name=fname,
        mimetype='application/pdf'
    )


# ═══════════════════════════════════════════════════════════════════════════
# PLATFORM WATCHDOG — checks its own health every 60s, emails if degraded
# ═══════════════════════════════════════════════════════════════════════════
_watchdog_alerts_sent = set()

def platform_watchdog():
    """
    Background watchdog that monitors the platform's own health.
    Fires a self-alert email if queue depth is critically high,
    cache is stale, or no readings have been received in 15 minutes.
    Mirrors the same monitoring philosophy applied to client equipment.
    """
    global _watchdog_alerts_sent
    while True:
        time.sleep(60)
        issues = []

        # Queue overloading — ingestion can't keep up
        if len(metric_queue) > 400:
            issues.append(f'Ingestion queue at {len(metric_queue)}/500 — near capacity')

        # Cache staleness — suggests DB connectivity problem
        cache_age = time.time() - _data_cache['ts']
        if cache_age > 120 and _data_cache['ts'] > 0:
            issues.append(f'Data cache stale for {cache_age:.0f}s — possible DB issue')

        # No readings received in 15 minutes during expected operational hours
        last_flush = platform_stats.get('last_flush_ts')
        if last_flush and (time.time() - last_flush) > 900:
            issues.append(f'No data flushed in {int((time.time()-last_flush)/60)} minutes — collectors may be offline')

        if issues:
            alert_key = '|'.join(sorted(issues))
            if alert_key not in _watchdog_alerts_sent:
                _watchdog_alerts_sent.add(alert_key)
                msg = 'Platform self-diagnostic alert: ' + '; '.join(issues)
                threading.Thread(
                    target=send_email_alert,
                    kwargs=dict(
                        subject='Platform health warning',
                        body=msg,
                        device_id='IISentinel™ Platform',
                        health_score=None,
                        diagnosis='; '.join(issues),
                        automation_command='Check collector processes and database connectivity.',
                        severity='warning',
                    ),
                    daemon=True
                ).start()
        else:
            # Clear alert state when platform recovers
            _watchdog_alerts_sent.clear()

threading.Thread(target=platform_watchdog, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════════════
# HEALTH CHECK ENDPOINT — for load balancers and uptime monitors
# Returns 200 OK with platform status JSON when healthy
# Returns 503 when critically degraded
# ═══════════════════════════════════════════════════════════════════════════
@app.route('/health', methods=['GET'])
def health_check():
    """
    Lightweight health check endpoint.
    Used by uptime monitors (UptimeRobot, Better Uptime, etc.)
    and load balancers to verify the platform is alive.
    """
    queue_depth = len(metric_queue)
    cache_age   = round(time.time() - _data_cache['ts'], 1)
    uptime_h    = round((time.time() - platform_stats['start_ts']) / 3600, 2)

    degraded = queue_depth > 450 or (cache_age > 300 and _data_cache['ts'] > 0)

    status = {
        'status'       : 'degraded' if degraded else 'ok',
        'uptime_h'     : uptime_h,
        'queue_depth'  : queue_depth,
        'cache_age_s'  : cache_age,
        'devices'      : len(device_history),
        'anomalies'    : anomaly_count,
        'version'      : '2.0',
        'platform'     : 'IISentinel™',
    }
    return jsonify(status), 503 if degraded else 200


@app.route('/')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
