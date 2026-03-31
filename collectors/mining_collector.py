import time
import random
import requests
import math

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

SECTIONS = {
    'shaft1': {
        'name': 'Shaft 1 — Level 3-7',
        'devices': {
            'mc-shaft1-pump-01': ('pump', 58.0, 2800.0),
            'mc-shaft1-pump-02': ('pump', 62.0, 2600.0),
            'mc-shaft1-vent-01': ('ventilation', 50.0, 3200.0),
            'mc-shaft1-conveyor-01': ('conveyor', 55.0, 1200.0),
        },
        'depth_factor': 1.3,
    },
    'shaft2': {
        'name': 'Shaft 2 — Level 5-10',
        'devices': {
            'mc-shaft2-pump-01': ('pump', 68.0, 2400.0),
            'mc-shaft2-pump-02': ('pump', 72.0, 2200.0),
            'mc-shaft2-vent-01': ('ventilation', 60.0, 3000.0),
            'mc-shaft2-vent-02': ('ventilation', 58.0, 2800.0),
            'mc-shaft2-conveyor-01': ('conveyor', 60.0, 1000.0),
        },
        'depth_factor': 1.6,
    },
    'plant': {
        'name': 'Processing Plant',
        'devices': {
            'mc-plant-crusher-01': ('plc', 70.0, 800.0),
            'mc-plant-mill-01': ('plc', 65.0, 1500.0),
            'mc-plant-pump-01': ('pump', 50.0, 3000.0),
            'mc-plant-scada-01': ('scada_node', 40.0, 1800.0),
        },
        'depth_factor': 1.0,
    },
    'surface': {
        'name': 'Surface Infrastructure',
        'devices': {
            'mc-surface-power-01': ('power_meter', 45.0, 500.0),
            'mc-surface-water-01': ('pump', 42.0, 1200.0),
            'mc-surface-compressor-01': ('plc', 55.0, 3500.0),
            'mc-surface-sensor-01': ('sensor', 38.0, 0.0),
        },
        'depth_factor': 0.8,
    },
}

device_cycles = {}

def get_device_metrics(device_id, base_temp, base_speed, depth_factor, cycle):
    if device_id not in device_cycles:
        device_cycles[device_id] = {'degrading': False, 'degrade_start': random.randint(30, 80), 'cycle': 0}
    dc = device_cycles[device_id]
    dc['cycle'] += 1
    if dc['cycle'] > dc['degrade_start']:
        dc['degrading'] = True

    noise_temp = random.gauss(0, 2.0)
    noise_speed = random.gauss(0, 80)
    depth_heat = (depth_factor - 1.0) * 15.0
    drift_temp = (dc['cycle'] - dc['degrade_start']) * 0.4 if dc['degrading'] else 0
    drift_speed = -(dc['cycle'] - dc['degrade_start']) * 15 if dc['degrading'] else 0

    temp = base_temp + depth_heat + noise_temp + drift_temp
    speed = base_speed + noise_speed + drift_speed if base_speed > 0 else 0
    vibration = 0.5 + (0.1 * (dc['cycle'] - dc['degrade_start'])) if dc['degrading'] else random.uniform(0.2, 0.8)

    return {
        'temperature': max(20.0, min(120.0, temp)),
        'speed': max(0.0, speed),
        'vibration': max(0.0, min(10.0, vibration)),
    }

def send(device_type, device_id, metric_name, metric_value, extras={}):
    payload = {
        'device_type': device_type,
        'device_id': device_id,
        'metric_name': metric_name,
        'metric_value': metric_value,
        'cpu_load': extras.get('cpu_load', random.uniform(15, 45)),
        'bandwidth_mbps': extras.get('bandwidth_mbps', random.uniform(5, 50)),
        'latency_ms': extras.get('latency_ms', random.uniform(1, 10)),
        'packet_loss': extras.get('packet_loss', random.uniform(0, 0.3)),
        'connected_devices': extras.get('connected_devices', random.randint(2, 10)),
        'temperature': extras.get('temperature', random.uniform(35, 70)),
        'signal_strength': extras.get('signal_strength', random.uniform(60, 95)),
        'protocol': 'Profinet/EtherNet-IP'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        sec = device_id.split('-')[1].upper()
        print(f"[MC][{sec}][{device_id.split('-')[-2]}-{device_id.split('-')[-1]}] "
              f"{metric_name}={metric_value:.1f} → score={result.get('health_score')} "
              f"anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel MiningCo Collector running...")
    print("Sections: Shaft 1 · Shaft 2 · Processing Plant · Surface Infrastructure")
    print("Protocol: Profinet / EtherNet-IP / Modbus TCP / OPC-UA")
    print("-" * 58)

    while True:
        for sec_key, section in SECTIONS.items():
            for device_id, (device_type, base_temp, base_speed) in section['devices'].items():
                metrics = get_device_metrics(
                    device_id, base_temp, base_speed,
                    section['depth_factor'],
                    device_cycles.get(device_id, {}).get('cycle', 0)
                )
                temp = metrics['temperature']
                vibration = metrics['vibration']
                cpu = 20.0 + vibration * 4
                latency = 1.0 + vibration * 0.8
                packet_loss = max(0.0, vibration * 0.15)
                signal = max(40.0, 95.0 - vibration * 6)

                send(device_type, device_id, 'temperature', temp, {
                    'cpu_load': cpu,
                    'bandwidth_mbps': random.uniform(5, 40),
                    'latency_ms': latency,
                    'packet_loss': packet_loss,
                    'connected_devices': random.randint(2, 10),
                    'temperature': temp,
                    'signal_strength': signal,
                })

        time.sleep(10)