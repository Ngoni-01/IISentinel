import time
import random
import requests

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

LOCATIONS = {
    'byo': {
        'name': 'Bulawayo HQ',
        'base_stations': ['tc-byo-bs-01', 'tc-byo-bs-02', 'tc-byo-bs-03'],
        'towers': ['tc-byo-tower-01', 'tc-byo-tower-02'],
        'mw_links': ['tc-byo-mw-01'],
        'base_load': 0.6,
    },
    'hre': {
        'name': 'Harare',
        'base_stations': ['tc-hre-bs-01', 'tc-hre-bs-02', 'tc-hre-bs-03', 'tc-hre-bs-04'],
        'towers': ['tc-hre-tower-01', 'tc-hre-tower-02', 'tc-hre-tower-03'],
        'mw_links': ['tc-hre-mw-01', 'tc-hre-mw-02'],
        'base_load': 0.75,
    },
    'mut': {
        'name': 'Mutare',
        'base_stations': ['tc-mut-bs-01', 'tc-mut-bs-02'],
        'towers': ['tc-mut-tower-01'],
        'mw_links': ['tc-mut-mw-01'],
        'base_load': 0.45,
    },
}

def send(device_type, device_id, metric_name, metric_value, extras={}):
    payload = {
        'device_type': device_type,
        'device_id': device_id,
        'metric_name': metric_name,
        'metric_value': metric_value,
        'cpu_load': extras.get('cpu_load', random.uniform(10, 50)),
        'bandwidth_mbps': extras.get('bandwidth_mbps', random.uniform(10, 300)),
        'latency_ms': extras.get('latency_ms', random.uniform(1, 20)),
        'packet_loss': extras.get('packet_loss', random.uniform(0, 0.5)),
        'connected_devices': extras.get('connected_devices', random.randint(50, 500)),
        'temperature': extras.get('temperature', random.uniform(25, 55)),
        'signal_strength': extras.get('signal_strength', random.uniform(70, 100)),
        'protocol': 'SNMP/Ethernet-802.3'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        loc = device_id.split('-')[1].upper()
        print(f"[TC][{loc}][{device_id.split('-')[-2]}-{device_id.split('-')[-1]}] "
              f"{metric_name}={metric_value:.1f} → score={result.get('health_score')} "
              f"anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel TelecomCo Collector running...")
    print("Sites: Bulawayo HQ · Harare · Mutare")
    print("Protocol: SNMP over Ethernet IEEE 802.3")
    print("-" * 55)

    while True:
        for loc_key, loc in LOCATIONS.items():
            load = loc['base_load']

            for bs in loc['base_stations']:
                congestion = random.random() < 0.15
                send('base_station', bs, 'signal_strength',
                     random.uniform(40, 95) if not congestion else random.uniform(20, 50), {
                     'cpu_load': random.uniform(20, 45) if not congestion else random.uniform(75, 92),
                     'bandwidth_mbps': random.uniform(100, 400) if not congestion else random.uniform(800, 1000),
                     'latency_ms': random.uniform(2, 15) if not congestion else random.uniform(80, 250),
                     'packet_loss': random.uniform(0, 0.3) if not congestion else random.uniform(2, 8),
                     'connected_devices': random.randint(int(200*load), int(800*load)),
                     'temperature': random.uniform(28, 55),
                     'signal_strength': random.uniform(65, 95) if not congestion else random.uniform(25, 55),
                 })

            for tower in loc['towers']:
                failure = random.random() < 0.05
                send('network_tower', tower, 'bandwidth_mbps',
                     random.uniform(150, 400) if not failure else random.uniform(900, 1000), {
                     'cpu_load': random.uniform(25, 50) if not failure else random.uniform(90, 100),
                     'bandwidth_mbps': random.uniform(150, 400) if not failure else random.uniform(900, 1000),
                     'latency_ms': random.uniform(5, 25) if not failure else random.uniform(300, 600),
                     'packet_loss': random.uniform(0, 0.4) if not failure else random.uniform(12, 25),
                     'connected_devices': random.randint(int(300*load), int(1000*load)),
                     'temperature': random.uniform(28, 58),
                     'signal_strength': random.uniform(70, 95) if not failure else random.uniform(8, 28),
                 })

            for mw in loc['mw_links']:
                send('microwave_link', mw, 'latency_ms',
                     random.uniform(3, 18), {
                     'cpu_load': random.uniform(15, 40),
                     'bandwidth_mbps': random.uniform(200, 600),
                     'latency_ms': random.uniform(3, 18),
                     'packet_loss': random.uniform(0, 0.2),
                     'connected_devices': random.randint(100, 400),
                     'temperature': random.uniform(22, 48),
                     'signal_strength': random.uniform(80, 98),
                 })

        time.sleep(10)