import time
import random
import requests
import subprocess
import platform

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

LOCATIONS = {
    'byo': {
        'name': 'Bulawayo HQ',
        'routers': ['net-byo-router-01', 'net-byo-router-02'],
        'switches': ['net-byo-switch-01', 'net-byo-switch-02', 'net-byo-switch-03'],
        'firewalls': ['net-byo-fw-01'],
        'wan': ['net-byo-wan-01'],
    },
    'hre': {
        'name': 'Harare',
        'routers': ['net-hre-router-01'],
        'switches': ['net-hre-switch-01', 'net-hre-switch-02'],
        'firewalls': ['net-hre-fw-01'],
        'wan': ['net-hre-wan-01'],
    },
    'mut': {
        'name': 'Mutare',
        'routers': ['net-mut-router-01'],
        'switches': ['net-mut-switch-01'],
        'firewalls': [],
        'wan': ['net-mut-wan-01'],
    },
}

PING_TARGETS = {
    'net-byo-router-01': '192.168.1.1',
    'net-byo-wan-01': '8.8.8.8',
    'net-hre-wan-01': '1.1.1.1',
    'net-mut-wan-01': '8.8.4.4',
}

def ping(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        result = subprocess.run(['ping', param, '1', host],
            capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and 'time=' in result.stdout:
            t = result.stdout.split('time=')[-1].split('ms')[0].strip()
            return float(t.replace('<', '').replace('>', ''))
        return 500.0
    except:
        return 500.0

def send(device_type, device_id, metric_name, metric_value, extras={}):
    payload = {
        'device_type': device_type,
        'device_id': device_id,
        'metric_name': metric_name,
        'metric_value': metric_value,
        'cpu_load': extras.get('cpu_load', random.uniform(10, 50)),
        'bandwidth_mbps': extras.get('bandwidth_mbps', random.uniform(50, 500)),
        'latency_ms': extras.get('latency_ms', random.uniform(1, 20)),
        'packet_loss': extras.get('packet_loss', random.uniform(0, 0.5)),
        'connected_devices': extras.get('connected_devices', random.randint(5, 80)),
        'temperature': extras.get('temperature', random.uniform(30, 55)),
        'signal_strength': extras.get('signal_strength', random.uniform(75, 100)),
        'protocol': 'SNMP/Ethernet-802.3'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        loc = device_id.split('-')[1].upper()
        dtype = device_id.split('-')[2]
        print(f"[NET][{loc}][{dtype}] {metric_name}={metric_value:.1f} "
              f"→ score={result.get('health_score')} anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel Network Infrastructure Collector running...")
    print("Sites: Bulawayo HQ · Harare · Mutare")
    print("Protocol: SNMP over Ethernet IEEE 802.3")
    print("Device types: Routers · Switches · Firewalls · WAN links")
    print("-" * 58)

    while True:
        for loc_key, loc in LOCATIONS.items():
            for router in loc['routers']:
                latency = ping(PING_TARGETS.get(router, '8.8.8.8'))
                packet_loss = 0.0 if latency < 400 else random.uniform(5, 15)
                send('router', router, 'latency_ms', latency, {
                    'cpu_load': random.uniform(15, 55),
                    'bandwidth_mbps': random.uniform(100, 600),
                    'latency_ms': latency,
                    'packet_loss': packet_loss,
                    'connected_devices': random.randint(20, 100),
                    'temperature': random.uniform(32, 58),
                    'signal_strength': max(20, 100 - latency * 0.15),
                })

            for switch in loc['switches']:
                congestion = random.random() < 0.1
                send('switch', switch, 'bandwidth_mbps',
                     random.uniform(50, 400) if not congestion else random.uniform(800, 1000), {
                     'cpu_load': random.uniform(10, 40) if not congestion else random.uniform(75, 92),
                     'bandwidth_mbps': random.uniform(50, 400) if not congestion else random.uniform(800, 1000),
                     'latency_ms': random.uniform(0.5, 5) if not congestion else random.uniform(50, 150),
                     'packet_loss': random.uniform(0, 0.2) if not congestion else random.uniform(2, 8),
                     'connected_devices': random.randint(10, 48),
                     'temperature': random.uniform(28, 52),
                     'signal_strength': random.uniform(80, 100) if not congestion else random.uniform(40, 65),
                 })

            for fw in loc['firewalls']:
                send('firewall', fw, 'cpu_load', random.uniform(20, 65), {
                    'cpu_load': random.uniform(20, 65),
                    'bandwidth_mbps': random.uniform(200, 800),
                    'latency_ms': random.uniform(1, 8),
                    'packet_loss': random.uniform(0, 0.1),
                    'connected_devices': random.randint(50, 200),
                    'temperature': random.uniform(35, 60),
                    'signal_strength': random.uniform(85, 100),
                })

            for wan in loc['wan']:
                latency = ping(PING_TARGETS.get(wan, '8.8.8.8'))
                send('wan_link', wan, 'latency_ms', latency, {
                    'cpu_load': random.uniform(5, 30),
                    'bandwidth_mbps': random.uniform(50, 300),
                    'latency_ms': latency,
                    'packet_loss': 0.0 if latency < 400 else random.uniform(1, 10),
                    'connected_devices': random.randint(5, 20),
                    'temperature': random.uniform(25, 45),
                    'signal_strength': max(20, 100 - latency * 0.1),
                })

        time.sleep(15)