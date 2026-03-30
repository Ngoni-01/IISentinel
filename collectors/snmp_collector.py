import time
import random
import requests
import subprocess
import platform

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

def ping_host(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        result = subprocess.run(
            ['ping', param, '1', host],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            output = result.stdout
            if 'time=' in output:
                time_str = output.split('time=')[-1].split('ms')[0].strip()
                return float(time_str.replace('<', ''))
        return 999.0
    except:
        return 999.0

def send(device_type, device_id, metric_name, metric_value, extras={}):
    payload = {
        'device_type': device_type,
        'device_id': device_id,
        'metric_name': metric_name,
        'metric_value': metric_value,
        'cpu_load': extras.get('cpu_load', random.uniform(10, 50)),
        'bandwidth_mbps': extras.get('bandwidth_mbps', random.uniform(10, 300)),
        'latency_ms': extras.get('latency_ms', 10.0),
        'packet_loss': extras.get('packet_loss', 0.0),
        'connected_devices': extras.get('connected_devices', 10),
        'temperature': extras.get('temperature', 40.0),
        'signal_strength': extras.get('signal_strength', 90.0),
        'protocol': 'SNMP/Ethernet-802.3'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        print(f"[SNMP][{device_id}] {metric_name}={metric_value:.1f} "
              f"→ score={result.get('health_score')} "
              f"anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel SNMP Collector running...")
    print("Protocol: SNMP over Ethernet IEEE 802.3")
    print("Pinging real network hosts + simulating SNMP metrics")
    print("-" * 55)
    
    hosts = {
        'gateway-router-01': '192.168.1.1',
        'dns-server-01': '8.8.8.8',
        'cloud-endpoint-01': '1.1.1.1',
    }
    
    while True:
        for device_id, host in hosts.items():
            latency = ping_host(host)
            packet_loss = 0.0 if latency < 999 else 100.0
            signal = max(0, 100 - latency * 0.5)
            
            send('router', device_id, 'latency_ms', latency, {
                'cpu_load': random.uniform(15, 45),
                'bandwidth_mbps': random.uniform(50, 400),
                'latency_ms': latency,
                'packet_loss': packet_loss,
                'connected_devices': random.randint(5, 50),
                'temperature': random.uniform(35, 55),
                'signal_strength': signal,
            })
        
        time.sleep(15)