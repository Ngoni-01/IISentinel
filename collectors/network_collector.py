import time
import random
import requests

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

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
        'connected_devices': extras.get('connected_devices', random.randint(5, 30)),
        'temperature': extras.get('temperature', random.uniform(20, 60)),
        'signal_strength': extras.get('signal_strength', random.uniform(70, 100)),
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        print(f"[{device_id}] {metric_name}={metric_value:.1f} "
              f"→ score={r.json().get('health_score')} "
              f"anomaly={r.json().get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel Network Collector running...")
    while True:
        # Normal router
        send('router', 'core-router-01', 'cpu_load',
             random.uniform(10, 50), {
                 'cpu_load': random.uniform(10, 50),
                 'bandwidth_mbps': random.uniform(50, 300),
                 'latency_ms': random.uniform(1, 15),
                 'packet_loss': random.uniform(0, 0.3),
                 'connected_devices': random.randint(10, 40),
                 'temperature': random.uniform(30, 55),
                 'signal_strength': random.uniform(75, 100),
             })

        # Congestion event occasionally
        if random.random() < 0.2:
            send('switch', 'core-switch-01', 'bandwidth_mbps',
                 random.uniform(800, 1000), {
                     'cpu_load': random.uniform(75, 95),
                     'bandwidth_mbps': random.uniform(800, 1000),
                     'latency_ms': random.uniform(80, 200),
                     'packet_loss': random.uniform(2, 8),
                     'connected_devices': random.randint(60, 100),
                     'temperature': random.uniform(65, 85),
                     'signal_strength': random.uniform(40, 65),
                 })

        # Critical failure occasionally
        if random.random() < 0.05:
            send('router', 'edge-router-02', 'packet_loss',
                 random.uniform(10, 20), {
                     'cpu_load': random.uniform(92, 100),
                     'bandwidth_mbps': random.uniform(950, 1000),
                     'latency_ms': random.uniform(250, 500),
                     'packet_loss': random.uniform(10, 20),
                     'connected_devices': random.randint(90, 150),
                     'temperature': random.uniform(85, 100),
                     'signal_strength': random.uniform(10, 30),
                 })

        time.sleep(10)