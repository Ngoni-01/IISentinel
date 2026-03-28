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
        'connected_devices': extras.get('connected_devices', random.randint(50, 500)),
        'temperature': extras.get('temperature', random.uniform(20, 60)),
        'signal_strength': extras.get('signal_strength', random.uniform(70, 100)),
        'sector': 'telecom'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        print(f"[TELECOM][{device_id}] {metric_name}={metric_value:.1f} "
              f"→ score={result.get('health_score')} "
              f"anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel TelecomCo Collector running...")
    print("Monitoring: Base stations, towers, microwave links")
    print("-" * 50)
    while True:
        # Base station CBD — normal
        send('base_station', 'telecom-bs-cbd-01', 'signal_strength',
             random.uniform(75, 95), {
                 'cpu_load': random.uniform(20, 45),
                 'bandwidth_mbps': random.uniform(100, 400),
                 'latency_ms': random.uniform(2, 15),
                 'packet_loss': random.uniform(0, 0.3),
                 'connected_devices': random.randint(200, 800),
                 'temperature': random.uniform(25, 50),
                 'signal_strength': random.uniform(75, 95),
             })

        # Network tower — normal
        send('network_tower', 'telecom-tower-north-01', 'bandwidth_mbps',
             random.uniform(150, 350), {
                 'cpu_load': random.uniform(25, 50),
                 'bandwidth_mbps': random.uniform(150, 350),
                 'latency_ms': random.uniform(5, 25),
                 'packet_loss': random.uniform(0, 0.4),
                 'connected_devices': random.randint(300, 1000),
                 'temperature': random.uniform(28, 55),
                 'signal_strength': random.uniform(70, 92),
             })

        # Microwave backhaul link
        send('microwave_link', 'telecom-mw-link-01', 'latency_ms',
             random.uniform(3, 18), {
                 'cpu_load': random.uniform(15, 40),
                 'bandwidth_mbps': random.uniform(200, 500),
                 'latency_ms': random.uniform(3, 18),
                 'packet_loss': random.uniform(0, 0.2),
                 'connected_devices': random.randint(100, 400),
                 'temperature': random.uniform(22, 48),
                 'signal_strength': random.uniform(80, 98),
             })

        # Congestion event occasionally
        if random.random() < 0.2:
            send('base_station', 'telecom-bs-east-02', 'bandwidth_mbps',
                 random.uniform(800, 1000), {
                     'cpu_load': random.uniform(75, 92),
                     'bandwidth_mbps': random.uniform(800, 1000),
                     'latency_ms': random.uniform(80, 250),
                     'packet_loss': random.uniform(2, 8),
                     'connected_devices': random.randint(1000, 2000),
                     'temperature': random.uniform(60, 80),
                     'signal_strength': random.uniform(35, 55),
                 })

        # Tower failure occasionally
        if random.random() < 0.05:
            send('network_tower', 'telecom-tower-remote-03', 'packet_loss',
                 random.uniform(12, 25), {
                     'cpu_load': random.uniform(90, 100),
                     'bandwidth_mbps': random.uniform(900, 1000),
                     'latency_ms': random.uniform(300, 600),
                     'packet_loss': random.uniform(12, 25),
                     'connected_devices': random.randint(800, 1500),
                     'temperature': random.uniform(82, 98),
                     'signal_strength': random.uniform(8, 25),
                 })

        time.sleep(10)