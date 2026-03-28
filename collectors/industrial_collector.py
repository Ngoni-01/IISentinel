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
        'bandwidth_mbps': extras.get('bandwidth_mbps', random.uniform(10, 100)),
        'latency_ms': extras.get('latency_ms', random.uniform(1, 20)),
        'packet_loss': extras.get('packet_loss', random.uniform(0, 0.5)),
        'connected_devices': extras.get('connected_devices', random.randint(2, 15)),
        'temperature': extras.get('temperature', random.uniform(20, 80)),
        'signal_strength': extras.get('signal_strength', random.uniform(60, 100)),
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        print(f"[{device_id}] {metric_name}={metric_value:.1f} "
              f"→ score={r.json().get('health_score')} "
              f"anomaly={r.json().get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel Industrial Collector running...")
    while True:
        send('plc', 'pump-plc-01', 'temperature',
             random.uniform(40, 70), {
                 'cpu_load': random.uniform(15, 40),
                 'bandwidth_mbps': random.uniform(5, 50),
                 'latency_ms': random.uniform(1, 10),
                 'packet_loss': random.uniform(0, 0.2),
                 'connected_devices': random.randint(2, 8),
                 'temperature': random.uniform(40, 70),
                 'signal_strength': random.uniform(70, 95),
             })

        send('plc', 'motor-plc-02', 'motor_speed',
             random.uniform(1000, 3000), {
                 'cpu_load': random.uniform(20, 45),
                 'bandwidth_mbps': random.uniform(10, 80),
                 'latency_ms': random.uniform(2, 12),
                 'packet_loss': random.uniform(0, 0.3),
                 'connected_devices': random.randint(3, 10),
                 'temperature': random.uniform(35, 65),
                 'signal_strength': random.uniform(65, 90),
             })

        if random.random() < 0.15:
            send('sensor', 'temp-sensor-03', 'temperature',
                 random.uniform(88, 100), {
                     'cpu_load': random.uniform(60, 85),
                     'bandwidth_mbps': random.uniform(5, 20),
                     'latency_ms': random.uniform(30, 100),
                     'packet_loss': random.uniform(1, 5),
                     'connected_devices': random.randint(5, 15),
                     'temperature': random.uniform(88, 100),
                     'signal_strength': random.uniform(30, 55),
                 })

        time.sleep(10)