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
        'bandwidth_mbps': extras.get('bandwidth_mbps', random.uniform(5, 100)),
        'latency_ms': extras.get('latency_ms', random.uniform(1, 20)),
        'packet_loss': extras.get('packet_loss', random.uniform(0, 0.5)),
        'connected_devices': extras.get('connected_devices', random.randint(2, 20)),
        'temperature': extras.get('temperature', random.uniform(20, 80)),
        'signal_strength': extras.get('signal_strength', random.uniform(50, 100)),
        'sector': 'mining'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        print(f"[MINING][{device_id}] {metric_name}={metric_value:.1f} "
              f"→ score={result.get('health_score')} "
              f"anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel MiningCo Collector running...")
    print("Monitoring: Pumps, conveyors, ventilation, power meters")
    print("-" * 50)
    while True:
        # Underground pump — normal
        send('pump', 'mining-pump-level3-01', 'temperature',
             random.uniform(35, 65), {
                 'cpu_load': random.uniform(15, 40),
                 'bandwidth_mbps': random.uniform(5, 30),
                 'latency_ms': random.uniform(1, 10),
                 'packet_loss': random.uniform(0, 0.2),
                 'connected_devices': random.randint(2, 8),
                 'temperature': random.uniform(35, 65),
                 'signal_strength': random.uniform(60, 90),
             })

        # Conveyor belt motor
        send('conveyor', 'mining-conveyor-main-01', 'motor_speed',
             random.uniform(800, 1500), {
                 'cpu_load': random.uniform(20, 45),
                 'bandwidth_mbps': random.uniform(10, 50),
                 'latency_ms': random.uniform(2, 12),
                 'packet_loss': random.uniform(0, 0.3),
                 'connected_devices': random.randint(3, 10),
                 'temperature': random.uniform(30, 60),
                 'signal_strength': random.uniform(65, 88),
             })

        # Ventilation fan
        send('ventilation', 'mining-vent-fan-shaft2', 'motor_speed',
             random.uniform(1200, 2000), {
                 'cpu_load': random.uniform(18, 42),
                 'bandwidth_mbps': random.uniform(8, 40),
                 'latency_ms': random.uniform(1, 8),
                 'packet_loss': random.uniform(0, 0.2),
                 'connected_devices': random.randint(2, 6),
                 'temperature': random.uniform(28, 55),
                 'signal_strength': random.uniform(62, 85),
             })

        # Power meter
        send('power_meter', 'mining-power-main-grid', 'bandwidth_mbps',
             random.uniform(50, 200), {
                 'cpu_load': random.uniform(10, 30),
                 'bandwidth_mbps': random.uniform(50, 200),
                 'latency_ms': random.uniform(1, 5),
                 'packet_loss': random.uniform(0, 0.1),
                 'connected_devices': random.randint(10, 30),
                 'temperature': random.uniform(25, 45),
                 'signal_strength': random.uniform(75, 95),
             })

        # Overheating pump occasionally
        if random.random() < 0.15:
            send('pump', 'mining-pump-level5-02', 'temperature',
                 random.uniform(88, 100), {
                     'cpu_load': random.uniform(65, 88),
                     'bandwidth_mbps': random.uniform(5, 15),
                     'latency_ms': random.uniform(40, 120),
                     'packet_loss': random.uniform(2, 6),
                     'connected_devices': random.randint(2, 5),
                     'temperature': random.uniform(88, 100),
                     'signal_strength': random.uniform(25, 50),
                 })

        # Critical ventilation failure occasionally
        if random.random() < 0.05:
            send('ventilation', 'mining-vent-emergency-01', 'temperature',
                 random.uniform(92, 100), {
                     'cpu_load': random.uniform(88, 100),
                     'bandwidth_mbps': random.uniform(2, 10),
                     'latency_ms': random.uniform(200, 500),
                     'packet_loss': random.uniform(8, 20),
                     'connected_devices': random.randint(1, 3),
                     'temperature': random.uniform(92, 100),
                     'signal_strength': random.uniform(5, 20),
                 })

        time.sleep(10)