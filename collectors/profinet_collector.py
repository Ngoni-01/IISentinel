import time
import random
import requests
import math

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

def send(device_type, device_id, metric_name, metric_value, extras={}):
    payload = {
        'device_type': device_type,
        'device_id': device_id,
        'metric_name': metric_name,
        'metric_value': metric_value,
        'cpu_load': extras.get('cpu_load', 20.0),
        'bandwidth_mbps': extras.get('bandwidth_mbps', 20.0),
        'latency_ms': extras.get('latency_ms', 2.0),
        'packet_loss': extras.get('packet_loss', 0.0),
        'connected_devices': extras.get('connected_devices', 4),
        'temperature': extras.get('temperature', 45.0),
        'signal_strength': extras.get('signal_strength', 90.0),
        'protocol': 'Profinet/EtherNet-IP'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        print(f"[PROFINET][{device_id}] {metric_name}={metric_value:.2f} "
              f"→ score={result.get('health_score')} "
              f"anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

class PLCSimulator:
    def __init__(self, device_id, base_temp=50.0, base_speed=1500.0):
        self.device_id = device_id
        self.base_temp = base_temp
        self.base_speed = base_speed
        self.cycle = 0
        self.degrading = False
        self.degrade_start = random.randint(20, 60)

    def read_temperature(self):
        self.cycle += 1
        if self.cycle > self.degrade_start:
            self.degrading = True
        noise = random.gauss(0, 1.5)
        drift = (self.cycle - self.degrade_start) * 0.3 if self.degrading else 0
        temp = self.base_temp + noise + drift
        return max(20.0, min(120.0, temp))

    def read_speed(self):
        noise = random.gauss(0, 50)
        if self.degrading:
            noise -= random.uniform(0, 200)
        return max(0.0, self.base_speed + noise)

    def read_vibration(self):
        base_vib = 0.5
        if self.degrading:
            base_vib += (self.cycle - self.degrade_start) * 0.05
        return max(0.0, min(10.0, base_vib + random.gauss(0, 0.1)))

if __name__ == '__main__':
    print("IISentinel Profinet/EtherNet-IP Collector running...")
    print("Protocol: Profinet over Ethernet — Real-time PLC monitoring")
    print("Simulating: Conveyor PLCs, Pump controllers, Ventilation units")
    print("-" * 60)

    plcs = [
        PLCSimulator('profinet-conveyor-plc-01', base_temp=55.0, base_speed=1200.0),
        PLCSimulator('profinet-pump-plc-02', base_temp=60.0, base_speed=2800.0),
        PLCSimulator('profinet-vent-plc-03', base_temp=45.0, base_speed=3000.0),
        PLCSimulator('ethernetip-crusher-plc-04', base_temp=70.0, base_speed=800.0),
    ]

    while True:
        for plc in plcs:
            temp = plc.read_temperature()
            speed = plc.read_speed()
            vibration = plc.read_vibration()
            
            cpu = random.uniform(10, 35) + (vibration * 2)
            latency = random.uniform(0.5, 3.0)
            packet_loss = 0.0 if vibration < 3.0 else random.uniform(0, 2.0)
            signal = max(40.0, 100.0 - vibration * 5)

            send('plc', plc.device_id, 'temperature', temp, {
                'cpu_load': cpu,
                'bandwidth_mbps': random.uniform(5, 40),
                'latency_ms': latency,
                'packet_loss': packet_loss,
                'connected_devices': random.randint(2, 8),
                'temperature': temp,
                'signal_strength': signal,
            })

            if speed < 500:
                send('plc', plc.device_id, 'motor_speed', speed, {
                    'cpu_load': cpu + 10,
                    'bandwidth_mbps': random.uniform(5, 20),
                    'latency_ms': latency * 2,
                    'packet_loss': packet_loss + 1,
                    'connected_devices': random.randint(2, 6),
                    'temperature': temp,
                    'signal_strength': signal - 10,
                })

        time.sleep(10)