import time
import random
import requests

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

MODBUS_REGISTERS = {
    100: 'temperature',
    101: 'motor_speed',
    102: 'pressure_bar',
    103: 'flow_rate',
    104: 'vibration',
    105: 'current_amps',
}

class ModbusSimulator:
    def __init__(self, device_id, base_values):
        self.device_id = device_id
        self.base_values = base_values
        self.fault_mode = False
        self.cycle = 0

    def read_register(self, address):
        self.cycle += 1
        if random.random() < 0.03:
            self.fault_mode = not self.fault_mode
        
        base = self.base_values.get(address, 50.0)
        noise = random.gauss(0, base * 0.05)
        
        if self.fault_mode:
            if address == 100:
                base *= 1.4
            elif address == 101:
                base *= 0.6
            elif address == 104:
                base *= 3.0
        
        return max(0.0, base + noise)

def send_modbus(device_id, register_name, value, extras={}):
    payload = {
        'device_type': 'scada_node',
        'device_id': device_id,
        'metric_name': register_name,
        'metric_value': value,
        'cpu_load': extras.get('cpu_load', 25.0),
        'bandwidth_mbps': extras.get('bandwidth_mbps', 15.0),
        'latency_ms': extras.get('latency_ms', 3.0),
        'packet_loss': extras.get('packet_loss', 0.1),
        'connected_devices': extras.get('connected_devices', 6),
        'temperature': extras.get('temperature', 50.0),
        'signal_strength': extras.get('signal_strength', 88.0),
        'protocol': 'Modbus-TCP/OPC-UA'
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        print(f"[MODBUS/OPC-UA][{device_id}] "
              f"reg={register_name} val={value:.2f} "
              f"→ score={result.get('health_score')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel Modbus-TCP / OPC-UA Collector running...")
    print("Protocol: Modbus TCP + OPC-UA — SCADA data exchange layer")
    print("Simulating: SCADA nodes, flow meters, pressure sensors")
    print("-" * 58)

    devices = [
        ModbusSimulator('modbus-pump-station-01', {
            100: 65.0, 101: 2800.0, 102: 6.5,
            103: 120.0, 104: 0.8, 105: 45.0
        }),
        ModbusSimulator('opcua-water-treatment-02', {
            100: 42.0, 101: 1500.0, 102: 4.2,
            103: 85.0, 104: 0.4, 105: 32.0
        }),
        ModbusSimulator('modbus-compressor-03', {
            100: 78.0, 101: 3500.0, 102: 8.8,
            103: 200.0, 104: 1.2, 105: 68.0
        }),
    ]

    while True:
        for device in devices:
            temp = device.read_register(100)
            speed = device.read_register(101)
            vibration = device.read_register(104)
            
            cpu = 20.0 + vibration * 3
            latency = 1.0 + vibration * 0.5
            signal = max(50.0, 95.0 - vibration * 5)
            
            send_modbus(device.device_id, 'temperature', temp, {
                'cpu_load': cpu,
                'bandwidth_mbps': random.uniform(8, 30),
                'latency_ms': latency,
                'packet_loss': max(0.0, vibration * 0.1),
                'connected_devices': random.randint(4, 12),
                'temperature': temp,
                'signal_strength': signal,
            })
        
        time.sleep(12)