import time
import random
import requests

API_URL = "https://git-push-origin-main.onrender.com/api/metrics"

CBS_SAFETY_THRESHOLD = 90.0

class CentralisedBlastingSystem:
    def __init__(self):
        self.blast_hold = False
        self.blast_count = 0
        self.personnel_clear = True
        self.doors_locked = True
        self.link_health = 100.0
        self.cycle = 0

    def simulate_link(self):
        self.cycle += 1
        noise = random.gauss(0, 2.0)
        if random.random() < 0.05:
            noise -= random.uniform(15, 40)
        self.link_health = max(0.0, min(100.0, self.link_health + noise))
        return self.link_health

    def check_safety(self, link_health):
        if link_health < CBS_SAFETY_THRESHOLD:
            if not self.blast_hold:
                self.blast_hold = True
                print(f"\n{'='*55}")
                print(f"  CBS SAFETY INTERLOCK ACTIVATED")
                print(f"  Link health: {link_health:.1f}% — below threshold {CBS_SAFETY_THRESHOLD}%")
                print(f"  BLAST HOLD command issued to detonator network")
                print(f"  Blasting officer alert triggered")
                print(f"{'='*55}\n")
        else:
            if self.blast_hold:
                self.blast_hold = False
                print(f"\n  CBS link restored — health: {link_health:.1f}%")
                print(f"  Blast hold released — awaiting blasting officer confirmation\n")

def send_cbs(device_id, link_health, blast_hold, extras={}):
    automation = None
    if blast_hold:
        automation = (f"CBS SAFETY INTERLOCK: BLAST HOLD active on {device_id} "
                     f"— link health {link_health:.1f}% below safe threshold. "
                     f"All detonation circuits locked.")
    payload = {
        'device_type': 'cbs_controller',
        'device_id': device_id,
        'metric_name': 'link_health',
        'metric_value': link_health,
        'cpu_load': extras.get('cpu_load', 20.0),
        'bandwidth_mbps': extras.get('bandwidth_mbps', 10.0),
        'latency_ms': extras.get('latency_ms', 1.0),
        'packet_loss': extras.get('packet_loss', 0.0),
        'connected_devices': extras.get('connected_devices', 3),
        'temperature': extras.get('temperature', 35.0),
        'signal_strength': link_health,
        'protocol': 'DNP3/Ethernet',
        'blast_hold': blast_hold,
        'automation_override': automation
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=15)
        result = r.json()
        status = "HOLD ACTIVE" if blast_hold else "ARMED"
        print(f"[CBS][{device_id}] link={link_health:.1f}% "
              f"status={status} "
              f"→ score={result.get('health_score')} "
              f"anomaly={result.get('anomaly_flag')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    print("IISentinel CBS Monitor running...")
    print("Protocol: DNP3 over Ethernet — Safety-critical blasting system")
    print(f"Safety threshold: {CBS_SAFETY_THRESHOLD}% link health")
    print("BLAST HOLD triggers automatically if link degrades")
    print("-" * 55)

    cbs_units = [
        CentralisedBlastingSystem(),
        CentralisedBlastingSystem(),
    ]
    unit_ids = [
        'cbs-dnp3-shaft2-detonator',
        'cbs-dnp3-shaft4-detonator',
    ]

    while True:
        for i, (cbs, device_id) in enumerate(zip(cbs_units, unit_ids)):
            link_health = cbs.simulate_link()
            cbs.check_safety(link_health)
            
            latency = max(0.1, (100 - link_health) * 0.5)
            packet_loss = max(0.0, (100 - link_health) * 0.1)
            
            send_cbs(device_id, link_health, cbs.blast_hold, {
                'cpu_load': random.uniform(5, 25),
                'bandwidth_mbps': random.uniform(2, 15),
                'latency_ms': latency,
                'packet_loss': packet_loss,
                'connected_devices': random.randint(2, 5),
                'temperature': random.uniform(25, 45),
                'signal_strength': link_health,
            })

        time.sleep(10)