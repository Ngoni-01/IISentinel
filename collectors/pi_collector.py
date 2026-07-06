#!/usr/bin/env python3
"""
IISentinel™ Raspberry Pi Edge Collector
========================================
Runs on a Raspberry Pi 4 field node. Reads physical sensors, scores them
against the IISentinel platform, and drives local indicators (LEDs, buzzer)
so field crews get instant visual/audible status without a screen.

Works in TWO modes automatically:
  REAL  — on a Pi with sensors wired (DHT22 temp/humidity, MPU-6050 vibration)
  SIM   — on any machine with no GPIO — generates realistic readings
          (use for development and demos)

Usage:
    python3 pi_collector.py --server https://your-app.onrender.com \
                            --key   <collector-api-key> \
                            --device mc-shaft1-pump-01 --type pump

    # No key yet? Register one first from the specialist panel, or:
    python3 pi_collector.py --server http://localhost:5000 --register "shaft1-pi-01"

GPIO wiring (BCM numbering):
    GPIO4   DHT22 data
    GPIO17  Green LED   (healthy, score >= 70)
    GPIO27  Amber LED   (warning, 35-70)
    GPIO22  Red LED     (critical < 35 or CBS hold)
    GPIO23  Buzzer      (critical / CBS hold)
    GPIO24  Blue LED    (maintenance window active)
    I2C     MPU-6050 vibration sensor (SDA/SCL, addr 0x68)

Offline resilience: if the server is unreachable, readings buffer to
pi_buffer.jsonl on disk and flush automatically when the link returns.
"""
import argparse, json, os, random, sys, time, math
from collections import deque

try:
    import requests
except ImportError:
    print("pip install requests"); sys.exit(1)

# ── Optional hardware imports — absent on non-Pi machines ─────────────────────
GPIO = None
DHT_SENSOR = None
MPU = None
try:
    import RPi.GPIO as GPIO           # type: ignore
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
except Exception:
    GPIO = None

try:
    import adafruit_dht, board        # type: ignore
    DHT_SENSOR = adafruit_dht.DHT22(board.D4)
except Exception:
    DHT_SENSOR = None

try:
    from mpu6050 import mpu6050       # type: ignore
    MPU = mpu6050(0x68)
except Exception:
    MPU = None

SIM_MODE = GPIO is None
PIN = {'green': 17, 'amber': 27, 'red': 22, 'buzzer': 23, 'blue': 24}
BUFFER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pi_buffer.jsonl')


# ── GPIO helpers ──────────────────────────────────────────────────────────────
def gpio_init():
    if GPIO is None:
        return
    for p in PIN.values():
        GPIO.setup(p, GPIO.OUT)
        GPIO.output(p, GPIO.LOW)


def set_leds(score, cbs_hold=False, in_maintenance=False):
    """Green >=70, Amber 35-70, Red <35 or hold. Blue = maintenance."""
    state = {
        'green':  score >= 70 and not cbs_hold,
        'amber':  35 <= score < 70 and not cbs_hold,
        'red':    score < 35 or cbs_hold,
        'buzzer': (score < 20 or cbs_hold) and not in_maintenance,
        'blue':   in_maintenance,
    }
    if GPIO is None:
        icons = []
        if state['green']:  icons.append('GREEN')
        if state['amber']:  icons.append('AMBER')
        if state['red']:    icons.append('RED')
        if state['buzzer']: icons.append('BUZZER!')
        if state['blue']:   icons.append('MAINT')
        return ' '.join(icons) or 'off'
    for name, on in state.items():
        GPIO.output(PIN[name], GPIO.HIGH if on else GPIO.LOW)
    return ''


# ── Sensor reading ────────────────────────────────────────────────────────────
_sim_phase = random.uniform(0, math.pi * 2)
_sim_event = 0

def read_sensors():
    """Return (temperature_c, humidity_pct, vibration_g)."""
    global _sim_event, _sim_phase
    if not SIM_MODE and (DHT_SENSOR or MPU):
        temp = hum = vib = None
        if DHT_SENSOR:
            try:
                temp = DHT_SENSOR.temperature
                hum  = DHT_SENSOR.humidity
            except Exception:
                pass  # DHT22 misreads ~1 in 5 polls — normal, reuse previous
        if MPU:
            try:
                a = MPU.get_accel_data()
                vib = abs(math.sqrt(a['x']**2 + a['y']**2 + a['z']**2) - 9.81) / 9.81
            except Exception:
                pass
        return temp if temp is not None else 35.0, \
               hum  if hum  is not None else 50.0, \
               vib  if vib  is not None else 0.05
    # Simulation: slow sinusoidal drift + occasional degradation events
    _sim_phase += 0.05
    if _sim_event > 0:
        _sim_event -= 1
    elif random.random() < 0.03:
        _sim_event = random.randint(8, 20)
    sev  = _sim_event / 20.0
    temp = 38 + 6 * math.sin(_sim_phase) + sev * 30 + random.gauss(0, 1.5)
    hum  = 55 + 10 * math.sin(_sim_phase * 0.6) + random.gauss(0, 3)
    vib  = 0.05 + sev * 1.8 + abs(random.gauss(0, 0.05))
    return round(temp, 1), round(max(0, min(100, hum)), 1), round(vib, 3)


def build_reading(device_id, device_type, temp, hum, vib):
    """Map physical sensors into the IISentinel metric schema."""
    sig = max(5.0, min(100.0, 100 - vib * 40))           # vibration erodes 'signal'
    return {
        'device_id':         device_id,
        'device_type':       device_type,
        'metric_name':       'temperature',
        'metric_value':      temp,
        'temperature':       temp,
        'signal_strength':   round(sig, 1),
        'cpu_load':          round(min(98, 15 + vib * 60 + random.gauss(0, 4)), 1),
        'bandwidth_mbps':    50.0,
        'latency_ms':        round(5 + vib * 40, 1),
        'packet_loss':       round(min(20, vib * 4), 2),
        'connected_devices': 1,
        'humidity':          hum,
        'vibration_g':       vib,
        'protocol':          'GPIO/I2C-Edge' if not SIM_MODE else 'SIM/Edge',
    }


# ── Offline buffer ────────────────────────────────────────────────────────────
def buffer_append(reading):
    try:
        with open(BUFFER_FILE, 'a') as f:
            f.write(json.dumps(reading) + '\n')
    except Exception:
        pass


def buffer_flush(server, key):
    """Send buffered readings in batches of 100. Returns count sent."""
    if not os.path.exists(BUFFER_FILE):
        return 0
    try:
        with open(BUFFER_FILE) as f:
            lines = [json.loads(l) for l in f if l.strip()]
    except Exception:
        return 0
    if not lines:
        return 0
    sent = 0
    for i in range(0, len(lines), 100):
        batch = lines[i:i+100]
        try:
            r = requests.post(f'{server}/api/collector/ingest',
                              headers={'X-Collector-Key': key},
                              json={'readings': batch}, timeout=10)
            if r.status_code == 200:
                sent += len(batch)
            else:
                break
        except Exception:
            break
    if sent >= len(lines):
        os.remove(BUFFER_FILE)
    elif sent:
        with open(BUFFER_FILE, 'w') as f:
            for row in lines[sent:]:
                f.write(json.dumps(row) + '\n')
    return sent


# ── Registration helper ───────────────────────────────────────────────────────
def register(server, name):
    r = requests.post(f'{server}/api/collector/register',
                      json={'name': name, 'sector': 'mc',
                            'description': f'Raspberry Pi edge node {name}'},
                      timeout=10)
    d = r.json()
    if 'api_key' in d:
        print('\nCollector registered.')
        print(f"  ID:      {d['id']}")
        print(f"  API key: {d['api_key']}")
        print('\nSTORE THIS KEY — it is not shown again.')
        print(f"Run: python3 pi_collector.py --server {server} --key {d['api_key']} "
              f"--device mc-shaft1-pi-01 --type sensor")
    else:
        print('Registration failed:', d.get('error', r.status_code))


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description='IISentinel Pi Edge Collector')
    p.add_argument('--server',   default='http://localhost:5000')
    p.add_argument('--key',      default=os.environ.get('IIS_COLLECTOR_KEY', ''))
    p.add_argument('--device',   default='mc-field-pi-01')
    p.add_argument('--type',     default='sensor', dest='dtype')
    p.add_argument('--interval', type=float, default=5.0)
    p.add_argument('--register', default=None, metavar='NAME',
                   help='Register a new collector and print its API key')
    args = p.parse_args()

    if args.register:
        register(args.server, args.register)
        return
    if not args.key:
        print('No API key. Register first:  --register "my-pi-01"')
        sys.exit(1)

    gpio_init()
    mode = 'SIMULATION (no GPIO detected)' if SIM_MODE else 'REAL SENSORS'
    print(f'IISentinel Pi Collector — {mode}')
    print(f'  Server:   {args.server}')
    print(f'  Device:   {args.device} ({args.dtype})')
    print(f'  Interval: {args.interval}s\n')

    recent = deque(maxlen=12)
    consecutive_failures = 0

    while True:
        temp, hum, vib = read_sensors()
        reading = build_reading(args.device, args.dtype, temp, hum, vib)
        try:
            r = requests.post(f'{args.server}/api/collector/ingest',
                              headers={'X-Collector-Key': args.key},
                              json={'readings': [reading]}, timeout=8)
            if r.status_code == 200:
                consecutive_failures = 0
                flushed = buffer_flush(args.server, args.key)
                # Pull live score back for LED display
                d = r.json()
                res = (d.get('results') or [{}])[0]
                score = res.get('health_score', 50)
                recent.append(score)
                leds = set_leds(score,
                                cbs_hold=bool(res.get('blast_hold')),
                                in_maintenance=bool(res.get('in_maintenance')))
                extra = f'  [buffered flushed: {flushed}]' if flushed else ''
                sim_leds = f'  LEDs: {leds}' if SIM_MODE else ''
                print(f'{time.strftime("%H:%M:%S")}  T={temp:5.1f}C  H={hum:4.1f}%  '
                      f'V={vib:5.3f}g  score={score:5.1f}{sim_leds}{extra}')
            else:
                raise RuntimeError(f'HTTP {r.status_code}')
        except Exception as e:
            consecutive_failures += 1
            buffer_append(reading)
            set_leds(50)  # neutral amber-ish state while offline
            print(f'{time.strftime("%H:%M:%S")}  OFFLINE ({e}) — buffered locally '
                  f'({consecutive_failures} consecutive)')
        time.sleep(args.interval)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        if GPIO:
            GPIO.cleanup()
        print('\nStopped.')
