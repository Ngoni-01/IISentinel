#!/usr/bin/env python3
"""
IISentinel™ Demo Collector
──────────────────────────
Standalone script that injects realistic sensor data into IISentinel™.
Use this for:
  - Expo / pitch demonstrations
  - Development and testing
  - Training new engineers on the dashboard

Usage:
  python demo_collector.py                      # connects to localhost:5000
  python demo_collector.py --host 10.0.0.5:5000 # remote host
  python demo_collector.py --speed fast         # faster injection (1s)
  python demo_collector.py --event cbs          # trigger a CBS blast hold

Devices simulated:
  Network:  5 devices (Bulawayo, Harare, Mutare)
  Telecom:  3 devices (base stations, towers, microwave)
  Mining:   6 devices (pumps, ventilation, conveyor, PLC)
  CBS:      1 controller (DNP3 link health)
"""
import argparse
import random
import time
import requests
import sys
from datetime import datetime

BASE_URL = 'http://localhost:5000'

DEVICES = [
    # id, type, site, base_sig, base_lat, base_bw, base_temp
    ('net-byo-router-01',     'router',          'byo',   90, 35,  120, 42),
    ('net-byo-switch-core',   'switch',          'byo',   88,  8,  480, 38),
    ('net-hre-router-01',     'router',          'hre',   82, 28,   95, 45),
    ('net-hre-wan-link',      'wan_link',        'hre',   75, 62,   55, 40),
    ('net-mut-firewall-01',   'firewall',        'mut',   85, 18,   75, 44),
    ('tc-byo-base-stn-01',    'base_station',    'byo',   78, 15,  220, 52),
    ('tc-hre-tower-main',     'network_tower',   'hre',   82, 22,  180, 48),
    ('tc-mut-microwave-01',   'microwave_link',  'mut',   70, 35,  120, 55),
    ('mc-shaft1-pump-01',     'pump',            'mine',  88, 12,   18, 68),
    ('mc-shaft1-pump-02',     'pump',            'mine',  84, 14,   16, 72),
    ('mc-shaft2-ventilation', 'ventilation',     'mine',  86, 10,   22, 75),
    ('mc-shaft2-conveyor',    'conveyor',        'mine',  90,  8,   20, 62),
    ('mc-plant-plc-01',       'plc',             'mine',  92,  6,   30, 55),
    ('mc-surface-pwr-meter',  'power_meter',     'mine',  95,  9,   12, 48),
    ('cbs-dnp3-mine-ctrl',    'cbs_controller',  'mine',  96,  5,    8, 35),
]

MINING_TYPES  = {'pump','conveyor','ventilation','plc','power_meter','sensor','scada_node'}
TELECOM_TYPES = {'base_station','network_tower','microwave_link'}

in_event  = {d[0]: 0 for d in DEVICES}
cycle_num = 0

def make_reading(dev, forced_event=None):
    did, dtype, site, bsig, blat, bbw, btemp = dev

    # Event logic
    if forced_event == 'cbs' and dtype == 'cbs_controller':
        in_event[did] = 8
    elif forced_event == 'critical' and dtype in ('pump','ventilation'):
        in_event[did] = 10
    elif in_event[did] > 0:
        in_event[did] -= 1
    elif random.random() < 0.08:
        in_event[did] = random.randint(4, 12)

    # CBS has extra degradation chance
    if dtype == 'cbs_controller' and random.random() < 0.008:
        in_event[did] = random.randint(5, 9)

    sev  = in_event[did] / 12.0
    sig  = max(20, bsig  * (1 - sev * 0.45) + random.gauss(0, 4))
    lat  = max(1,  blat  * (1 + sev * 3.0)  + random.gauss(0, blat * 0.1))
    bw   = max(1,  bbw   * (1 - sev * 0.6)  + random.gauss(0, bbw * 0.08))
    temp = btemp * (1 + sev * 0.5)  + random.gauss(0, 3)
    cpu  = min(98, 20 + sev * 75    + random.gauss(0, 8))
    loss = max(0,  sev * 8          + random.gauss(0, 0.8))

    if dtype in MINING_TYPES:
        mn, mv = 'temperature', round(temp, 1)
    elif dtype in TELECOM_TYPES or dtype == 'cbs_controller':
        mn, mv = 'signal_strength', round(sig, 1)
    else:
        mn, mv = 'latency_ms', round(lat, 1)

    return {
        'device_id':         did,
        'device_type':       dtype,
        'metric_name':       mn,
        'metric_value':      mv,
        'cpu_load':          round(cpu, 1),
        'bandwidth_mbps':    round(bw, 1),
        'latency_ms':        round(lat, 1),
        'packet_loss':       round(loss, 2),
        'connected_devices': max(1, int(10 * (1 - sev * 0.4))),
        'temperature':       round(temp, 1),
        'signal_strength':   round(sig, 1),
        'protocol': (
            'DNP3/Ethernet'        if dtype == 'cbs_controller' else
            'Profinet/EtherNet-IP' if dtype in MINING_TYPES else
            'SNMP/Ethernet-802.3'
        ),
    }

def run(host, speed, forced_event=None):
    global cycle_num
    url = f'{host}/api/metrics'
    interval = {'fast': 1.0, 'normal': 3.5, 'slow': 6.0}.get(speed, 3.5)
    print(f'IISentinel™ Demo Collector')
    print(f'  Target : {url}')
    print(f'  Devices: {len(DEVICES)}')
    print(f'  Speed  : {speed} ({interval}s)')
    if forced_event:
        print(f'  Event  : {forced_event}')
    print()

    ok_count  = 0
    err_count = 0

    while True:
        cycle_num += 1
        for dev in DEVICES:
            payload = make_reading(dev, forced_event if cycle_num <= 3 else None)
            try:
                r = requests.post(url, json=payload, timeout=5)
                if r.status_code == 200:
                    d = r.json()
                    score   = d.get('health_score', 0)
                    anomaly = '⚠ ANOM' if d.get('anomaly_flag') else ''
                    hold    = '🔴 HOLD' if d.get('blast_hold')  else ''
                    ok_count += 1
                    status = f"{score:5.1f}  {anomaly}{hold}"
                else:
                    err_count += 1
                    status = f"HTTP {r.status_code}"
            except requests.exceptions.ConnectionError:
                print(f'\n  ✗ Cannot connect to {host}')
                print('    Make sure app.py is running: python app.py')
                sys.exit(1)
            except Exception as e:
                err_count += 1
                status = str(e)[:30]

            ts = datetime.now().strftime('%H:%M:%S')
            print(f'  {ts}  {payload["device_id"]:<32} {status}')

        print(f'  ── Cycle {cycle_num} complete | OK: {ok_count} | Err: {err_count}\n')
        time.sleep(interval)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='IISentinel™ Demo Collector')
    p.add_argument('--host',  default='http://localhost:5000', help='IISentinel™ host URL')
    p.add_argument('--speed', default='normal', choices=['fast','normal','slow'])
    p.add_argument('--event', default=None, choices=['cbs','critical','anomaly'],
                   help='Trigger a specific event type on first 3 cycles')
    args = p.parse_args()
    run(args.host, args.speed, args.event)
