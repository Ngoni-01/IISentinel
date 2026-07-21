#!/usr/bin/env python3
"""
IISentinel LAN Probe
=====================
WHY THIS EXISTS
  A cloud-hosted Sentinel (Render/VPS) cannot ping 192.168.x.x / 10.x.x.x —
  private LAN addresses only exist inside your network. Your cmd ping works
  because YOU are on the LAN; the cloud server is not.

  This probe runs ON your LAN (your laptop, a Pi, any always-on box), pings
  your routers/switches locally, and pushes real results up to Sentinel.
  The devices then appear on the dashboard with genuine latency/loss data,
  tagged data_source='lan-ping'.

USAGE
  1. Register a collector once (prints an API key — save it):
       python lan_probe.py --server https://iisentinel.onrender.com --register "office-lan"
  2. Run the probe:
       python lan_probe.py --server https://iisentinel.onrender.com \
                           --key YOUR_KEY \
                           --targets 192.168.1.1,192.168.1.10,192.168.8.1 \
                           --interval 15
  Optional: --names "core-router,switch-a,ap-lounge"  (labels matching targets)
            --type router          (device_type: router|switch|firewall|workstation)

  Windows / Linux / macOS. Only needs:  pip install requests
"""
import argparse, json, os, platform, re, shutil, subprocess, sys, time

try:
    import requests
except ImportError:
    print("pip install requests"); sys.exit(1)

PING = shutil.which('ping')
IS_WIN = platform.system().lower().startswith('win')

def icmp(host, timeout_s=1.0):
    """One real ICMP ping via the OS binary. Returns (ok, latency_ms|None)."""
    if not PING: return False, None
    cmd = ([PING, '-n', '1', '-w', str(int(timeout_s*1000)), host] if IS_WIN
           else [PING, '-c', '1', '-W', str(max(1, int(timeout_s))), host])
    try:
        t0 = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s+0.6)
        if r.returncode == 0:
            m = re.search(r'[Tt]ime[=<]([\d.]+)', r.stdout)
            return True, float(m.group(1)) if m else round((time.time()-t0)*1000, 1)
    except Exception:
        pass
    return False, None

def probe(host):
    """3 pings -> (reachable, avg_latency_ms, loss_pct)."""
    results = [icmp(host) for _ in range(3)]
    ups = [lat for ok, lat in results if ok and lat is not None]
    loss = round((3 - sum(1 for ok, _ in results if ok)) / 3 * 100)
    if not ups:
        return False, None, 100
    return True, round(sum(ups)/len(ups), 1), loss

def sanitize_id(ip):
    return 'net-lan-' + re.sub(r'[^a-zA-Z0-9]', '-', ip)

def build_reading(ip, name, dtype, up, lat, loss):
    """Honest schema: only fields we actually measured, plus required keys."""
    return {
        'device_id':       sanitize_id(ip),
        'device_type':     dtype,
        'metric_name':     'latency_ms',
        'metric_value':    lat if lat is not None else 999,
        'latency_ms':      lat if lat is not None else 999,
        'packet_loss':     loss,
        'signal_strength': 100 - loss if up else 5,   # link quality proxy from loss
        'bandwidth_mbps':  100,                        # nominal; not measured by ping
        'cpu_load':        20,                         # nominal; SNMP upgrade measures real
        'connected_devices': 1,
        'temperature':     35,
        'protocol':        'ICMP/LAN-probe',
        'data_source':     'lan-ping',
        'label':           name or ip,
        'ip':              ip,
    }

def register(server, name):
    r = requests.post(f'{server}/api/collector/register',
                      json={'name': name, 'sector': 'net',
                            'description': f'LAN probe {name} ({platform.node()})'},
                      timeout=10)
    d = r.json()
    if 'api_key' in d:
        print(f"\nRegistered. API key (save it — shown once):\n  {d['api_key']}\n")
        print(f"Run:\n  python lan_probe.py --server {server} --key {d['api_key']} "
              f"--targets 192.168.1.1")
    else:
        print('Registration failed:', d.get('error', r.status_code))

def main():
    ap = argparse.ArgumentParser(description='IISentinel LAN Probe')
    ap.add_argument('--server', required=True)
    ap.add_argument('--key', default=os.environ.get('IIS_COLLECTOR_KEY', ''))
    ap.add_argument('--targets', default='')
    ap.add_argument('--names', default='')
    ap.add_argument('--type', dest='dtype', default='router',
                    choices=['router', 'switch', 'firewall', 'workstation'])
    ap.add_argument('--interval', type=float, default=15.0)
    ap.add_argument('--register', metavar='NAME')
    a = ap.parse_args()

    if a.register:
        return register(a.server, a.register)
    if not a.key:
        print('Need --key (register first with --register "my-lan")'); sys.exit(1)
    targets = [t.strip() for t in a.targets.split(',') if t.strip()]
    if not targets:
        print('Need --targets 192.168.1.1,192.168.1.2'); sys.exit(1)
    names = [n.strip() for n in a.names.split(',')] if a.names else []
    if not PING:
        print('WARNING: no ping binary found on this machine — cannot probe.')

    print(f'LAN Probe -> {a.server}')
    print(f'  Targets:  {", ".join(targets)}   every {a.interval}s   as {a.dtype}\n')

    while True:
        readings, lines = [], []
        for i, ip in enumerate(targets):
            up, lat, loss = probe(ip)
            nm = names[i] if i < len(names) else ip
            readings.append(build_reading(ip, nm, a.dtype, up, lat, loss))
            lines.append(f'{nm:<18} ' + (f'UP  {lat:>6.1f}ms  loss {loss}%' if up else 'DOWN'))
        try:
            r = requests.post(f'{a.server}/api/collector/ingest',
                              headers={'X-Collector-Key': a.key},
                              json={'readings': readings}, timeout=10)
            ok = (r.status_code == 200)
            stamp = time.strftime('%H:%M:%S')
            print(f'[{stamp}] pushed {len(readings)} ' + ('OK' if ok else f'HTTP {r.status_code}'))
            for ln in lines: print('   ', ln)
        except Exception as e:
            print(f'[{time.strftime("%H:%M:%S")}] push failed: {e} (will retry)')
        time.sleep(a.interval)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nStopped.')
