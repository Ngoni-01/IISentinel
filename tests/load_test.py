"""
Load test — establishes the REAL device ceiling, not a guess.

The workload a network-integrity monitor actually sees: N segment sensors
each POSTing a scan on an interval. This drives the write path
(net_intel.analyse -> db.record_finding) which is where SQLite/WAL
serialisation would bite first.

We ramp concurrent sensors, hold each for a burst of scans, and record the
p50/p95/p99 latency of the finding-write path. The ceiling is defined as the
sensor count at which p95 crosses 50 ms.

Run:  python3 tests/load_test.py
"""
import concurrent.futures as cf
import os
import signal
import statistics
import subprocess
import sys
import time
import pathlib

import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://localhost:5002"


def start_server(db_path):
    env = {**os.environ, "DB_PATH": db_path, "PORT": "5002", "ENROL_LIMIT": "500", "SCAN_LIMIT": "100000"}
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "from sentinel.storage import db; from sentinel.api.app import app; "
         "b=db.init_db(); print('PW='+(b['password'] or ''), flush=True); "
         "app.run(host='0.0.0.0', port=5002, threaded=True)"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    password = None
    while True:
        line = proc.stdout.readline()
        if line.startswith("PW="):
            password = line[3:].strip()
            break
    for _ in range(40):
        try:
            if requests.get(BASE + "/health", timeout=1).ok:
                break
        except Exception:
            time.sleep(0.3)
    return proc, password


def enrol_sensor(admin_token, segment):
    code = requests.post(BASE + "/api/admin/enrol-code",
                         headers={"X-Admin-Token": admin_token},
                         json={"segment": segment}).json()["code"]
    return requests.post(BASE + "/api/enrol",
                         json={"code": code, "name": segment}).json()["api_key"]


def scan_payload(segment, seq):
    """A realistic scan: one sanctioned server, one rogue, a few ARP hosts."""
    return {
        "segment": segment,
        "expected_dhcp": "192.168.0.1",
        "dhcp_servers": [
            {"ip": "192.168.0.1", "mac": "00:00:0C:00:00:01",
             "offer": {"router": "192.168.0.1", "dns": "192.168.0.2", "lease": "86400"}},
            {"ip": f"192.168.0.{50 + (seq % 40)}", "mac": "50:C7:BF:AA:BB:CC",
             "offer": {"router": "192.168.0.99", "dns": "192.168.0.99", "lease": "3600"}},
        ],
        "arp": [{"ip": f"192.168.0.{10 + i}", "gateway": "192.168.0.99"} for i in range(4)],
        "lldp": {"switch": "sw-load", "port": "Gi1/0/1"},
    }


def run_wave(keys, scans_per_sensor):
    """Fire scans_per_sensor from each sensor concurrently; return latencies (ms)."""
    latencies = []

    def one(seg_key):
        seg, key = seg_key
        out = []
        for i in range(scans_per_sensor):
            t0 = time.time()
            r = requests.post(BASE + "/api/scan",
                              headers={"X-Collector-Key": key},
                              json=scan_payload(seg, i), timeout=30)
            out.append((time.time() - t0) * 1000.0)
            if r.status_code != 200:
                out[-1] = float("nan")
        return out

    with cf.ThreadPoolExecutor(max_workers=len(keys)) as ex:
        for res in ex.map(one, keys):
            latencies.extend(x for x in res if x == x)  # drop NaN
    return latencies


def main():
    import tempfile
    db_path = os.path.join(tempfile.mkdtemp(), "load.db")
    proc, password = start_server(db_path)
    try:
        token = requests.post(BASE + "/api/login",
                              json={"username": "admin", "password": password}).json()["token"]

        print(f"{'sensors':>8}  {'scans':>6}  {'p50':>7}  {'p95':>7}  {'p99':>7}")
        print("-" * 44)
        ceiling = None
        for n in (5, 10, 25, 50, 100, 200):
            keys = [(f"seg-{i}", enrol_sensor(token, f"seg-{i}")) for i in range(n)]
            lat = run_wave(keys, scans_per_sensor=5)
            if not lat:
                print(f"{n:>8}  (all failed)")
                break
            lat.sort()
            p50 = statistics.median(lat)
            p95 = lat[int(len(lat) * 0.95) - 1]
            p99 = lat[int(len(lat) * 0.99) - 1]
            print(f"{n:>8}  {len(lat):>6}  {p50:>6.1f}m  {p95:>6.1f}m  {p99:>6.1f}m")
            if p95 > 50 and ceiling is None:
                ceiling = n

        print("-" * 44)
        if ceiling:
            print(f"Ceiling (p95 > 50ms): between the prior tier and {ceiling} concurrent sensors.")
        else:
            print("p95 stayed under 50ms across all tiers tested (up to 200 concurrent sensors).")
        print("Note: sensors report periodically, not continuously; 200 concurrent")
        print("reporting sensors corresponds to a far larger fleet at realistic intervals.")
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    main()
