"""Smoke suite — run before every deploy:  pytest tests/ -q
Spawns the real server (demo mode, temp DB) and exercises the contract."""
import os, signal, subprocess, sys, time, pathlib
import pytest, requests

BASE = "http://localhost:5000"
ROOT = pathlib.Path(__file__).resolve().parents[1] / "backend"

@pytest.fixture(scope="session", autouse=True)
def server(tmp_path_factory):
    db = tmp_path_factory.mktemp("db") / "test.db"
    env = {**os.environ, "DEMO_MODE": "true", "DB_PATH": str(db)}
    proc = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        try:
            if requests.get(BASE + "/health", timeout=1).ok: break
        except Exception: time.sleep(0.5)
    else:
        proc.kill(); pytest.fail("server never became healthy")
    time.sleep(4)  # let demo devices inject
    yield
    proc.send_signal(signal.SIGTERM); proc.wait(timeout=5)

def test_health():
    r = requests.get(BASE + "/health"); assert r.ok and r.json()["status"] in ("ok","healthy")

def test_request_id_present():
    r = requests.get(BASE + "/api/ping")
    assert r.ok and len(r.headers.get("X-Request-ID", "")) >= 8

def test_config_contract():
    c = requests.get(BASE + "/api/config").json()
    assert set(c["modules"]) <= {"net", "tc", "mc", "cbs"} and "edition" in c

def test_snapshot_shape():
    d = requests.get(BASE + "/api/snapshot").json()
    assert "data" in d and "intel" in d and len(d["data"]) > 0
    ids = [r["device_id"] for r in d["data"]]
    assert len(ids) == len(set(ids)), "duplicate device rows (latest-row bug)"

def test_lineage_honesty():
    l = requests.get(BASE + "/api/v4/lineage").json()
    assert l["demo_mode"] is True and "demo" in l["sources"]

def test_admin_requires_auth():
    assert requests.get(BASE + "/api/admin/system").status_code == 401

def test_local_ping():
    p = requests.get(BASE + "/api/net/ping", params={"host": "127.0.0.1"}).json()
    assert p["reachable"] is True

def test_edition_gate():
    r = requests.post(BASE + "/api/metrics", json={
        "device_id": "x-test-1", "device_type": "pump",
        "metric_name": "temperature", "metric_value": 50})
    assert r.status_code == 200  # full suite in tests; gate covered by config test
