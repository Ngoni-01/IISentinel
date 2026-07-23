"""
Sentinel test suite.

Three groups:
  1. security   — the trust boundaries from SECURITY.md, exercised over HTTP
  2. detection  — the engine's correctness AND its refusal to guess
  3. blast      — the dependency model's honesty (observed/derived/assumed)

Run:  pytest tests/ -q
"""
import json
import os
import signal
import subprocess
import sys
import time
import pathlib

import pytest
import requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://localhost:5001"


# ── server fixture ────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def server(tmp_path_factory):
    db = tmp_path_factory.mktemp("db") / "test.db"
    env = {**os.environ, "DB_PATH": str(db), "PORT": "5001"}
    # capture the first-boot password from stdout
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "from sentinel.storage import db; "
         "from sentinel.api.app import app; "
         "b=db.init_db(); print('PW=' + (b['password'] or ''), flush=True); "
         "app.run(host='0.0.0.0', port=5001, threaded=True)"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    password = None
    t0 = time.time()
    while time.time() - t0 < 30:
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
    else:
        proc.kill()
        pytest.fail("server did not become healthy")

    yield {"password": password}
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


@pytest.fixture(scope="session")
def admin_token(server):
    r = requests.post(BASE + "/api/login",
                      json={"username": "admin", "password": server["password"]})
    assert r.ok, "login with first-boot password should succeed"
    return r.json()["token"]


# ── 1. SECURITY BOUNDARIES ────────────────────────────────────────────

def test_no_default_password(server):
    r = requests.post(BASE + "/api/login",
                      json={"username": "admin", "password": "admin123"})
    assert r.status_code == 401


def test_first_boot_password_works(server):
    r = requests.post(BASE + "/api/login",
                      json={"username": "admin", "password": server["password"]})
    assert r.status_code == 200 and "token" in r.json()


def test_unauthenticated_enrol_rejected(server):
    r = requests.post(BASE + "/api/enrol", json={"name": "attacker"})
    assert r.status_code == 401


def test_bogus_enrol_code_rejected(server):
    r = requests.post(BASE + "/api/enrol",
                      json={"code": "FAKE-FAKE-FAKE", "name": "attacker"})
    assert r.status_code == 401


def test_minting_code_requires_admin(server):
    r = requests.post(BASE + "/api/admin/enrol-code", json={"segment": "x"})
    assert r.status_code == 401


def test_scan_without_key_rejected(server):
    r = requests.post(BASE + "/api/scan", json={"segment": "floor-1"})
    assert r.status_code == 401


def test_findings_require_admin(server):
    assert requests.get(BASE + "/api/findings").status_code == 401


def test_enrol_code_is_single_use(server, admin_token):
    code = requests.post(BASE + "/api/admin/enrol-code",
                         headers={"X-Admin-Token": admin_token},
                         json={"segment": "seg-a"}).json()["code"]
    first = requests.post(BASE + "/api/enrol", json={"code": code, "name": "s1"})
    assert first.status_code == 200
    second = requests.post(BASE + "/api/enrol", json={"code": code, "name": "s2"})
    assert second.status_code == 401


def test_collector_key_is_segment_scoped(server, admin_token):
    code = requests.post(BASE + "/api/admin/enrol-code",
                         headers={"X-Admin-Token": admin_token},
                         json={"segment": "seg-b"}).json()["code"]
    key = requests.post(BASE + "/api/enrol",
                        json={"code": code, "name": "s"}).json()["api_key"]
    # correct segment works
    ok = requests.post(BASE + "/api/scan", headers={"X-Collector-Key": key},
                       json={"segment": "seg-b", "dhcp_servers": []})
    assert ok.status_code == 200
    # a different segment is rejected even with a valid key
    bad = requests.post(BASE + "/api/scan", headers={"X-Collector-Key": key},
                        json={"segment": "seg-c", "dhcp_servers": []})
    assert bad.status_code == 401


def test_request_id_on_every_response(server):
    r = requests.get(BASE + "/health")
    assert len(r.headers.get("X-Request-ID", "")) >= 8


# ── 2. DETECTION ENGINE ───────────────────────────────────────────────

sys.path.insert(0, str(ROOT))
from sentinel.detection import net_intel  # noqa: E402
from sentinel.detection import blast_radius  # noqa: E402


def test_consumer_vs_enterprise_classification():
    assert net_intel.lookup_vendor("50:C7:BF:00:00:01")["category"] == "consumer"
    assert net_intel.lookup_vendor("00:00:0C:00:00:01")["category"] == "enterprise"


def test_engine_refuses_to_guess():
    v = net_intel.lookup_vendor("11:22:33:44:55:66")
    assert v["vendor"] == "Unknown" and v["category"] == "unknown"
    assert net_intel.lookup_vendor("")["vendor"] == "Unknown"


def test_randomised_mac_is_flagged():
    assert net_intel.lookup_vendor("DE:AD:BE:EF:00:01")["locally_administered"] is True


def test_clean_segment_has_no_rogue():
    f = net_intel.analyse({"expected_dhcp": "10.0.0.1",
                           "dhcp_servers": [{"ip": "10.0.0.1", "mac": "00:00:0C:1:2:3"}]})
    assert f["rogue_count"] == 0


def test_rogue_detected_with_reasoning_and_actions():
    f = net_intel.analyse({
        "expected_dhcp": "10.0.0.1",
        "dhcp_servers": [
            {"ip": "10.0.0.1", "mac": "00:00:0C:00:00:01",
             "offer": {"router": "10.0.0.1", "dns": "10.0.0.2"}},
            {"ip": "10.0.0.99", "mac": "50:C7:BF:00:00:01",
             "offer": {"router": "10.0.0.99", "dns": "10.0.0.99"}}]})
    assert f["rogue_count"] == 1
    r = f["rogues"][0]
    assert r["level"] == "critical"
    assert any(d["option"] == "router" for d in r["differences"])
    assert len(r["why"]) >= 3 and len(r["actions"]) >= 3


def test_malformed_scan_never_crashes():
    assert net_intel.analyse({})["rogue_count"] == 0
    assert net_intel.analyse({"dhcp_servers": [{}, {"ip": None}]})["rogue_count"] == 0


# ── 3. BLAST RADIUS HONESTY ───────────────────────────────────────────

def _finding_with_lease(lease):
    return net_intel.analyse({
        "segment": "floor-3", "expected_dhcp": "192.168.3.1",
        "dhcp_servers": [
            {"ip": "192.168.3.1", "mac": "00:00:0C:00:00:01",
             "offer": {"router": "192.168.3.1", "lease": "86400"}},
            {"ip": "192.168.3.57", "mac": "50:C7:BF:AA:BB:CC",
             "offer": {"router": "192.168.3.57", "dns": "192.168.3.57", "lease": str(lease)}}],
        "arp": [{"ip": "192.168.3.40", "gateway": "192.168.3.57"},
                {"ip": "192.168.3.41", "gateway": "192.168.3.57"}],
        "lldp": {"switch": "sw-access-3", "port": "Gi1/0/12"}})


def test_every_node_and_edge_has_a_basis():
    a = blast_radius.analyse(_finding_with_lease(3600))
    for n in a["nodes"]:
        assert n["basis"] in ("observed", "derived", "assumed")
    for e in a["edges"]:
        assert e["basis"] in ("observed", "derived", "assumed")


def test_dhcp_timing_is_derived_from_observed_lease():
    a = blast_radius.analyse(_finding_with_lease(3600))
    scenario = next(s for s in a["scenarios"] if s["id"].startswith("remove"))
    dhcp_event = next(e for e in scenario["timeline"] if e["dependency"] == "dhcp")
    # renewal at half of the 3600s lease = 1800s = 30m, and it must be labelled derived
    assert dhcp_event["at_seconds"] == 1800
    assert dhcp_event["basis"] == "derived"


def test_gateway_loss_is_immediate_and_observed():
    a = blast_radius.analyse(_finding_with_lease(3600))
    scenario = next(s for s in a["scenarios"] if s["id"].startswith("remove"))
    gw_event = next(e for e in scenario["timeline"] if e["dependency"] == "gateway")
    assert gw_event["at_seconds"] == 0 and gw_event["basis"] == "observed"


def test_assumptions_are_surfaced_not_hidden():
    a = blast_radius.analyse(_finding_with_lease(3600))
    # the DNS cache assumption must appear in the surfaced assumptions list
    assert any("cache" in x.lower() for x in a["assumptions"])
    dns_event = next(e for s in a["scenarios"] for e in s["timeline"]
                     if e["dependency"] == "dns")
    assert dns_event["basis"] == "assumed"
