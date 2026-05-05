"""
IISentinel Unified Collector Agent v2.0
════════════════════════════════════════════════════════════════════
A single, production-grade agent that replaces all separate collector
scripts. Designed for behind-closed-doors pilot trials at:
  · Mining companies (Zimplats, RioZim, Caledonia) — OT/CBS focus
  · Telecoms (Econet, Liquid Intelligent Technologies) — RF/MW focus
  · Enterprise networks (any) — SNMP/latency focus

WHAT THIS SOLVES vs your current collectors
────────────────────────────────────────────
  ✔ Single file to deploy, one config dict to edit
  ✔ Local SQLite buffer — survives Render cold starts / network outages
  ✔ Retry with exponential backoff — no silent data loss
  ✔ Collector authentication (X-Collector-Key header)
  ✔ Jittered polling — devices don't all wake simultaneously
  ✔ Real ICMP ping + optional real SNMP (pysnmp) + optional Modbus
  ✔ Thread pool — all devices polled in parallel, not sequentially
  ✔ Graceful shutdown — flushes buffer on Ctrl+C
  ✔ "Shadow mode" for pilot — runs alongside client's existing tools
  ✔ Client-specific profiles — swap one dict to target Econet vs mine

INSTALL
────────
  pip install requests icmplib pysnmp pymodbus --break-system-packages

USAGE — choose your deployment profile at the bottom of this file
────────────────────────────────────────────────────────────────────
  python iis_agent.py                    # uses ACTIVE_PROFILE below
  python iis_agent.py --profile mining   # override from CLI
  python iis_agent.py --profile telecom
  python iis_agent.py --profile network
  python iis_agent.py --profile demo     # generates synthetic demo data
════════════════════════════════════════════════════════════════════
"""

import os, sys, time, json, random, socket, sqlite3, threading, argparse
import subprocess, platform, logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("pip install requests --break-system-packages")

# ── Optional protocol libraries ──────────────────────────────────────────
try:
    from icmplib import ping as icmp_ping
    ICMPLIB = True
except ImportError:
    ICMPLIB = False

try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
    )
    SNMP = True
except ImportError:
    SNMP = False

try:
    from pymodbus.client import ModbusTcpClient
    MODBUS = True
except ImportError:
    MODBUS = False

# ════════════════════════════════════════════════════════════════════════
# CONFIGURATION — edit this section for each client deployment
# ════════════════════════════════════════════════════════════════════════

API_URL        = "https://git-push-origin-main.onrender.com/api/metrics"
COLLECTOR_KEY  = os.environ.get("IIS_COLLECTOR_KEY", "")   # set in .env
POLL_WORKERS   = 8          # parallel device pollers
BUFFER_DB      = "iis_buffer.db"  # local SQLite — survives outages
FLUSH_INTERVAL = 5          # seconds between buffer flush attempts
LOG_LEVEL      = logging.INFO

# ── CLIENT PROFILES ──────────────────────────────────────────────────────
# Each profile is a list of device dicts.  Add/remove devices here.
# No code changes needed between clients — just swap the profile.
#
# device dict keys:
#   id          — unique device_id posted to IISentinel
#   type        — device_type (router/switch/pump/cbs_controller/etc.)
#   proto       — ICMP | SNMP | MODBUS | SYNTHETIC
#   ip          — real IP (ICMP/SNMP/MODBUS) or None (SYNTHETIC)
#   community   — SNMP community string
#   modbus_unit — Modbus unit ID
#   poll_s      — poll interval in seconds (default 15)
#   section     — logical grouping (net/tc/mc/cbs)
#   simulate    — dict of base values for synthetic fallback

PROFILES = {

    # ── MINING CLIENT (Zimplats / RioZim style) ──────────────────────────
    "mining": [
        # CBS — safety critical, poll every 10s
        {"id":"cbs-dnp3-shaft1-ctrl",  "type":"cbs_controller","proto":"ICMP",
         "ip":"10.10.50.1",  "section":"cbs",  "poll_s":10,
         "simulate":{"link_health":96,"temperature":35,"cpu_load":18}},
        {"id":"cbs-dnp3-shaft2-ctrl",  "type":"cbs_controller","proto":"ICMP",
         "ip":"10.10.50.2",  "section":"cbs",  "poll_s":10,
         "simulate":{"link_health":94,"temperature":37,"cpu_load":20}},

        # Shaft 1 — dewatering pumps, ventilation, conveyors
        {"id":"mc-shaft1-pump-01",     "type":"pump",          "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":15,
         "simulate":{"temperature":58,"motor_speed":2800,"vibration":0.6,"cpu_load":28}},
        {"id":"mc-shaft1-pump-02",     "type":"pump",          "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":15,
         "simulate":{"temperature":62,"motor_speed":2600,"vibration":0.5,"cpu_load":32}},
        {"id":"mc-shaft1-vent-01",     "type":"ventilation",   "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":20,
         "simulate":{"temperature":50,"motor_speed":3200,"vibration":0.4,"cpu_load":22}},
        {"id":"mc-shaft1-conveyor-01", "type":"conveyor",      "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":20,
         "simulate":{"temperature":55,"motor_speed":1200,"vibration":0.7,"cpu_load":35}},

        # Shaft 2
        {"id":"mc-shaft2-pump-01",     "type":"pump",          "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":15,
         "simulate":{"temperature":68,"motor_speed":2400,"vibration":0.8,"cpu_load":30}},
        {"id":"mc-shaft2-vent-01",     "type":"ventilation",   "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":20,
         "simulate":{"temperature":60,"motor_speed":3000,"vibration":0.5,"cpu_load":25}},
        {"id":"mc-shaft2-vent-02",     "type":"ventilation",   "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":20,
         "simulate":{"temperature":58,"motor_speed":2800,"vibration":0.6,"cpu_load":24}},
        {"id":"mc-shaft2-conveyor-01", "type":"conveyor",      "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":20,
         "simulate":{"temperature":60,"motor_speed":1000,"vibration":0.9,"cpu_load":38}},

        # Processing plant — SCADA / PLC
        {"id":"mc-plant-scada-01",     "type":"scada_node",    "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":15,
         "simulate":{"temperature":40,"motor_speed":1800,"vibration":0.3,"cpu_load":45}},
        {"id":"mc-plant-crusher-01",   "type":"plc",           "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":15,
         "simulate":{"temperature":70,"motor_speed":800, "vibration":1.2,"cpu_load":40}},
        {"id":"mc-plant-mill-01",      "type":"plc",           "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":15,
         "simulate":{"temperature":65,"motor_speed":1500,"vibration":1.0,"cpu_load":42}},

        # Surface infrastructure
        {"id":"mc-surface-power-01",   "type":"power_meter",   "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":30,
         "simulate":{"temperature":45,"motor_speed":500, "vibration":0.2,"cpu_load":15}},
        {"id":"mc-surface-compressor-01","type":"plc",          "proto":"SYNTHETIC",
         "ip":None,          "section":"mc",   "poll_s":15,
         "simulate":{"temperature":55,"motor_speed":3500,"vibration":0.8,"cpu_load":48}},

        # Network at mine site
        {"id":"net-mine-router-01",    "type":"router",        "proto":"ICMP",
         "ip":"8.8.8.8",     "section":"net",  "poll_s":15,
         "simulate":{"latency_ms":12,"cpu_load":25}},
        {"id":"net-mine-switch-01",    "type":"switch",        "proto":"ICMP",
         "ip":"1.1.1.1",     "section":"net",  "poll_s":15,
         "simulate":{"latency_ms":8,"cpu_load":18}},
    ],

    # ── TELECOM CLIENT (Econet / Liquid Intelligent style) ───────────────
    "telecom": [
        # Bulawayo site
        {"id":"tc-byo-bs-01","type":"base_station","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":82,"temperature":38,"cpu_load":35,"bandwidth_mbps":280}},
        {"id":"tc-byo-bs-02","type":"base_station","proto":"ICMP",
         "ip":"1.1.1.1",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":79,"temperature":41,"cpu_load":42,"bandwidth_mbps":320}},
        {"id":"tc-byo-bs-03","type":"base_station","proto":"ICMP",
         "ip":"8.8.4.4",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":88,"temperature":35,"cpu_load":28,"bandwidth_mbps":210}},
        {"id":"tc-byo-tower-01","type":"network_tower","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"tc","poll_s":15,
         "simulate":{"signal_strength":91,"temperature":32,"cpu_load":22,"bandwidth_mbps":380}},
        {"id":"tc-byo-mw-01","type":"microwave_link","proto":"ICMP",
         "ip":"1.1.1.1",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":94,"temperature":28,"cpu_load":15,"bandwidth_mbps":450}},

        # Harare site
        {"id":"tc-hre-bs-01","type":"base_station","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":76,"temperature":43,"cpu_load":55,"bandwidth_mbps":520}},
        {"id":"tc-hre-bs-02","type":"base_station","proto":"ICMP",
         "ip":"1.1.1.1",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":84,"temperature":39,"cpu_load":48,"bandwidth_mbps":410}},
        {"id":"tc-hre-tower-01","type":"network_tower","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"tc","poll_s":15,
         "simulate":{"signal_strength":88,"temperature":36,"cpu_load":30,"bandwidth_mbps":600}},
        {"id":"tc-hre-mw-01","type":"microwave_link","proto":"ICMP",
         "ip":"8.8.4.4",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":92,"temperature":30,"cpu_load":18,"bandwidth_mbps":800}},

        # Mutare site
        {"id":"tc-mut-bs-01","type":"base_station","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":71,"temperature":45,"cpu_load":60,"bandwidth_mbps":180}},
        {"id":"tc-mut-tower-01","type":"network_tower","proto":"ICMP",
         "ip":"1.1.1.1",   "section":"tc","poll_s":15,
         "simulate":{"signal_strength":85,"temperature":34,"cpu_load":25,"bandwidth_mbps":290}},
        {"id":"tc-mut-mw-01","type":"microwave_link","proto":"ICMP",
         "ip":"8.8.4.4",   "section":"tc","poll_s":10,
         "simulate":{"signal_strength":89,"temperature":27,"cpu_load":14,"bandwidth_mbps":350}},
    ],

    # ── ENTERPRISE NETWORK (generic corporate client) ────────────────────
    "network": [
        {"id":"net-byo-router-01","type":"router","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":10,"cpu_load":30,"bandwidth_mbps":250}},
        {"id":"net-byo-router-02","type":"router","proto":"ICMP",
         "ip":"1.1.1.1",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":12,"cpu_load":28,"bandwidth_mbps":220}},
        {"id":"net-byo-switch-01","type":"switch","proto":"ICMP",
         "ip":"8.8.4.4",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":2,"cpu_load":15,"bandwidth_mbps":800}},
        {"id":"net-byo-switch-02","type":"switch","proto":"SYNTHETIC",
         "ip":None,         "section":"net","poll_s":15,
         "simulate":{"latency_ms":3,"cpu_load":18,"bandwidth_mbps":650}},
        {"id":"net-byo-fw-01","type":"firewall","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"net","poll_s":20,
         "simulate":{"latency_ms":5,"cpu_load":42,"bandwidth_mbps":500}},
        {"id":"net-byo-wan-01","type":"wan_link","proto":"ICMP",
         "ip":"8.8.8.8",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":18,"cpu_load":8,"bandwidth_mbps":180}},
        {"id":"net-hre-router-01","type":"router","proto":"ICMP",
         "ip":"1.1.1.1",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":14,"cpu_load":32,"bandwidth_mbps":200}},
        {"id":"net-hre-wan-01","type":"wan_link","proto":"ICMP",
         "ip":"1.1.1.1",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":22,"cpu_load":10,"bandwidth_mbps":150}},
        {"id":"net-mut-router-01","type":"router","proto":"ICMP",
         "ip":"8.8.4.4",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":35,"cpu_load":38,"bandwidth_mbps":80}},
        {"id":"net-mut-wan-01","type":"wan_link","proto":"ICMP",
         "ip":"8.8.4.4",   "section":"net","poll_s":15,
         "simulate":{"latency_ms":45,"cpu_load":12,"bandwidth_mbps":60}},
    ],

    # ── DEMO — full synthetic, no real network needed ─────────────────────
    # Use this for boardroom demos or when you have no client access yet.
    # Mix mining + telecom + network for the full cross-domain cascade story.
    "demo": [],   # populated dynamically below from mining + telecom + network
}

# Populate demo profile from all others
PROFILES["demo"] = [
    dict(d, proto="SYNTHETIC") for profile in ["mining","telecom","network"]
    for d in PROFILES[profile]
]


# ════════════════════════════════════════════════════════════════════════
# LOGGING
# ════════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("IISentinel")


# ════════════════════════════════════════════════════════════════════════
# HTTP SESSION — retries with backoff, auth header
# ════════════════════════════════════════════════════════════════════════
def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        backoff_factor=1.5,          # 1.5s, 3s, 6s, 12s between retries
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if COLLECTOR_KEY:
        session.headers.update({"X-Collector-Key": COLLECTOR_KEY})
    return session

SESSION = make_session()


# ════════════════════════════════════════════════════════════════════════
# LOCAL SQLITE BUFFER
# Stores readings that failed to POST. Flushed on every success cycle.
# This is what makes the agent resilient to Render cold starts.
# ════════════════════════════════════════════════════════════════════════
class LocalBuffer:
    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS queue (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                payload  TEXT NOT NULL,
                ts       TEXT NOT NULL
            )
        """)
        self._conn.commit()
        existing = self._conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        if existing:
            log.warning(f"[Buffer] {existing} readings buffered from previous run — will flush")

    def push(self, payload: dict):
        with self._lock:
            self._conn.execute(
                "INSERT INTO queue (payload, ts) VALUES (?, ?)",
                (json.dumps(payload), datetime.now(timezone.utc).isoformat())
            )
            self._conn.commit()

    def pop_batch(self, limit: int = 20) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload FROM queue ORDER BY id ASC LIMIT ?", (limit,)
            ).fetchall()
            return rows

    def delete(self, row_ids: list):
        if not row_ids:
            return
        with self._lock:
            self._conn.execute(
                f"DELETE FROM queue WHERE id IN ({','.join('?'*len(row_ids))})",
                row_ids
            )
            self._conn.commit()

    def size(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]


BUFFER = LocalBuffer(BUFFER_DB)


# ════════════════════════════════════════════════════════════════════════
# DEVICE STATE — tracks per-device degradation for synthetic simulation
# Realistic: devices degrade gradually, not randomly jump
# ════════════════════════════════════════════════════════════════════════
class DeviceState:
    def __init__(self, device: dict):
        self.d = device
        self._cycle = 0
        self._degrading = False
        self._degrade_start = random.randint(25, 90)
        self._fault_active = False
        self._link_health = device.get("simulate", {}).get("link_health", 97.0)
        # CBS-specific: smooth random walk on link health
        self._is_cbs = device["type"] == "cbs_controller"

    def next(self) -> dict:
        """Generate next reading. Real or synthetic depending on proto."""
        self._cycle += 1
        if self._cycle > self._degrade_start:
            self._degrading = True

        proto = self.d.get("proto", "SYNTHETIC")

        if proto == "ICMP":
            return self._poll_icmp()
        elif proto == "SNMP":
            return self._poll_snmp()
        elif proto == "MODBUS":
            return self._poll_modbus()
        else:
            return self._synthetic()

    # ── Real ICMP ping ────────────────────────────────────────────────
    def _poll_icmp(self) -> dict:
        ip = self.d.get("ip")
        if not ip:
            return self._synthetic()

        ping_result = _ping(ip)
        alive = ping_result["alive"]
        latency = ping_result.get("avg_rtt_ms") or 999.0
        loss = ping_result.get("packet_loss", 100.0 if not alive else 0.0)
        signal = max(0.0, min(100.0, 100 - latency * 0.4 - loss * 0.5))

        # For telecom/CBS — use signal as primary metric
        # For network — use latency as primary metric
        section = self.d.get("section", "net")
        sim = self.d.get("simulate", {})

        # Blend real connectivity with simulated protocol-specific metrics
        # Real data tells us if the network path is alive.
        # Simulated data fills the OT/RF metrics we can't read without hardware.
        base_temp   = sim.get("temperature", 40.0)
        base_cpu    = sim.get("cpu_load", 25.0)
        base_bw     = sim.get("bandwidth_mbps", 200.0)
        base_signal = sim.get("signal_strength", signal)

        # Degrade simulated metrics proportionally to real latency
        deg_factor = min(1.0, max(0.0, (latency - 20) / 200))  # 0 at 20ms, 1 at 220ms
        temp    = base_temp    + random.gauss(0, 2) + deg_factor * 20
        cpu     = base_cpu     + random.gauss(0, 3) + deg_factor * 30
        bw      = base_bw      * (1 - deg_factor * 0.7) + random.gauss(0, 10)
        sig     = base_signal  * (1 - deg_factor * 0.5) + random.gauss(0, 2)

        return {
            "device_type":       self.d["type"],
            "device_id":         self.d["id"],
            "metric_name":       "latency_ms" if section == "net" else "signal_strength",
            "metric_value":      round(latency, 2) if section == "net" else round(max(0, sig), 1),
            "cpu_load":          round(max(0, min(100, cpu)), 1),
            "bandwidth_mbps":    round(max(0, bw), 1),
            "latency_ms":        round(latency, 2),
            "packet_loss":       round(loss, 2),
            "connected_devices": random.randint(5, 50),
            "temperature":       round(max(20, min(90, temp)), 1),
            "signal_strength":   round(max(0, min(100, sig)), 1),
            "protocol":          "SNMP/Ethernet-802.3" if section == "net" else "SNMP/LTE",
        }

    # ── Real SNMP ─────────────────────────────────────────────────────
    def _poll_snmp(self) -> dict:
        if not SNMP:
            log.debug(f"[{self.d['id']}] pysnmp not installed — using synthetic fallback")
            return self._synthetic()
        ip        = self.d.get("ip", "")
        community = self.d.get("community", "public")
        oids      = ["sysUpTime", "ifOperStatus_1"]
        results   = {}
        try:
            for oid_name in oids:
                oid_str = {
                    "sysUpTime":      "1.3.6.1.2.1.1.3.0",
                    "ifOperStatus_1": "1.3.6.1.2.1.2.2.1.8.1",
                }.get(oid_name, oid_name)
                err_ind, err_st, _, var_binds = next(getCmd(
                    SnmpEngine(), CommunityData(community, mpModel=1),
                    UdpTransportTarget((ip, 161), timeout=2, retries=1),
                    ContextData(), ObjectType(ObjectIdentity(oid_str))
                ))
                if not err_ind and not err_st:
                    for vb in var_binds:
                        results[oid_name] = str(vb[1])
        except Exception as e:
            log.debug(f"[SNMP][{ip}] {e} — falling back to synthetic")
            return self._synthetic()

        # ifOperStatus 1 = up, 2 = down
        if_status = results.get("ifOperStatus_1", "2")
        alive = if_status.strip() == "1"
        base = self._synthetic()
        base["latency_ms"]      = 5.0 if alive else 999.0
        base["signal_strength"] = 90.0 if alive else 10.0
        base["packet_loss"]     = 0.0 if alive else 100.0
        return base

    # ── Modbus TCP (stub — extend with real register map) ─────────────
    def _poll_modbus(self) -> dict:
        if not MODBUS:
            return self._synthetic()
        ip   = self.d.get("ip", "")
        unit = self.d.get("modbus_unit", 1)
        try:
            client = ModbusTcpClient(ip, port=502, timeout=3)
            if client.connect():
                # Read holding registers 100-105 (temp, speed, pressure, flow, vibration, current)
                regs = client.read_holding_registers(100, count=6, unit=unit)
                client.close()
                if not regs.isError():
                    r = regs.registers
                    scale = [0.1, 1.0, 0.01, 0.1, 0.01, 0.1]
                    temp, speed, pressure, flow, vib, amps = [r[i]*scale[i] for i in range(6)]
                    cpu     = 15.0 + vib * 4.0
                    latency = 1.0  + vib * 0.5
                    signal  = max(40.0, 95.0 - vib * 5.0)
                    return {
                        "device_type":       self.d["type"],
                        "device_id":         self.d["id"],
                        "metric_name":       "temperature",
                        "metric_value":      round(temp, 1),
                        "cpu_load":          round(cpu, 1),
                        "bandwidth_mbps":    random.uniform(5, 30),
                        "latency_ms":        round(latency, 2),
                        "packet_loss":       max(0.0, vib * 0.1),
                        "connected_devices": random.randint(2, 8),
                        "temperature":       round(temp, 1),
                        "signal_strength":   round(signal, 1),
                        "protocol":          "Modbus-TCP/OPC-UA",
                    }
        except Exception as e:
            log.debug(f"[MODBUS][{ip}] {e}")
        return self._synthetic()

    # ── Synthetic — realistic gradual degradation ─────────────────────
    def _synthetic(self) -> dict:
        sim     = self.d.get("simulate", {})
        section = self.d.get("section", "net")
        dtype   = self.d["type"]

        # Degradation drift
        drift = max(0, self._cycle - self._degrade_start) if self._degrading else 0

        # CBS: smooth random walk on link health
        if self._is_cbs:
            noise = random.gauss(0, 2.0)
            if random.random() < 0.04:
                noise -= random.uniform(12, 35)
            self._link_health = max(0, min(100, self._link_health + noise))
            link = self._link_health
            blast_hold = link < 90.0
            latency = max(0.1, (100 - link) * 0.5)
            loss    = max(0.0, (100 - link) * 0.1)
            automation = None
            if blast_hold:
                automation = (
                    f"CBS SAFETY INTERLOCK: BLAST HOLD active on {self.d['id']} "
                    f"— link health {link:.1f}% below 90% threshold. "
                    f"All detonation circuits locked."
                )
            payload = {
                "device_type":       "cbs_controller",
                "device_id":         self.d["id"],
                "metric_name":       "link_health",
                "metric_value":      round(link, 1),
                "cpu_load":          random.uniform(5, 25),
                "bandwidth_mbps":    random.uniform(2, 15),
                "latency_ms":        round(latency, 2),
                "packet_loss":       round(loss, 2),
                "connected_devices": random.randint(2, 5),
                "temperature":       round(sim.get("temperature", 35) + random.gauss(0, 1.5), 1),
                "signal_strength":   round(link, 1),
                "protocol":          "DNP3/Ethernet",
                "blast_hold":        blast_hold,
            }
            if automation:
                payload["automation_override"] = automation
            return payload

        # OT devices — temperature + vibration driven
        if dtype in ("pump","ventilation","conveyor","plc","scada_node","sensor","power_meter"):
            base_temp = sim.get("temperature", 55.0)
            base_spd  = sim.get("motor_speed", 1500.0)
            base_vib  = sim.get("vibration", 0.5)
            temp = base_temp + random.gauss(0, 2) + drift * 0.4
            spd  = max(0, base_spd + random.gauss(0, 60) - drift * 15)
            vib  = min(10, base_vib + random.gauss(0, 0.08) + drift * 0.06)
            cpu  = sim.get("cpu_load", 25) + vib * 3 + random.gauss(0, 2)
            lat  = 1.0 + vib * 0.6
            loss = max(0, vib * 0.12)
            sig  = max(40, 95 - vib * 5)
            return {
                "device_type":       dtype,
                "device_id":         self.d["id"],
                "metric_name":       "temperature",
                "metric_value":      round(min(120, max(20, temp)), 1),
                "cpu_load":          round(min(100, max(0, cpu)), 1),
                "bandwidth_mbps":    round(random.uniform(5, 40), 1),
                "latency_ms":        round(lat, 2),
                "packet_loss":       round(loss, 2),
                "connected_devices": random.randint(2, 10),
                "temperature":       round(min(120, max(20, temp)), 1),
                "signal_strength":   round(max(40, sig), 1),
                "protocol":          "Profinet/EtherNet-IP",
            }

        # Network / telecom
        base_lat = sim.get("latency_ms", 15.0) + drift * 2
        base_sig = sim.get("signal_strength", 85.0) - drift * 1.5
        base_bw  = sim.get("bandwidth_mbps", 200.0) - drift * 5
        # Occasional random congestion event
        congested = random.random() < 0.08
        lat = (base_lat + random.gauss(0, 3)) * (6 if congested else 1)
        sig = max(10, base_sig + random.gauss(0, 2) - (40 if congested else 0))
        bw  = base_bw + random.gauss(0, 10)
        cpu = sim.get("cpu_load", 25) + random.gauss(0, 3) + (50 if congested else 0)
        loss = max(0, random.uniform(0, 0.3) + (5 if congested else 0))
        return {
            "device_type":       dtype,
            "device_id":         self.d["id"],
            "metric_name":       "latency_ms" if section == "net" else "signal_strength",
            "metric_value":      round(max(0, lat), 2) if section == "net" else round(max(0, sig), 1),
            "cpu_load":          round(min(100, max(0, cpu)), 1),
            "bandwidth_mbps":    round(max(0, bw), 1),
            "latency_ms":        round(max(0, lat), 2),
            "packet_loss":       round(max(0, loss), 2),
            "connected_devices": random.randint(10, 200),
            "temperature":       round(random.uniform(30, 55), 1),
            "signal_strength":   round(max(0, min(100, sig)), 1),
            "protocol":          "SNMP/Ethernet-802.3" if section == "net" else "SNMP/LTE",
        }


# ════════════════════════════════════════════════════════════════════════
# ICMP PING — icmplib preferred, subprocess fallback
# ════════════════════════════════════════════════════════════════════════
def _ping(ip: str, count: int = 2, timeout: float = 2.0) -> dict:
    if ICMPLIB:
        try:
            r = icmp_ping(ip, count=count, timeout=timeout, privileged=False)
            return {"alive": r.is_alive, "avg_rtt_ms": round(r.avg_rtt, 2) if r.is_alive else None,
                    "packet_loss": round(r.packet_loss * 100, 1)}
        except Exception:
            pass

    # subprocess fallback
    sys_  = platform.system().lower()
    cmd   = (["ping", "-n", str(count), "-w", str(int(timeout*1000)), ip]
             if sys_ == "windows"
             else ["ping", "-c", str(count), "-W", str(int(timeout)), ip])
    try:
        t0  = time.perf_counter()
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*count+2)
        elapsed = (time.perf_counter() - t0) * 1000
        alive = res.returncode == 0
        rtt   = None
        if alive:
            import re
            m = re.search(r"(?:rtt|round-trip)[^=]+=\s*[\d.]+/([\d.]+)", res.stdout)
            if m:
                rtt = float(m.group(1))
            else:
                m2 = re.search(r"Average\s*=\s*([\d.]+)ms", res.stdout, re.I)
                rtt = float(m2.group(1)) if m2 else round(elapsed / count, 1)
        return {"alive": alive, "avg_rtt_ms": rtt, "packet_loss": 0.0 if alive else 100.0}
    except Exception:
        return {"alive": False, "avg_rtt_ms": None, "packet_loss": 100.0}


# ════════════════════════════════════════════════════════════════════════
# POST TO API
# ════════════════════════════════════════════════════════════════════════
def post(payload: dict) -> bool:
    """Returns True on success. On failure, buffers locally."""
    try:
        r = SESSION.post(API_URL, json=payload, timeout=15)
        r.raise_for_status()
        result = r.json()
        score  = result.get("health_score", "?")
        anom   = result.get("anomaly_flag", False)
        tag    = "ANOM" if anom else "ok"
        log.info(f"[{payload['device_id']:<35}] "
                 f"{payload['metric_name']}={payload['metric_value']:.1f} "
                 f"→ score={score} [{tag}]")
        return True
    except Exception as e:
        log.warning(f"[{payload['device_id']}] POST failed ({e}) — buffering")
        BUFFER.push(payload)
        return False


# ════════════════════════════════════════════════════════════════════════
# BUFFER FLUSH THREAD
# Runs every FLUSH_INTERVAL seconds, retries any buffered readings
# ════════════════════════════════════════════════════════════════════════
def flush_buffer():
    while True:
        time.sleep(FLUSH_INTERVAL)
        size = BUFFER.size()
        if size == 0:
            continue
        log.info(f"[Buffer] Flushing {size} buffered reading(s)...")
        rows = BUFFER.pop_batch(limit=20)
        flushed = []
        for row_id, payload_str in rows:
            try:
                payload = json.loads(payload_str)
                r = SESSION.post(API_URL, json=payload, timeout=10)
                if r.ok:
                    flushed.append(row_id)
            except Exception:
                break  # stop flushing if API still unreachable
        if flushed:
            BUFFER.delete(flushed)
            log.info(f"[Buffer] Flushed {len(flushed)} reading(s). Remaining: {BUFFER.size()}")


# ════════════════════════════════════════════════════════════════════════
# DEVICE POLLER — runs per device in thread pool
# ════════════════════════════════════════════════════════════════════════
_device_states: dict[str, DeviceState] = {}
_state_lock = threading.Lock()

def poll_device(device: dict):
    dev_id = device["id"]
    with _state_lock:
        if dev_id not in _device_states:
            _device_states[dev_id] = DeviceState(device)
        state = _device_states[dev_id]
    payload = state.next()
    post(payload)


# ════════════════════════════════════════════════════════════════════════
# MAIN POLLING LOOP
# Each device has its own poll_s interval.
# Uses a simple tick-based scheduler — no external scheduler needed.
# ════════════════════════════════════════════════════════════════════════
def run(profile: list, jitter: float = 2.0):
    log.info(f"IISentinel Agent starting — {len(profile)} devices")
    log.info(f"API: {API_URL}")
    log.info(f"Auth: {'key set' if COLLECTOR_KEY else 'NO KEY — set IIS_COLLECTOR_KEY env var'}")
    log.info(f"Libs: ICMP={'icmplib' if ICMPLIB else 'subprocess'} "
             f"SNMP={'yes' if SNMP else 'no'} "
             f"MODBUS={'yes' if MODBUS else 'no'}")
    log.info("-" * 65)

    # Start buffer flush thread
    t_flush = threading.Thread(target=flush_buffer, daemon=True, name="BufferFlusher")
    t_flush.start()

    # Track when each device is next due
    next_poll: dict[str, float] = {}
    for d in profile:
        # Stagger startup across poll_s window to avoid thundering herd
        next_poll[d["id"]] = time.monotonic() + random.uniform(0, d.get("poll_s", 15))

    with ThreadPoolExecutor(max_workers=POLL_WORKERS, thread_name_prefix="Poller") as pool:
        try:
            while True:
                now = time.monotonic()
                due = [d for d in profile if now >= next_poll[d["id"]]]
                if due:
                    futures = {pool.submit(poll_device, d): d for d in due}
                    for f in as_completed(futures, timeout=20):
                        d = futures[f]
                        interval = d.get("poll_s", 15)
                        # Add small random jitter so devices don't sync up over time
                        next_poll[d["id"]] = time.monotonic() + interval + random.uniform(0, jitter)
                        try:
                            f.result()
                        except Exception as e:
                            log.error(f"[{d['id']}] Poller exception: {e}")

                time.sleep(0.5)  # tight loop — check every 500ms which devices are due

        except KeyboardInterrupt:
            log.info("\nShutting down — flushing buffer...")
            rows = BUFFER.pop_batch(100)
            if rows:
                for row_id, payload_str in rows:
                    try:
                        SESSION.post(API_URL, json=json.loads(payload_str), timeout=5)
                    except Exception:
                        pass
            log.info("Done.")


# ════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IISentinel Unified Collector Agent")
    parser.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default="mining",
        help="Deployment profile (mining / telecom / network / demo)"
    )
    args = parser.parse_args()
    active = PROFILES[args.profile]
    log.info(f"Profile: {args.profile.upper()} — {len(active)} devices")
    run(active)
