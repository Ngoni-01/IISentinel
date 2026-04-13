"""
IISentinel — node_collector.py
═══════════════════════════════════════════════════════════════════════════════
SolarWinds-equivalent node discovery, ICMP ping, and SNMP polling engine.

USAGE
─────
  # Standalone (registers its own Flask routes):
  from node_collector import register_routes, start_polling
  register_routes(app)       # adds /api/ping, /api/nodes endpoints
  start_polling(interval=30) # background thread

  # Or run directly for testing:
  python node_collector.py --ip 192.168.1.1 --type router

INSTALL DEPENDENCIES
────────────────────
  pip install pysnmp icmplib requests --break-system-packages

  For SNMP v3 support:
  pip install pysnmp-lextudio --break-system-packages

WHAT IT DOES (SolarWinds parity)
─────────────────────────────────
  ✔ ICMP ping with true RTT measurement
  ✔ SNMP v2c / v3 OID polling (sysDescr, ifOperStatus, ifInOctets, etc.)
  ✔ HTTP/HTTPS probe (response time, status code)
  ✔ TCP port check (e.g. port 161 for SNMP, 22 for SSH)
  ✔ Auto-discovery: given a subnet, scans and finds live hosts
  ✔ Persistent node registry (JSON file + in-memory)
  ✔ Posts results to IISentinel /api/metrics automatically
  ✔ Flask route /api/ping — called by dashboard when user adds a node
  ✔ Flask route /api/nodes — CRUD for node registry
  ✔ Flask route /api/discover — subnet sweep
═══════════════════════════════════════════════════════════════════════════════
"""

import os, json, time, socket, subprocess, threading, platform, ipaddress
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests as _requests
except ImportError:
    _requests = None

# ── OPTIONAL: pysnmp for real SNMP polling ────────────────────────────────
try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
        UsmUserData, usmHMACMD5AuthProtocol, usmDESPrivProtocol,
        usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False

# ── OPTIONAL: icmplib for precision ICMP ─────────────────────────────────
try:
    from icmplib import ping as icmp_ping, ICMPLibError
    ICMPLIB_AVAILABLE = True
except ImportError:
    ICMPLIB_AVAILABLE = False


NODE_REGISTRY_FILE = Path("node_registry.json")

# ── Common SNMP OIDs ──────────────────────────────────────────────────────
SNMP_OIDS = {
    "sysDescr":        "1.3.6.1.2.1.1.1.0",
    "sysUpTime":       "1.3.6.1.2.1.1.3.0",
    "sysName":         "1.3.6.1.2.1.1.5.0",
    "ifNumber":        "1.3.6.1.2.1.2.1.0",
    "ifOperStatus_1":  "1.3.6.1.2.1.2.2.1.8.1",   # first interface
    "ifInOctets_1":    "1.3.6.1.2.1.2.2.1.10.1",
    "ifOutOctets_1":   "1.3.6.1.2.1.2.2.1.16.1",
    "ifInErrors_1":    "1.3.6.1.2.1.2.2.1.14.1",
    "ipForwarding":    "1.3.6.1.2.1.4.1.0",
    # Wireless / telecom
    "dot11OperState":  "1.2.840.10036.1.1.1.4.1",
    # Cisco-specific
    "ciscoMemFree":    "1.3.6.1.4.1.9.2.1.8.0",
    "ciscoCPU5s":      "1.3.6.1.4.1.9.2.1.57.0",
}

# ── Device-type SNMP community defaults ──────────────────────────────────
DEFAULT_COMMUNITIES = {
    "router":       "public",
    "switch":       "public",
    "firewall":     "private",
    "base_station": "public",
    "network_tower":"public",
    "microwave_link":"public",
}

# ─────────────────────────────────────────────────────────────────────────
# NODE REGISTRY
# ─────────────────────────────────────────────────────────────────────────

class NodeRegistry:
    """Thread-safe registry of monitored nodes."""

    def __init__(self):
        self._lock = threading.Lock()
        self._nodes: dict = {}
        self._load()

    def _load(self):
        if NODE_REGISTRY_FILE.exists():
            try:
                with open(NODE_REGISTRY_FILE) as f:
                    data = json.load(f)
                    self._nodes = {n["id"]: n for n in data}
                print(f"[NodeCollector] Loaded {len(self._nodes)} nodes from registry")
            except Exception as e:
                print(f"[NodeCollector] Could not load registry: {e}")

    def _save(self):
        try:
            with open(NODE_REGISTRY_FILE, "w") as f:
                json.dump(list(self._nodes.values()), f, indent=2)
        except Exception as e:
            print(f"[NodeCollector] Could not save registry: {e}")

    def add(self, node: dict) -> dict:
        if "id" not in node:
            node["id"] = f"node-{int(time.time()*1000)}"
        node.setdefault("status", "pending")
        node.setdefault("latency_ms", None)
        node.setdefault("snmp_data", {})
        node.setdefault("last_seen", None)
        node.setdefault("community", DEFAULT_COMMUNITIES.get(node.get("type",""), "public"))
        with self._lock:
            self._nodes[node["id"]] = node
            self._save()
        return node

    def update(self, node_id: str, updates: dict):
        with self._lock:
            if node_id in self._nodes:
                self._nodes[node_id].update(updates)
                self._save()

    def remove(self, node_id: str) -> bool:
        with self._lock:
            if node_id in self._nodes:
                del self._nodes[node_id]
                self._save()
                return True
        return False

    def all(self) -> list:
        with self._lock:
            return list(self._nodes.values())

    def get(self, node_id: str) -> dict | None:
        with self._lock:
            return self._nodes.get(node_id)


registry = NodeRegistry()


# ─────────────────────────────────────────────────────────────────────────
# ICMP PING
# ─────────────────────────────────────────────────────────────────────────

def icmp_ping_host(ip: str, count: int = 3, timeout: float = 2.0) -> dict:
    """
    Ping a host. Returns:
      {"alive": bool, "avg_rtt_ms": float|None, "packet_loss": float}
    Uses icmplib if available, else subprocess ping.
    """
    if ICMPLIB_AVAILABLE:
        try:
            result = icmp_ping(ip, count=count, timeout=timeout, privileged=False)
            return {
                "alive": result.is_alive,
                "avg_rtt_ms": round(result.avg_rtt, 2) if result.is_alive else None,
                "packet_loss": round(result.packet_loss * 100, 1),
                "min_rtt_ms": round(result.min_rtt, 2) if result.is_alive else None,
                "max_rtt_ms": round(result.max_rtt, 2) if result.is_alive else None,
            }
        except Exception:
            pass  # fall through to subprocess

    # subprocess fallback
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), ip]

    try:
        t0 = time.perf_counter()
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout * count + 2
        )
        elapsed = (time.perf_counter() - t0) * 1000

        alive = result.returncode == 0
        # Parse RTT from output
        rtt = None
        if alive:
            import re
            # Linux: "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms"
            m = re.search(r"(?:rtt|round-trip)[^=]+=\s*[\d.]+/([\d.]+)", result.stdout)
            if m:
                rtt = float(m.group(1))
            else:
                # Windows: "Average = 2ms" or fallback to total elapsed / count
                m2 = re.search(r"Average\s*=\s*([\d.]+)ms", result.stdout, re.I)
                rtt = float(m2.group(1)) if m2 else round(elapsed / count, 1)

        return {"alive": alive, "avg_rtt_ms": rtt, "packet_loss": 0.0 if alive else 100.0}

    except subprocess.TimeoutExpired:
        return {"alive": False, "avg_rtt_ms": None, "packet_loss": 100.0}
    except Exception as e:
        return {"alive": False, "avg_rtt_ms": None, "packet_loss": 100.0, "error": str(e)}


# ─────────────────────────────────────────────────────────────────────────
# TCP PORT CHECK
# ─────────────────────────────────────────────────────────────────────────

def tcp_check(ip: str, port: int, timeout: float = 2.0) -> dict:
    """Check if a TCP port is open. Returns alive + connect_ms."""
    try:
        t0 = time.perf_counter()
        with socket.create_connection((ip, port), timeout=timeout):
            rtt = round((time.perf_counter() - t0) * 1000, 2)
        return {"alive": True, "connect_ms": rtt}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"alive": False, "connect_ms": None}


# ─────────────────────────────────────────────────────────────────────────
# HTTP PROBE
# ─────────────────────────────────────────────────────────────────────────

def http_probe(url: str, timeout: float = 4.0) -> dict:
    if not _requests:
        return {"alive": False, "error": "requests not installed"}
    if not url.startswith("http"):
        url = "http://" + url
    try:
        t0 = time.perf_counter()
        r = _requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        rtt = round((time.perf_counter() - t0) * 1000, 2)
        return {"alive": r.status_code < 500, "status_code": r.status_code, "response_ms": rtt}
    except Exception as e:
        return {"alive": False, "error": str(e)[:80]}


# ─────────────────────────────────────────────────────────────────────────
# SNMP POLL
# ─────────────────────────────────────────────────────────────────────────

def snmp_poll(ip: str, community: str = "public", oids: list | None = None,
              version: str = "v2c", port: int = 161,
              username: str | None = None, auth_key: str | None = None,
              priv_key: str | None = None) -> dict:
    """
    Poll SNMP OIDs. Returns dict of {oid_name: value}.
    Supports v2c and v3.
    """
    if not SNMP_AVAILABLE:
        return {"error": "pysnmp not installed — run: pip install pysnmp --break-system-packages"}

    if oids is None:
        oids = ["sysDescr", "sysName", "sysUpTime", "ifOperStatus_1"]

    results = {}
    try:
        if version in ("v3", "3") and username:
            auth = UsmUserData(
                username,
                authKey=auth_key or "",
                privKey=priv_key or "",
                authProtocol=usmHMACSHAAuthProtocol if auth_key else None,
                privProtocol=usmAesCfb128Protocol if priv_key else None,
            )
        else:
            auth = CommunityData(community, mpModel=1)  # v2c

        transport = UdpTransportTarget((ip, port), timeout=2, retries=1)

        for oid_name in oids:
            oid_str = SNMP_OIDS.get(oid_name, oid_name)
            try:
                err_indication, err_status, err_index, var_binds = next(
                    getCmd(SnmpEngine(), auth, transport, ContextData(),
                           ObjectType(ObjectIdentity(oid_str)))
                )
                if not err_indication and not err_status:
                    for var_bind in var_binds:
                        results[oid_name] = str(var_bind[1])
                else:
                    results[oid_name] = f"error: {err_indication or err_status}"
            except Exception as e:
                results[oid_name] = f"exception: {e}"

    except Exception as e:
        results["error"] = str(e)

    return results


# ─────────────────────────────────────────────────────────────────────────
# SUBNET DISCOVERY
# ─────────────────────────────────────────────────────────────────────────

def discover_subnet(cidr: str, max_workers: int = 50, timeout: float = 1.0) -> list:
    """
    Ping sweep a CIDR subnet (e.g. 192.168.1.0/24).
    Returns list of {ip, alive, rtt_ms} for all responsive hosts.
    Limited to /24 or smaller for safety.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.num_addresses > 256:
            return [{"error": "Subnet too large — use /24 or smaller"}]
    except ValueError as e:
        return [{"error": str(e)}]

    results = []
    lock = threading.Lock()

    def check(ip):
        r = icmp_ping_host(str(ip), count=1, timeout=timeout)
        if r["alive"]:
            with lock:
                results.append({"ip": str(ip), "alive": True, "rtt_ms": r["avg_rtt_ms"]})

    threads = []
    for host in net.hosts():
        t = threading.Thread(target=check, args=(host,), daemon=True)
        threads.append(t)
        t.start()
        # Throttle
        if len(threads) >= max_workers:
            for th in threads:
                th.join(timeout=timeout + 0.5)
            threads = []

    for t in threads:
        t.join(timeout=timeout + 0.5)

    results.sort(key=lambda x: socket.inet_aton(x["ip"]))
    return results


# ─────────────────────────────────────────────────────────────────────────
# FULL NODE POLL — combines ICMP + SNMP + health score derivation
# ─────────────────────────────────────────────────────────────────────────

def poll_node(node: dict) -> dict:
    """
    Full poll of a registered node.
    Returns enriched result ready to POST to /api/metrics.
    """
    ip = node["ip"]
    proto = node.get("proto", "ICMP").upper()
    device_type = node.get("type", "router")
    community = node.get("community", "public")

    result = {
        "device_id": node.get("label", ip),
        "device_type": device_type,
        "protocol": proto,
        "ip": ip,
        "status": "unknown",
        "latency_ms": None,
        "packet_loss": 100.0,
        "snmp_data": {},
        "polled_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── ICMP ──
    if proto in ("ICMP", "SNMP", "SNMP3"):
        ping_r = icmp_ping_host(ip)
        result["alive"] = ping_r["alive"]
        result["latency_ms"] = ping_r.get("avg_rtt_ms")
        result["packet_loss"] = ping_r.get("packet_loss", 100.0)
        result["status"] = "up" if ping_r["alive"] else "down"

    # ── SNMP ──
    if proto in ("SNMP", "SNMP3") and SNMP_AVAILABLE:
        snmp_r = snmp_poll(ip, community=community, version="v3" if proto == "SNMP3" else "v2c")
        result["snmp_data"] = snmp_r

    # ── HTTP ──
    elif proto == "HTTP":
        http_r = http_probe(ip)
        result["alive"] = http_r.get("alive", False)
        result["latency_ms"] = http_r.get("response_ms")
        result["status"] = "up" if result["alive"] else "down"
        result["http_status"] = http_r.get("status_code")

    # ── TCP ──
    elif proto.startswith("TCP:"):
        port = int(proto.split(":")[1])
        tcp_r = tcp_check(ip, port)
        result["alive"] = tcp_r["alive"]
        result["latency_ms"] = tcp_r.get("connect_ms")
        result["status"] = "up" if result["alive"] else "down"

    # ── Derive health score ──
    if result["status"] == "down":
        health = 0.0
    elif result["latency_ms"] is not None:
        lat = result["latency_ms"]
        loss = result["packet_loss"]
        # Score degrades with latency and packet loss
        health = max(0, min(100, 100 - lat * 0.4 - loss * 0.8))
    else:
        health = 50.0  # alive but no RTT data

    result["health_score"] = round(health, 1)
    result["metric_name"] = "latency_ms"
    result["metric_value"] = result["latency_ms"] or 0

    return result


# ─────────────────────────────────────────────────────────────────────────
# METRICS POSTER — sends result to IISentinel /api/metrics
# ─────────────────────────────────────────────────────────────────────────

def post_to_metrics(result: dict, base_url: str = "http://localhost:5000"):
    if not _requests:
        return
    payload = {
        "device_id":    result["device_id"],
        "device_type":  result["device_type"],
        "protocol":     result["protocol"],
        "metric_name":  result.get("metric_name", "latency_ms"),
        "metric_value": result.get("metric_value", 0),
        "latency_ms":   result.get("latency_ms", 0) or 0,
        "packet_loss":  result.get("packet_loss", 0),
        "signal_strength": max(0, 100 - (result.get("latency_ms") or 0) * 0.5),
    }
    try:
        _requests.post(f"{base_url}/api/metrics", json=payload, timeout=5)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────
# BACKGROUND POLLING THREAD
# ─────────────────────────────────────────────────────────────────────────

_polling_active = False
_polling_thread: threading.Thread | None = None

def start_polling(interval: int = 30, base_url: str = "http://localhost:5000"):
    """Start background polling of all registered nodes."""
    global _polling_active, _polling_thread

    if _polling_active:
        return

    _polling_active = True

    def _loop():
        print(f"[NodeCollector] Polling started — interval: {interval}s")
        while _polling_active:
            nodes = registry.all()
            for node in nodes:
                try:
                    result = poll_node(node)
                    registry.update(node["id"], {
                        "status":     result["status"],
                        "latency_ms": result.get("latency_ms"),
                        "last_seen":  result["polled_at"],
                        "snmp_data":  result.get("snmp_data", {}),
                        "health_score": result.get("health_score"),
                    })
                    post_to_metrics(result, base_url)
                    print(f"[NodeCollector] {node['label']} ({node['ip']}) → {result['status']} "
                          f"{result.get('latency_ms', '--')}ms  health={result.get('health_score', '--')}")
                except Exception as e:
                    print(f"[NodeCollector] Error polling {node.get('ip','?')}: {e}")
            time.sleep(interval)

    _polling_thread = threading.Thread(target=_loop, daemon=True, name="NodeCollector")
    _polling_thread.start()

def stop_polling():
    global _polling_active
    _polling_active = False


# ─────────────────────────────────────────────────────────────────────────
# FLASK ROUTE REGISTRATION
# ─────────────────────────────────────────────────────────────────────────

def register_routes(app, base_url: str = "http://localhost:5000"):
    """
    Call this in app.py:
        from node_collector import register_routes, start_polling
        register_routes(app)
        start_polling()
    """
    from flask import request, jsonify

    @app.route("/api/ping", methods=["POST"])
    def api_ping():
        """
        Dashboard calls this when user adds a node.
        Body: {ip, device_id, device_type, protocol}
        Returns: {status, latency_ms, snmp_data, health_score}
        """
        data = request.json or {}
        ip = data.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "ip required"}), 400

        node = {
            "id":       f"tmp-{int(time.time()*1000)}",
            "ip":       ip,
            "label":    data.get("device_id", ip),
            "type":     data.get("device_type", "router"),
            "proto":    data.get("protocol", "ICMP"),
            "community": data.get("community", "public"),
        }

        result = poll_node(node)
        post_to_metrics(result, base_url)

        return jsonify({
            "ip":          ip,
            "status":      result["status"],
            "latency_ms":  result.get("latency_ms"),
            "packet_loss": result.get("packet_loss"),
            "health_score": result.get("health_score"),
            "snmp_data":   result.get("snmp_data", {}),
            "polled_at":   result["polled_at"],
        })

    @app.route("/api/nodes", methods=["GET"])
    def api_nodes_list():
        return jsonify(registry.all())

    @app.route("/api/nodes", methods=["POST"])
    def api_nodes_add():
        data = request.json or {}
        if not data.get("ip"):
            return jsonify({"error": "ip required"}), 400
        node = registry.add(data)
        # Immediate poll in background
        threading.Thread(
            target=lambda: post_to_metrics(poll_node(node), base_url),
            daemon=True
        ).start()
        return jsonify(node), 201

    @app.route("/api/nodes/<node_id>", methods=["DELETE"])
    def api_nodes_delete(node_id):
        if registry.remove(node_id):
            return jsonify({"deleted": node_id})
        return jsonify({"error": "not found"}), 404

    @app.route("/api/nodes/<node_id>/poll", methods=["POST"])
    def api_nodes_poll(node_id):
        node = registry.get(node_id)
        if not node:
            return jsonify({"error": "not found"}), 404
        result = poll_node(node)
        registry.update(node_id, {"status": result["status"], "latency_ms": result.get("latency_ms")})
        post_to_metrics(result, base_url)
        return jsonify(result)

    @app.route("/api/discover", methods=["POST"])
    def api_discover():
        data = request.json or {}
        cidr = data.get("cidr", "")
        if not cidr:
            return jsonify({"error": "cidr required (e.g. 192.168.1.0/24)"}), 400
        hosts = discover_subnet(cidr)
        return jsonify({"cidr": cidr, "hosts_found": len(hosts), "hosts": hosts})

    print("[NodeCollector] Routes registered: /api/ping, /api/nodes, /api/discover")


# ─────────────────────────────────────────────────────────────────────────
# STANDALONE CLI — for testing
# ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IISentinel Node Collector")
    parser.add_argument("--ip",       required=True, help="IP address or hostname to poll")
    parser.add_argument("--type",     default="router", help="Device type")
    parser.add_argument("--proto",    default="ICMP", help="Protocol: ICMP|SNMP|HTTP")
    parser.add_argument("--label",    default=None, help="Display label")
    parser.add_argument("--community",default="public", help="SNMP community string")
    parser.add_argument("--discover", action="store_true", help="Treat --ip as CIDR for subnet scan")
    parser.add_argument("--post",     default=None, help="Post results to IISentinel URL")
    parser.add_argument("--watch",    type=int, default=0, help="Poll every N seconds continuously")
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  IISentinel Node Collector")
    print(f"  SNMP: {'✔' if SNMP_AVAILABLE else '✗ (pip install pysnmp)'}  "
          f"  ICMPLIB: {'✔' if ICMPLIB_AVAILABLE else '✗ (pip install icmplib)'}")
    print(f"{'═'*60}\n")

    if args.discover:
        print(f"Sweeping {args.ip}...")
        hosts = discover_subnet(args.ip)
        print(f"Found {len(hosts)} live hosts:\n")
        for h in hosts:
            print(f"  {h['ip']:<18}  {h.get('rtt_ms','--')}ms")
        print()
    else:
        node = {
            "id": "cli-test", "ip": args.ip, "type": args.type,
            "proto": args.proto, "label": args.label or args.ip,
            "community": args.community,
        }

        def run_once():
            print(f"Polling {node['label']} ({args.ip}) via {args.proto}...")
            result = poll_node(node)
            print(f"\n  Status:       {result['status'].upper()}")
            print(f"  Latency:      {result.get('latency_ms', '--')} ms")
            print(f"  Packet loss:  {result.get('packet_loss', '--')}%")
            print(f"  Health score: {result.get('health_score', '--')}/100")
            if result.get("snmp_data"):
                print(f"\n  SNMP data:")
                for k, v in result["snmp_data"].items():
                    print(f"    {k:<20} {v}")
            if args.post:
                post_to_metrics(result, args.post)
                print(f"\n  ✔ Posted to {args.post}/api/metrics")
            print()

        run_once()
        if args.watch > 0:
            print(f"Watching — polling every {args.watch}s (Ctrl+C to stop)...\n")
            try:
                while True:
                    time.sleep(args.watch)
                    run_once()
            except KeyboardInterrupt:
                print("\nStopped.")
