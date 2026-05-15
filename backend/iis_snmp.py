"""
iis_snmp.py — IISentinel real SNMP polling
==========================================
Drop next to app.py.

Install dependency:
    pip install easysnmp        # preferred — wraps net-snmp C library
    # OR
    pip install pysnmp          # pure-Python fallback (slower)

WHAT THE ORIGINAL CODE DID (broken)
------------------------------------
The poll_node_now() function in app.py did:
    s = socket.create_connection((host, 80), timeout=5)
    requests.get(f"http://{host}/", timeout=3)

That is not SNMP. It is a TCP port-80 connectivity check.
A router with SNMP enabled on UDP/161 but port 80 blocked would
show as "down" even though it is fully operational and monitored.

WHAT THIS MODULE DOES (real)
-----------------------------
Polls the standard SNMP MIBs that every managed router, switch,
and base station supports out of the box:

OID                     | Name           | What it tells you
------------------------|----------------|-------------------------------------
1.3.6.1.2.1.1.1.0      | sysDescr       | Device make/model/OS version
1.3.6.1.2.1.1.3.0      | sysUpTime      | Uptime in hundredths of a second
1.3.6.1.2.1.25.3.3.1.2 | hrProcessorLoad| CPU load % (Host Resources MIB)
1.3.6.1.2.1.25.2.3.1.6 | hrStorageUsed  | Memory used
1.3.6.1.2.1.2.2.1.8.1  | ifOperStatus   | Interface 1 up/down (1=up, 2=down)
1.3.6.1.2.1.2.2.1.10.1 | ifInOctets     | Bytes in on interface 1
1.3.6.1.2.1.2.2.1.16.1 | ifOutOctets    | Bytes out on interface 1

USAGE
-----
    from iis_snmp import snmp_poll, snmp_available

    if snmp_available():
        result = snmp_poll(host='192.168.1.1', community='public', port=161)
        # result is a dict ready to pass into extract_features('net', result)
        print(result)
    else:
        # fall back to TCP ping
        result = tcp_ping_fallback(host)
"""

from __future__ import annotations
import time
from typing import Optional

# ── Detect which SNMP library is available ────────────────────────────────────

_SNMP_BACKEND: Optional[str] = None

try:
    from easysnmp import Session as _EasySession
    _SNMP_BACKEND = "easysnmp"
except ImportError:
    pass

if _SNMP_BACKEND is None:
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
        _SNMP_BACKEND = "pysnmp"
    except ImportError:
        pass


def snmp_available() -> bool:
    """Return True if any SNMP backend is installed."""
    return _SNMP_BACKEND is not None


def snmp_backend() -> Optional[str]:
    """Return 'easysnmp', 'pysnmp', or None."""
    return _SNMP_BACKEND


# ── Standard OIDs ─────────────────────────────────────────────────────────────

_OIDS = {
    "sysDescr":       "1.3.6.1.2.1.1.1.0",
    "sysUpTime":      "1.3.6.1.2.1.1.3.0",
    "cpuLoad":        "1.3.6.1.2.1.25.3.3.1.2.1",   # hrProcessorLoad index 1
    "memUsed":        "1.3.6.1.2.1.25.2.3.1.6.1",   # hrStorageUsed index 1
    "memSize":        "1.3.6.1.2.1.25.2.3.1.5.1",   # hrStorageSize index 1
    "ifOperStatus":   "1.3.6.1.2.1.2.2.1.8.1",
    "ifInOctets":     "1.3.6.1.2.1.2.2.1.10.1",
    "ifOutOctets":    "1.3.6.1.2.1.2.2.1.16.1",
    "ifSpeed":        "1.3.6.1.2.1.2.2.1.5.1",      # interface speed in bps
}


def snmp_poll(
    host: str,
    community: str = "public",
    port: int = 161,
    timeout: int = 5,
    retries: int = 1,
) -> dict:
    """
    Poll a device via SNMP and return a dict compatible with
    extract_features('net', result).

    Keys returned:
        cpu_pct          — CPU load percent (0–100)
        mem_pct          — Memory used percent (0–100)
        uptime_s         — Uptime in seconds
        interface_util_pct — Interface utilisation estimate (0–100)
        packet_loss      — Always 0 if we got a response (SNMP timeout = unreachable)
        latency_ms       — Round-trip time for the SNMP GET
        sys_descr        — Human-readable device description
        if_oper_status   — 1=up, 2=down, 3+=other
        if_in_octets     — Raw counter (use for trend tracking)
        if_out_octets    — Raw counter
        snmp_ok          — True if poll succeeded
        error            — None or error string
    """
    if _SNMP_BACKEND == "easysnmp":
        return _poll_easysnmp(host, community, port, timeout, retries)
    elif _SNMP_BACKEND == "pysnmp":
        return _poll_pysnmp(host, community, port, timeout)
    else:
        return {
            "snmp_ok": False,
            "error": "No SNMP library installed. Run: pip install easysnmp",
            "cpu_pct": 50.0, "mem_pct": 50.0, "uptime_s": 0.0,
            "interface_util_pct": 0.0, "packet_loss": 100.0, "latency_ms": 9999.0,
        }


# ── easysnmp backend ──────────────────────────────────────────────────────────

def _poll_easysnmp(host, community, port, timeout, retries):
    result = _empty_result()
    t0 = time.monotonic()
    try:
        session = _EasySession(
            hostname=host, community=community, version=2,
            timeout=timeout, retries=retries,
            remote_port=port,
        )
        oid_list = list(_OIDS.values())
        items = session.get(oid_list)
        result["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)

        vals = {}
        for i, (name, oid) in enumerate(_OIDS.items()):
            try:
                v = items[i].value
                vals[name] = v
            except Exception:
                vals[name] = None

        result.update(_parse_vals(vals))
        result["snmp_ok"] = True
        result["packet_loss"] = 0.0

    except Exception as e:
        result["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
        result["error"]      = str(e)
        result["snmp_ok"]    = False
        result["packet_loss"] = 100.0

    return result


# ── pysnmp backend ────────────────────────────────────────────────────────────

def _poll_pysnmp(host, community, port, timeout):
    result = _empty_result()
    t0 = time.monotonic()
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
        oid_objects = [ObjectType(ObjectIdentity(oid)) for oid in _OIDS.values()]
        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((host, port), timeout=timeout, retries=1),
                ContextData(),
                *oid_objects,
            )
        )
        result["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)

        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(f"SNMP error at {error_index}: {error_status.prettyPrint()}")

        vals = {}
        names = list(_OIDS.keys())
        for i, (name, val) in enumerate(zip(names, var_binds)):
            vals[name] = str(val[1])

        result.update(_parse_vals(vals))
        result["snmp_ok"]    = True
        result["packet_loss"] = 0.0

    except Exception as e:
        result["latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
        result["error"]      = str(e)
        result["snmp_ok"]    = False
        result["packet_loss"] = 100.0

    return result


# ── Shared value parser ───────────────────────────────────────────────────────

def _parse_vals(vals: dict) -> dict:
    """Convert raw SNMP values to feature-ready floats."""
    out = {}

    # CPU
    try:
        out["cpu_pct"] = float(vals.get("cpuLoad") or 50)
    except (TypeError, ValueError):
        out["cpu_pct"] = 50.0

    # Memory %
    try:
        used = float(vals.get("memUsed") or 0)
        size = float(vals.get("memSize") or 1)
        out["mem_pct"] = round(min(100.0, (used / size * 100) if size > 0 else 50.0), 1)
    except (TypeError, ValueError):
        out["mem_pct"] = 50.0

    # Uptime (sysUpTime is in hundredths of a second)
    try:
        raw_uptime = vals.get("sysUpTime") or "0"
        # easysnmp returns timeticks as an integer string
        uptime_ticks = int(str(raw_uptime).split(" ")[0].replace(",", ""))
        out["uptime_s"] = round(uptime_ticks / 100.0, 0)
    except (TypeError, ValueError):
        out["uptime_s"] = 0.0

    # Interface utilisation (rough: out_octets / (speed/8) as %)
    try:
        speed_bps  = float(vals.get("ifSpeed")     or 1_000_000)  # default 1Mbps
        out_octets = float(vals.get("ifOutOctets")  or 0)
        # This is cumulative counter — use as a proxy for activity
        # Real % requires two polls (delta / interval). Use speed as denominator.
        # Here we clamp to 100 since we don't have a time delta yet.
        out["interface_util_pct"] = min(100.0, round(out_octets / max(speed_bps, 1) * 8 * 100, 1))
        out["if_in_octets"]  = int(float(vals.get("ifInOctets")  or 0))
        out["if_out_octets"] = int(float(vals.get("ifOutOctets") or 0))
    except (TypeError, ValueError):
        out["interface_util_pct"] = 0.0
        out["if_in_octets"]  = 0
        out["if_out_octets"] = 0

    # Interface status
    try:
        out["if_oper_status"] = int(float(vals.get("ifOperStatus") or 1))
    except (TypeError, ValueError):
        out["if_oper_status"] = 1

    # System description
    out["sys_descr"] = str(vals.get("sysDescr") or "").strip()[:200]

    return out


def _empty_result() -> dict:
    return {
        "cpu_pct": 50.0, "mem_pct": 50.0, "uptime_s": 0.0,
        "interface_util_pct": 0.0, "packet_loss": 100.0,
        "latency_ms": 9999.0, "if_oper_status": 2,
        "if_in_octets": 0, "if_out_octets": 0,
        "sys_descr": "", "snmp_ok": False, "error": None,
    }


# ── TCP-ping fallback (unchanged from original, but labelled honestly) ─────────

def tcp_ping_fallback(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """
    TCP connectivity check. This is NOT SNMP.
    Use only when snmp_available() is False.
    Returns minimal dict compatible with extract_features('net', ...).
    """
    import socket
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        latency = round((time.monotonic() - t0) * 1000, 1)
        return {
            "cpu_pct": 50.0, "mem_pct": 50.0, "uptime_s": 0.0,
            "interface_util_pct": 0.0, "packet_loss": 0.0,
            "latency_ms": latency, "snmp_ok": False,
            "warning": f"SNMP unavailable — TCP-only ping to {host}:{port}",
        }
    except Exception as e:
        latency = round((time.monotonic() - t0) * 1000, 1)
        return {
            "cpu_pct": 50.0, "mem_pct": 50.0, "uptime_s": 0.0,
            "interface_util_pct": 0.0, "packet_loss": 100.0,
            "latency_ms": latency, "snmp_ok": False, "error": str(e),
        }


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    print(f"SNMP backend: {snmp_backend() or 'NONE — install easysnmp or pysnmp'}")

    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    community = sys.argv[2] if len(sys.argv) > 2 else "public"

    if snmp_available():
        print(f"\nPolling {host} community={community} ...")
        result = snmp_poll(host, community)
        for k, v in result.items():
            print(f"  {k:25s}: {v}")
    else:
        print("\nFalling back to TCP ping ...")
        result = tcp_ping_fallback(host)
        for k, v in result.items():
            print(f"  {k:25s}: {v}")
