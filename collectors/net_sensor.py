#!/usr/bin/env python3
"""
IISentinel Network Sensor  (Raspberry Pi / any Linux box on the LAN)
====================================================================
WHY THIS EXISTS — the problem tracert cannot solve
  A consumer router meant for ACCESS mode accidentally has DHCP enabled.
  It starts handing out leases on a floor/office. Devices there get a wrong
  gateway/DNS and traffic blackholes. `tracert` is useless — it only shows
  the gateway YOU received, not the rogue one poisoning others.

  Rogue DHCP is invisible to:
    - a cloud-hosted monitor (can't see the LAN at all)
    - tracert / ping (only see your own path)
  It is ONLY visible to a sensor sitting INSIDE the segment, listening for
  who answers a DHCP DISCOVER. That is this script's job.

WHAT IT DOES
  1. Broadcasts a DHCP DISCOVER and records EVERY server that offers a lease.
  2. Compares against the sanctioned DHCP server you specify (--expected).
  3. Any other responder = ROGUE. Reports it to Sentinel, which alerts + shows
     it on the Network dashboard with the offending IP/MAC.
  4. Also ARP-sweeps the subnet for a live device inventory (optional).
  Runs one sensor per broadcast domain (per VLAN / per floor switch).

DEPLOY (per segment)
  sudo python3 net_sensor.py --server https://your-sentinel \
       --key <collector-key> --segment "floor-3" --expected 192.168.3.1
  (register a key first: python3 net_sensor.py --server ... --register "floor-3-pi")

  Needs root for raw DHCP. Pure-Python fallback works without extra installs;
  scapy is used if available for best accuracy:  sudo pip install scapy
"""
import argparse, json, os, random, socket, struct, sys, time, subprocess, re

try:
    import requests
except ImportError:
    print("pip install requests"); sys.exit(1)

# ---- scapy is optional but best; fall back to raw socket DHCP ----
_HAS_SCAPY = False
try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, conf  # type: ignore
    _HAS_SCAPY = True
except Exception:
    pass


def discover_dhcp_scapy(timeout=6):
    """Return list of {ip,mac} servers that offered a lease (scapy path)."""
    conf.checkIPaddr = False
    mac = get_if_mac()
    xid = random.randint(1, 0xFFFFFFFF)
    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=[mac_bytes(mac)], xid=xid, flags=0x8000) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    ans, _ = srp(dhcp_discover, multi=True, timeout=timeout, verbose=0)
    servers = {}
    for _, rx in ans:
        try:
            sip = rx[IP].src
            smac = rx[Ether].src
            servers[sip] = {"ip": sip, "mac": smac}
        except Exception:
            continue
    return list(servers.values())


def discover_dhcp_raw(timeout=6):
    """Raw-socket DHCP DISCOVER, no scapy. Best-effort; returns [{ip,mac?}]."""
    servers = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.bind(("", 68))
        except Exception:
            s.bind(("", 0))  # unprivileged fallback (may miss some replies)
        s.settimeout(timeout)
        xid = os.urandom(4)
        mac = mac_bytes(get_if_mac())
        pkt = struct.pack("!BBBB4sHH4s4s4s4s16s64s128s",
                          1, 1, 6, 0, xid, 0, 0x8000,
                          b"\x00"*4, b"\x00"*4, b"\x00"*4, b"\x00"*4,
                          mac + b"\x00"*10, b"\x00"*64, b"\x00"*128)
        pkt += bytes([0x63, 0x82, 0x53, 0x63])            # magic cookie
        pkt += bytes([53, 1, 1])                           # DHCP Discover
        pkt += bytes([255])                                # end
        s.sendto(pkt, ("255.255.255.255", 67))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(1024)
                if addr and addr[0] and addr[0] != "0.0.0.0":
                    servers[addr[0]] = {"ip": addr[0]}
            except socket.timeout:
                break
            except Exception:
                break
        s.close()
    except PermissionError:
        print("  (need sudo for raw DHCP; results may be incomplete)")
    except Exception as e:
        print(f"  DHCP probe error: {e}")
    return list(servers.values())


def get_if_mac():
    try:
        import uuid
        m = uuid.getnode()
        return ':'.join(f'{(m >> b) & 0xff:02x}' for b in range(40, -8, -8))
    except Exception:
        return "02:00:00:00:00:01"


def mac_bytes(macstr):
    try:
        return bytes(int(x, 16) for x in macstr.split(':'))
    except Exception:
        return b"\x02\x00\x00\x00\x00\x01"


def detect_gateway():
    """Find this host's default gateway — the natural 'sanctioned' DHCP server guess."""
    try:
        out = subprocess.run(['ip','route'], capture_output=True, text=True, timeout=4).stdout
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', out)
        if m: return m.group(1)
    except Exception:
        try:
            out = subprocess.run(['route','-n','get','default'], capture_output=True, text=True, timeout=4).stdout
            m = re.search(r'gateway:\s*(\d+\.\d+\.\d+\.\d+)', out)
            if m: return m.group(1)
        except Exception: pass
    return ''

def ping_sweep_subnet(base):
    """Lightweight /24 sweep to populate ARP so we can inventory + match MACs."""
    import concurrent.futures
    def _p(ip):
        try:
            subprocess.run(['ping','-c','1','-W','1',ip] if os.name!='nt' else ['ping','-n','1','-w','800',ip],
                           capture_output=True, timeout=2)
        except Exception: pass
    hosts = [f'{base}.{i}' for i in range(1,255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(_p, hosts))

def arp_sweep():
    """Read the OS ARP table for a quick device inventory. [{ip,mac}]."""
    out = []
    try:
        raw = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5).stdout
        for line in raw.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-f:]{17})', line)
            if m:
                out.append({"ip": m.group(1), "mac": m.group(2)})
    except Exception:
        try:  # fallback to `arp -a`
            raw = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
            for m in re.finditer(r'\(?(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+([0-9a-f:]{17})', raw):
                out.append({"ip": m.group(1), "mac": m.group(2)})
        except Exception:
            pass
    return out


def register(server, name):
    r = requests.post(f'{server}/api/collector/register',
                      json={'name': name, 'sector': 'net',
                            'description': f'Network sensor {name}'}, timeout=10)
    d = r.json()
    if 'api_key' in d:
        print(f"\nRegistered. API key (save it):\n  {d['api_key']}\n")
    else:
        print('Registration failed:', d.get('error', r.status_code))


def main():
    ap = argparse.ArgumentParser(description="IISentinel Network Sensor (rogue DHCP)")
    ap.add_argument('--server', required=True)
    ap.add_argument('--key', default=os.environ.get('IIS_COLLECTOR_KEY', ''))
    ap.add_argument('--segment', default='default', help='label for this broadcast domain')
    ap.add_argument('--expected', default='', help='sanctioned DHCP server IP')
    ap.add_argument('--interval', type=float, default=60.0)
    ap.add_argument('--arp', action='store_true', help='also report ARP inventory')
    ap.add_argument('--sweep', metavar='BASE', default='',
                    help='ping-sweep a /24 (e.g. 192.168.1) to build device inventory before scan')
    ap.add_argument('--register', metavar='NAME')
    a = ap.parse_args()

    if a.register:
        return register(a.server, a.register)
    if not a.key:
        print('Need --key (register first with --register "seg-pi")'); sys.exit(1)

    mode = "scapy" if _HAS_SCAPY else "raw-socket"
    if not a.expected:
        gw = detect_gateway()
        if gw:
            a.expected = gw
            print(f"  Auto-detected gateway as sanctioned DHCP: {gw}")
    print(f"IISentinel Network Sensor — segment '{a.segment}'  ({mode})")
    print(f"  Sanctioned DHCP: {a.expected or '(unset — will report all servers)'}")
    print(f"  Reporting to:    {a.server}  every {a.interval}s\n")

    while True:
        if a.sweep:
            print(f"  Sweeping {a.sweep}.0/24 for inventory...")
            ping_sweep_subnet(a.sweep)
        servers = discover_dhcp_scapy() if _HAS_SCAPY else discover_dhcp_raw()
        arp = arp_sweep() if (a.arp or a.sweep) else []
        payload = {'segment': a.segment, 'expected_dhcp': a.expected,
                   'dhcp_servers': servers, 'arp': arp}
        try:
            r = requests.post(f'{a.server}/api/net/scan',
                              headers={'X-Collector-Key': a.key},
                              json=payload, timeout=10)
            d = r.json()
            stamp = time.strftime('%H:%M:%S')
            if d.get('rogue'):
                ips = ', '.join(s.get('ip', '?') for s in d.get('rogue_servers', []))
                print(f"[{stamp}]  ⚠ ROGUE DHCP: {ips}  (sanctioned {a.expected})  — reported")
            else:
                seen = ', '.join(s.get('ip', '?') for s in servers) or 'none'
                print(f"[{stamp}]  clean — DHCP servers seen: {seen}")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}]  report failed: {e}")
        time.sleep(a.interval)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
