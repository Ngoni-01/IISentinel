#!/usr/bin/env python3
"""
IISentinel Network Sensor
=========================
Runs on a Raspberry Pi (or any Linux box) inside a broadcast domain and
reports what it hears to Sentinel.

WHAT IT FINDS THAT NOTHING ELSE DOES
  A consumer router left in access-point duty with its DHCP server still
  enabled will quietly answer DISCOVER broadcasts on its floor. Clients
  there receive the wrong gateway and DNS.

  `tracert` cannot find it: tracert only shows the gateway YOU received.
  A cloud-hosted monitor cannot see it at all — private LAN traffic never
  reaches the internet. Only a listener inside the same broadcast domain
  can observe the rogue answering.

WHAT IT COLLECTS
  1. Every server that answers a DHCP DISCOVER, with its MAC.
  2. The full offer from each: gateway, DNS, subnet, lease time, domain.
     Sentinel diffs these against the sanctioned server, because WHICH
     option differs determines how dangerous the rogue is.
  3. LLDP/CDP neighbour - the switch and port this sensor is plugged into,
     which narrows the physical hunt to one closet.
  4. ARP inventory, including each host's current gateway, so Sentinel can
     count how many devices already took a lease from the rogue.

DEPLOY (one sensor per VLAN / broadcast domain)
  python3 net_sensor.py --server https://your-sentinel --register "floor-3-pi"
  sudo python3 net_sensor.py --server https://your-sentinel --key <KEY> \
       --segment "floor-3" --expected 192.168.3.1 --arp --lldp

  Raw DHCP needs root. Accuracy is best with scapy:
      sudo pip install scapy
  A pure-Python fallback runs without it.
"""

import argparse, json, os, platform, random, re, socket, struct
import subprocess, sys, time

try:
    import requests
except ImportError:
    print("pip install requests"); sys.exit(1)

_HAS_SCAPY = False
try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, conf  # type: ignore
    _HAS_SCAPY = True
except Exception:
    pass


# -------------------------------------------------------------
# DHCP discovery
# -------------------------------------------------------------

def _mac_str():
    try:
        import uuid
        m = uuid.getnode()
        return ':'.join(f'{(m >> b) & 0xff:02x}' for b in range(40, -8, -8))
    except Exception:
        return "02:00:00:00:00:01"


def _mac_bytes(macstr):
    try:
        return bytes(int(x, 16) for x in macstr.split(':'))
    except Exception:
        return b"\x02\x00\x00\x00\x00\x01"


def _fmt_ip_list(val):
    """scapy returns str or list depending on the option; normalise."""
    if val is None:
        return ''
    if isinstance(val, (list, tuple)):
        return ', '.join(str(v) for v in val if v)
    return str(val)


def discover_scapy(timeout=6):
    """Broadcast a DISCOVER, collect every OFFER including its options."""
    conf.checkIPaddr = False
    mac = _mac_str()
    pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
           IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=[_mac_bytes(mac)], xid=random.randint(1, 0xFFFFFFFF), flags=0x8000) /
           DHCP(options=[("message-type", "discover"), "end"]))

    ans, _ = srp(pkt, multi=True, timeout=timeout, verbose=0)
    servers = {}
    for _, rx in ans:
        try:
            sip = rx[IP].src
            smac = rx[Ether].src
            offer = {}
            opts = rx[DHCP].options if DHCP in rx else []
            for o in opts:
                if not isinstance(o, tuple) or len(o) < 2:
                    continue
                k = o[0]
                v = o[1] if len(o) == 2 else list(o[1:])
                if k == 'router':          offer['router'] = _fmt_ip_list(v)
                elif k == 'name_server':   offer['dns'] = _fmt_ip_list(v)
                elif k == 'subnet_mask':   offer['subnet'] = _fmt_ip_list(v)
                elif k == 'lease_time':    offer['lease'] = str(v)
                elif k == 'domain':        offer['domain'] = _fmt_ip_list(v)
                elif k == 'server_id':     offer['server_id'] = _fmt_ip_list(v)
            try:
                offer['offered_ip'] = rx[BOOTP].yiaddr
            except Exception:
                pass
            servers[sip] = {'ip': sip, 'mac': smac, 'offer': offer}
        except Exception:
            continue
    return list(servers.values())


def _parse_dhcp_options(data):
    """Minimal DHCP option parser for the no-scapy path."""
    offer = {}
    try:
        i = data.find(b'\x63\x82\x53\x63')       # magic cookie
        if i < 0:
            return offer
        p = i + 4
        while p < len(data) - 1:
            code = data[p]
            if code in (0, 255):
                break
            ln = data[p + 1]
            val = data[p + 2: p + 2 + ln]
            if code == 3 and ln >= 4:
                offer['router'] = '.'.join(str(b) for b in val[:4])
            elif code == 6 and ln >= 4:
                offer['dns'] = ', '.join(
                    '.'.join(str(b) for b in val[j:j + 4]) for j in range(0, ln - 3, 4))
            elif code == 1 and ln >= 4:
                offer['subnet'] = '.'.join(str(b) for b in val[:4])
            elif code == 51 and ln >= 4:
                offer['lease'] = str(int.from_bytes(val[:4], 'big'))
            elif code == 15:
                offer['domain'] = val.decode('utf-8', 'ignore')
            elif code == 54 and ln >= 4:
                offer['server_id'] = '.'.join(str(b) for b in val[:4])
            p += 2 + ln
        if len(data) >= 20:
            offer['offered_ip'] = '.'.join(str(b) for b in data[16:20])
    except Exception:
        pass
    return offer


def discover_raw(timeout=6):
    """Raw-socket DISCOVER; parses options without scapy."""
    servers = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.bind(("", 68))
        except Exception:
            s.bind(("", 0))
        s.settimeout(timeout)

        xid = os.urandom(4)
        mac = _mac_bytes(_mac_str())
        pkt = struct.pack("!BBBB4sHH4s4s4s4s16s64s128s",
                          1, 1, 6, 0, xid, 0, 0x8000,
                          b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
                          mac + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128)
        pkt += bytes([0x63, 0x82, 0x53, 0x63, 53, 1, 1, 55, 4, 1, 3, 6, 15, 255])
        s.sendto(pkt, ("255.255.255.255", 67))

        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
                if addr and addr[0] and addr[0] != "0.0.0.0":
                    servers[addr[0]] = {'ip': addr[0], 'mac': '',
                                        'offer': _parse_dhcp_options(data)}
            except socket.timeout:
                break
            except Exception:
                break
        s.close()
    except PermissionError:
        print("  (raw DHCP needs sudo - results may be incomplete)")
    except Exception as e:
        print(f"  DHCP probe error: {e}")
    return list(servers.values())


def enrich_macs(servers):
    """Fill missing MACs from the ARP table (the raw path cannot see them)."""
    table = {a['ip']: a['mac'] for a in arp_table() if a.get('ip') and a.get('mac')}
    for s in servers:
        if not s.get('mac') and s.get('ip') in table:
            s['mac'] = table[s['ip']]
    return servers


# -------------------------------------------------------------
# Context: ARP inventory and switch location
# -------------------------------------------------------------

def arp_table():
    """[{ip, mac}] from the OS neighbour table."""
    out = []
    try:
        raw = subprocess.run(["ip", "neigh"], capture_output=True,
                             text=True, timeout=5).stdout
        for line in raw.splitlines():
            m = re.match(r'(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-fA-F:]{17})', line)
            if m:
                out.append({'ip': m.group(1), 'mac': m.group(2).lower()})
    except Exception:
        try:
            raw = subprocess.run(["arp", "-a"], capture_output=True,
                                 text=True, timeout=5).stdout
            for m in re.finditer(r'\(?(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+([0-9a-fA-F:]{17})', raw):
                out.append({'ip': m.group(1), 'mac': m.group(2).lower()})
        except Exception:
            pass
    return out


def default_gateway():
    """This host's own gateway - the control value for comparison."""
    try:
        raw = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', raw)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        raw = subprocess.run(["route", "-n"], capture_output=True,
                             text=True, timeout=5).stdout
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) > 2 and parts[0] == '0.0.0.0':
                return parts[1]
    except Exception:
        pass
    return ''


def lldp_neighbour():
    """
    Which switch and port is this sensor plugged into?
    Tries lldpctl, then lldpcli, then a brief CDP listen.
    Returns {} when nothing is available - never a guess.
    """
    for cmd in (["lldpctl", "-f", "keyvalue"],
                ["lldpcli", "show", "neighbors", "-f", "keyvalue"]):
        try:
            raw = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
            if not raw.strip():
                continue
            sw = re.search(r'\.chassis\.name=(.+)', raw)
            pt = (re.search(r'\.port\.descr=(.+)', raw) or
                  re.search(r'\.port\.ifname=(.+)', raw))
            if sw or pt:
                return {'switch': sw.group(1).strip() if sw else '',
                        'port': pt.group(1).strip() if pt else '',
                        'source': 'lldp'}
        except FileNotFoundError:
            continue
        except Exception:
            continue

    # CDP: Cisco gear announces roughly every 60s
    try:
        raw = subprocess.run(
            ["timeout", "65", "tcpdump", "-i", "any", "-s", "1500", "-c", "1", "-v",
             "ether[20:2] == 0x2000"],
            capture_output=True, text=True, timeout=72).stdout
        sw = re.search(r"Device-ID \(0x01\), length \d+: '?([^'\n]+)", raw)
        pt = re.search(r"Port-ID \(0x03\), length \d+: '?([^'\n]+)", raw)
        if sw or pt:
            return {'switch': sw.group(1).strip() if sw else '',
                    'port': pt.group(1).strip() if pt else '',
                    'source': 'cdp'}
    except Exception:
        pass
    return {}


# -------------------------------------------------------------

def enrol(server, code, name, key_file):
    """Exchange an admin-issued enrolment code for this sensor's own key."""
    try:
        r = requests.post(f'{server}/api/enrol',
                          json={'code': code, 'name': name}, timeout=15)
        d = r.json()
    except Exception as e:
        print(f'  enrolment failed: {e}'); return None
    if 'api_key' not in d:
        print(f'  enrolment rejected: {d.get("error", r.status_code)}'); return None
    try:
        with open(key_file, 'w') as f:
            json.dump({'api_key': d['api_key'], 'segment': d['segment']}, f)
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    print(f'  enrolled for segment "{d["segment"]}". Key cached in {key_file}.')
    return d['api_key']


def load_key(key_file):
    try:
        with open(key_file) as f:
            return json.load(f).get('api_key')
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="IISentinel Network Sensor")
    ap.add_argument('--server', required=True)
    ap.add_argument('--key', default=os.environ.get('SENTINEL_COLLECTOR_KEY', ''))
    ap.add_argument('--enrol', metavar='CODE', help='one-time enrolment code from the Sentinel UI')
    ap.add_argument('--key-file', default=os.path.expanduser('~/.sentinel-key'),
                    help='where the enrolled key is cached')
    ap.add_argument('--segment', default='default',
                    help='label for this broadcast domain, e.g. "floor-3"')
    ap.add_argument('--expected', default='',
                    help='sanctioned DHCP server IP (defaults to this host gateway)')
    ap.add_argument('--interval', type=float, default=60.0)
    ap.add_argument('--arp', action='store_true', help='include ARP inventory')
    ap.add_argument('--lldp', action='store_true', help='detect switch/port via LLDP or CDP')
    ap.add_argument('--once', action='store_true', help='single scan then exit')
    a = ap.parse_args()

    key = a.key or load_key(a.key_file)
    if a.enrol:
        key = enrol(a.server, a.enrol, a.segment or 'sensor', a.key_file)
        if not key:
            sys.exit(1)
    if not key:
        print('No key. Get an enrolment code from the Sentinel UI (Add sensor),')
        print('then run with --enrol CODE. The key is cached for future runs.')
        sys.exit(1)
    a.key = key

    expected = a.expected or default_gateway()
    mode = "scapy" if _HAS_SCAPY else "raw-socket"

    print("\n  IISentinel Network Sensor")
    print(f"  segment    : {a.segment}")
    print(f"  sanctioned : {expected or '(unset - every server will be reported)'}")
    print(f"  method     : {mode}")
    print(f"  reporting  : {a.server}  every {a.interval:.0f}s\n")

    location = {}
    if a.lldp:
        print("  Looking for the upstream switch (LLDP/CDP)...")
        location = lldp_neighbour()
        if location.get('switch'):
            print(f"    connected to {location['switch']} port {location.get('port','?')} "
                  f"via {location.get('source','').upper()}\n")
        else:
            print("    no LLDP/CDP neighbour visible - location hints unavailable\n")

    while True:
        servers = discover_scapy() if _HAS_SCAPY else enrich_macs(discover_raw())
        arp = []
        if a.arp:
            gw = default_gateway()
            arp = [dict(x, gateway=gw) for x in arp_table()]

        payload = {'segment': a.segment, 'expected_dhcp': expected,
                   'dhcp_servers': servers, 'arp': arp, 'lldp': location}
        stamp = time.strftime('%H:%M:%S')
        try:
            r = requests.post(f'{a.server}/api/scan',
                              headers={'X-Collector-Key': a.key},
                              json=payload, timeout=15)
            d = r.json()
            if d.get('rogue'):
                print(f"  [{stamp}]  ROGUE DHCP  severity {d.get('severity')}/100")
                for rg in d.get('rogue_servers', []):
                    print(f"            {rg['ip']}  {rg.get('vendor','Unknown')}"
                          f"  ({rg.get('vendor_category','?')})")
                    for w in (rg.get('why') or [])[:3]:
                        print(f"              - {w}")
            else:
                seen = ', '.join(s['ip'] for s in servers) or 'none'
                print(f"  [{stamp}]  clean  ({len(servers)} server: {seen})")
        except Exception as e:
            print(f"  [{stamp}]  report failed: {e}")

        if a.once:
            break
        time.sleep(a.interval)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n  Stopped.")
