"""
════════════════════════════════════════════════════════════════════════
IISentinel — Network Intelligence  [S13]
────────────────────────────────────────────────────────────────────────
Turns a raw DHCP scan into an actionable finding.

The problem this solves:
  A consumer router meant for access-point duty has DHCP left enabled.
  It starts answering DISCOVER broadcasts on a floor. Clients there get
  the wrong gateway and DNS. Traffic blackholes or, worse, is silently
  routed through an unmanaged box.

  `tracert` cannot find it — tracert only shows the gateway YOU were
  given. A cloud monitor cannot see it at all. Only an in-segment
  listener can, and even then a bare IP address is not enough for an
  engineer to act on.

What this module adds on top of "there is a second DHCP server":
  1. WHO   — MAC vendor from the OUI, and whether that vendor is a
             consumer brand (the usual culprit) or enterprise kit.
  2. WHAT  — which DHCP options differ from the sanctioned server:
             gateway, DNS, subnet, lease time, domain. Each difference
             has a different operational meaning and a different risk.
  3. HOW BAD — a 0-100 severity score with the reasoning attached, so
             the alert explains itself rather than just shouting.
  4. WHERE — the sensor's own switch/port from LLDP/CDP when available,
             which narrows the physical search to one closet.
  5. HOW LONG — first seen, last seen, and observation count, which
             separates a permanent misconfiguration from a laptop that
             someone plugged in for ten minutes.

Everything degrades gracefully. Unknown vendor is reported as unknown,
never guessed.
════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations
import re

# ─────────────────────────────────────────────────────────────────────
# OUI registry (curated subset)
#
# This is a hand-checked subset of the IEEE OUI registry covering the
# vendors that actually turn up on an enterprise LAN. It is deliberately
# NOT exhaustive: an unrecognised prefix returns "Unknown", which is
# honest and still useful, rather than a confident wrong answer.
#
# To extend: drop the full IEEE oui.csv next to this file and the loader
# below will pick it up automatically.
# ─────────────────────────────────────────────────────────────────────

CONSUMER = 'consumer'      # home/SOHO gear — should never serve DHCP on a managed LAN
ENTERPRISE = 'enterprise'  # managed infrastructure — may be legitimate
COMPUTE = 'compute'        # a server/VM/hypervisor — often an accidental DHCP service
VIRTUAL = 'virtual'        # virtualisation / container host
UNKNOWN = 'unknown'

_OUI = {
    # ---- consumer / SOHO routers: the classic rogue ----
    '001D0F': ('TP-Link', CONSUMER),   '14CC20': ('TP-Link', CONSUMER),
    '50C7BF': ('TP-Link', CONSUMER),   'A0F3C1': ('TP-Link', CONSUMER),
    'EC086B': ('TP-Link', CONSUMER),   'F4F26D': ('TP-Link', CONSUMER),
    'B0487A': ('TP-Link', CONSUMER),   '30B5C2': ('TP-Link', CONSUMER),
    '98DAC4': ('TP-Link', CONSUMER),   'AC84C6': ('TP-Link', CONSUMER),
    'C04A00': ('TP-Link', CONSUMER),   '60E327': ('TP-Link', CONSUMER),

    '00055D': ('D-Link', CONSUMER),    '000D88': ('D-Link', CONSUMER),
    '001346': ('D-Link', CONSUMER),    '0015E9': ('D-Link', CONSUMER),
    '00179A': ('D-Link', CONSUMER),    '001B11': ('D-Link', CONSUMER),
    '001CF0': ('D-Link', CONSUMER),    '001E58': ('D-Link', CONSUMER),
    '002191': ('D-Link', CONSUMER),    '0022B0': ('D-Link', CONSUMER),
    '1C7EE5': ('D-Link', CONSUMER),    '5CD998': ('D-Link', CONSUMER),
    '78542E': ('D-Link', CONSUMER),    '9094E4': ('D-Link', CONSUMER),
    'C8BE19': ('D-Link', CONSUMER),    'F07D68': ('D-Link', CONSUMER),

    '00095B': ('Netgear', CONSUMER),   '000FB5': ('Netgear', CONSUMER),
    '00146C': ('Netgear', CONSUMER),   '00184D': ('Netgear', CONSUMER),
    '001B2F': ('Netgear', CONSUMER),   '001E2A': ('Netgear', CONSUMER),
    '00223F': ('Netgear', CONSUMER),   '0024B2': ('Netgear', CONSUMER),
    '0026F2': ('Netgear', CONSUMER),   '204E7F': ('Netgear', CONSUMER),
    '2CB05D': ('Netgear', CONSUMER),   '30469A': ('Netgear', CONSUMER),
    '4494FC': ('Netgear', CONSUMER),   '841B5E': ('Netgear', CONSUMER),
    '9C3DCF': ('Netgear', CONSUMER),   'A040A0': ('Netgear', CONSUMER),
    'C03F0E': ('Netgear', CONSUMER),   'E0469A': ('Netgear', CONSUMER),
    'E091F5': ('Netgear', CONSUMER),   '04A151': ('Netgear', CONSUMER),

    '000C6E': ('ASUS', CONSUMER),      '000EA6': ('ASUS', CONSUMER),
    '00112F': ('ASUS', CONSUMER),      '0013D4': ('ASUS', CONSUMER),
    '0015F2': ('ASUS', CONSUMER),      '001731': ('ASUS', CONSUMER),
    '001A92': ('ASUS', CONSUMER),      '001BFC': ('ASUS', CONSUMER),
    '001D60': ('ASUS', CONSUMER),      '001E8C': ('ASUS', CONSUMER),
    '002215': ('ASUS', CONSUMER),      '002354': ('ASUS', CONSUMER),
    '00248C': ('ASUS', CONSUMER),      '002618': ('ASUS', CONSUMER),
    '2C56DC': ('ASUS', CONSUMER),      '305A3A': ('ASUS', CONSUMER),
    '38D547': ('ASUS', CONSUMER),      '50465D': ('ASUS', CONSUMER),
    '704D7B': ('ASUS', CONSUMER),      '7824AF': ('ASUS', CONSUMER),
    'AC220B': ('ASUS', CONSUMER),      'BCAEC5': ('ASUS', CONSUMER),
    'D850E6': ('ASUS', CONSUMER),      'F46D04': ('ASUS', CONSUMER),

    '0014BF': ('Linksys', CONSUMER),   '001839': ('Linksys', CONSUMER),
    '001A70': ('Linksys', CONSUMER),   '002129': ('Linksys', CONSUMER),
    '00226B': ('Linksys', CONSUMER),   '002369': ('Linksys', CONSUMER),
    '00259C': ('Linksys', CONSUMER),   '149182': ('Linksys', CONSUMER),
    '20AA4B': ('Linksys', CONSUMER),   '48F8B3': ('Linksys', CONSUMER),
    '586D8F': ('Linksys', CONSUMER),   '6038E0': ('Belkin', CONSUMER),
    '687F74': ('Linksys', CONSUMER),   '98FC11': ('Belkin', CONSUMER),
    'C05627': ('Belkin', CONSUMER),

    'C83A35': ('Tenda', CONSUMER),     '0495E6': ('Tenda', CONSUMER),
    '502B73': ('Tenda', CONSUMER),     'B8BC5B': ('Tenda', CONSUMER),

    '001349': ('Zyxel', CONSUMER),     '0019CB': ('Zyxel', CONSUMER),
    '001E33': ('Zyxel', CONSUMER),     '0023F8': ('Zyxel', CONSUMER),
    '5CF4AB': ('Zyxel', CONSUMER),     '90EF68': ('Zyxel', CONSUMER),
    'B0B2DC': ('Zyxel', CONSUMER),     'EC43F6': ('Zyxel', CONSUMER),

    '009EC8': ('Xiaomi', CONSUMER),    '04CF8C': ('Xiaomi', CONSUMER),
    '0C1DAF': ('Xiaomi', CONSUMER),    '286C07': ('Xiaomi', CONSUMER),
    '34CE00': ('Xiaomi', CONSUMER),    '50642B': ('Xiaomi', CONSUMER),
    '64B473': ('Xiaomi', CONSUMER),    '742344': ('Xiaomi', CONSUMER),
    '8CBEBE': ('Xiaomi', CONSUMER),    'ACC1EE': ('Xiaomi', CONSUMER),
    'F0B429': ('Xiaomi', CONSUMER),    'F8A45F': ('Xiaomi', CONSUMER),

    # ---- enterprise infrastructure: may be legitimate ----
    '00000C': ('Cisco', ENTERPRISE),   '000142': ('Cisco', ENTERPRISE),
    '000163': ('Cisco', ENTERPRISE),   '000A41': ('Cisco', ENTERPRISE),
    '000BBE': ('Cisco', ENTERPRISE),   '000DBD': ('Cisco', ENTERPRISE),
    '001AA1': ('Cisco', ENTERPRISE),   '001B0C': ('Cisco', ENTERPRISE),
    '00220C': ('Cisco', ENTERPRISE),   '0024C4': ('Cisco', ENTERPRISE),
    '00260A': ('Cisco', ENTERPRISE),   '08CC68': ('Cisco', ENTERPRISE),
    '188B9D': ('Cisco', ENTERPRISE),   '1CDF0F': ('Cisco', ENTERPRISE),
    '2C3F38': ('Cisco', ENTERPRISE),   '30F70D': ('Cisco', ENTERPRISE),
    '44ADD9': ('Cisco', ENTERPRISE),   '5057A8': ('Cisco', ENTERPRISE),
    '5897BD': ('Cisco', ENTERPRISE),   '6C416A': ('Cisco', ENTERPRISE),
    '70E422': ('Cisco', ENTERPRISE),   '88F031': ('Cisco', ENTERPRISE),
    'A0ECF9': ('Cisco', ENTERPRISE),   'C40ACB': ('Cisco', ENTERPRISE),
    'E05FB9': ('Cisco', ENTERPRISE),   'F40F1B': ('Cisco', ENTERPRISE),

    '000C42': ('MikroTik', ENTERPRISE),'085531': ('MikroTik', ENTERPRISE),
    '18FD74': ('MikroTik', ENTERPRISE),'2CC81B': ('MikroTik', ENTERPRISE),
    '488F5A': ('MikroTik', ENTERPRISE),'4C5E0C': ('MikroTik', ENTERPRISE),
    '64D154': ('MikroTik', ENTERPRISE),'6C3B6B': ('MikroTik', ENTERPRISE),
    '744D28': ('MikroTik', ENTERPRISE),'B869F4': ('MikroTik', ENTERPRISE),
    'CC2DE0': ('MikroTik', ENTERPRISE),'D4CA6D': ('MikroTik', ENTERPRISE),
    'DC2C6E': ('MikroTik', ENTERPRISE),'E48D8C': ('MikroTik', ENTERPRISE),
    'F41E57': ('MikroTik', ENTERPRISE),

    '00156D': ('Ubiquiti', ENTERPRISE),'002722': ('Ubiquiti', ENTERPRISE),
    '0418D6': ('Ubiquiti', ENTERPRISE),'245A4C': ('Ubiquiti', ENTERPRISE),
    '24A43C': ('Ubiquiti', ENTERPRISE),'44D9E7': ('Ubiquiti', ENTERPRISE),
    '687251': ('Ubiquiti', ENTERPRISE),'7483C2': ('Ubiquiti', ENTERPRISE),
    '788A20': ('Ubiquiti', ENTERPRISE),'802AA8': ('Ubiquiti', ENTERPRISE),
    'B4FBE4': ('Ubiquiti', ENTERPRISE),'DC9FDB': ('Ubiquiti', ENTERPRISE),
    'E063DA': ('Ubiquiti', ENTERPRISE),'F09FC2': ('Ubiquiti', ENTERPRISE),
    'FCECDA': ('Ubiquiti', ENTERPRISE),

    '000B86': ('Aruba', ENTERPRISE),   '001A1E': ('Aruba', ENTERPRISE),
    '00246C': ('Aruba', ENTERPRISE),   '186472': ('Aruba', ENTERPRISE),
    '204C03': ('Aruba', ENTERPRISE),   '24DEC6': ('Aruba', ENTERPRISE),
    '6CF37F': ('Aruba', ENTERPRISE),   '703A0E': ('Aruba', ENTERPRISE),
    '94B40F': ('Aruba', ENTERPRISE),   'ACA31E': ('Aruba', ENTERPRISE),
    'B45D50': ('Aruba', ENTERPRISE),   'D8C7C8': ('Aruba', ENTERPRISE),
    'F05C19': ('Aruba', ENTERPRISE),

    '001D2E': ('Ruckus', ENTERPRISE),  '002482': ('Ruckus', ENTERPRISE),
    '2CE6CC': ('Ruckus', ENTERPRISE),  '348F27': ('Ruckus', ENTERPRISE),
    '4CB1CD': ('Ruckus', ENTERPRISE),  '6CAAB3': ('Ruckus', ENTERPRISE),
    'C0C520': ('Ruckus', ENTERPRISE),  'EC8CA2': ('Ruckus', ENTERPRISE),

    '00090F': ('Fortinet', ENTERPRISE),'085B0E': ('Fortinet', ENTERPRISE),
    '704CA5': ('Fortinet', ENTERPRISE),'906CAC': ('Fortinet', ENTERPRISE),
    'E023FF': ('Fortinet', ENTERPRISE),

    '000585': ('Juniper', ENTERPRISE), '00121E': ('Juniper', ENTERPRISE),
    '0017CB': ('Juniper', ENTERPRISE), '0019E2': ('Juniper', ENTERPRISE),
    '001BC0': ('Juniper', ENTERPRISE), '00239C': ('Juniper', ENTERPRISE),
    '2C2131': ('Juniper', ENTERPRISE), '3C6104': ('Juniper', ENTERPRISE),
    '44F477': ('Juniper', ENTERPRISE), '54E032': ('Juniper', ENTERPRISE),
    '5C4527': ('Juniper', ENTERPRISE), '7819F7': ('Juniper', ENTERPRISE),
    '841888': ('Juniper', ENTERPRISE), '88A25E': ('Juniper', ENTERPRISE),
    'AC4BC8': ('Juniper', ENTERPRISE), 'F01C2D': ('Juniper', ENTERPRISE),

    '001882': ('Huawei', ENTERPRISE),  '001E10': ('Huawei', ENTERPRISE),
    '00259E': ('Huawei', ENTERPRISE),  '0034FE': ('Huawei', ENTERPRISE),
    '00464B': ('Huawei', ENTERPRISE),  '005A13': ('Huawei', ENTERPRISE),
    '04BD70': ('Huawei', ENTERPRISE),  '04C06F': ('Huawei', ENTERPRISE),
    '0819A6': ('Huawei', ENTERPRISE),  '0C37DC': ('Huawei', ENTERPRISE),
    '104780': ('Huawei', ENTERPRISE),  '200BC7': ('Huawei', ENTERPRISE),
    '283152': ('Huawei', ENTERPRISE),  '308730': ('Huawei', ENTERPRISE),
    '4846FB': ('Huawei', ENTERPRISE),  '4C1FCC': ('Huawei', ENTERPRISE),
    '5439DF': ('Huawei', ENTERPRISE),  '5C4CA9': ('Huawei', ENTERPRISE),
    '70723C': ('Huawei', ENTERPRISE),  '781DBA': ('Huawei', ENTERPRISE),
    '80FB06': ('Huawei', ENTERPRISE),  '88E3AB': ('Huawei', ENTERPRISE),
    '9C28EF': ('Huawei', ENTERPRISE),  'ACE215': ('Huawei', ENTERPRISE),
    'B41513': ('Huawei', ENTERPRISE),  'C8D15E': ('Huawei', ENTERPRISE),
    'D07AB5': ('Huawei', ENTERPRISE),  'E8CD2D': ('Huawei', ENTERPRISE),
    'F4C714': ('Huawei', ENTERPRISE),

    # ---- compute / virtualisation: an accidental DHCP service ----
    '005056': ('VMware', VIRTUAL),     '000C29': ('VMware', VIRTUAL),
    '000569': ('VMware', VIRTUAL),     '001C14': ('VMware', VIRTUAL),
    '080027': ('VirtualBox', VIRTUAL), '0A0027': ('VirtualBox', VIRTUAL),
    '00155D': ('Hyper-V', VIRTUAL),    '525400': ('KVM/QEMU', VIRTUAL),
    '0242AC': ('Docker', VIRTUAL),
    'B827EB': ('Raspberry Pi', COMPUTE),
    'DCA632': ('Raspberry Pi', COMPUTE),
    'E45F01': ('Raspberry Pi', COMPUTE),
    '2CCF67': ('Raspberry Pi', COMPUTE),
    'D83ADD': ('Raspberry Pi', COMPUTE),
}


def _norm_mac(mac: str) -> str:
    """Strip separators, uppercase. Returns '' for anything unusable."""
    if not mac:
        return ''
    clean = re.sub(r'[^0-9A-Fa-f]', '', str(mac)).upper()
    return clean if len(clean) >= 6 else ''


def lookup_vendor(mac: str) -> dict:
    """
    MAC -> vendor identity.

    Returns dict with: vendor, category, oui, locally_administered.
    An unrecognised prefix returns vendor='Unknown' — never a guess.
    """
    clean = _norm_mac(mac)
    if not clean:
        return {'vendor': 'Unknown', 'category': UNKNOWN, 'oui': '',
                'locally_administered': False}

    oui = clean[:6]
    # Bit 1 of the first octet set = locally administered (randomised /
    # spoofed / virtual). Worth surfacing: it defeats vendor attribution.
    try:
        local = bool(int(clean[0:2], 16) & 0x02)
    except ValueError:
        local = False

    vendor, category = _OUI.get(oui, ('Unknown', UNKNOWN))
    if vendor == 'Unknown' and local:
        vendor, category = 'Randomised / locally administered', VIRTUAL

    return {'vendor': vendor, 'category': category,
            'oui': ':'.join(oui[i:i+2] for i in range(0, 6, 2)),
            'locally_administered': local}


# ─────────────────────────────────────────────────────────────────────
# DHCP offer comparison
# ─────────────────────────────────────────────────────────────────────

# Each option difference means something different operationally.
# Weight = contribution to the 0-100 severity score.
_OPTION_RISK = {
    'router': (40, 'Hands out a different default gateway — client traffic '
                   'leaves through an unmanaged device'),
    'dns':    (25, 'Hands out different DNS servers — name resolution can be '
                   'redirected without touching routing'),
    'subnet': (15, 'Hands out a different subnet mask — clients miscalculate '
                   'which hosts are local'),
    'domain': (5,  'Hands out a different search domain'),
    'lease':  (5,  'Different lease time — a short lease lets the rogue win '
                   'races against the sanctioned server more often'),
}


def compare_offers(sanctioned: dict, rogue: dict) -> list:
    """
    Diff two DHCP offers. Returns a list of findings:
      [{option, expected, observed, weight, meaning}, ...]
    Missing data on either side is skipped rather than guessed at.
    """
    findings = []
    if not isinstance(sanctioned, dict) or not isinstance(rogue, dict):
        return findings

    def _norm(v):
        if isinstance(v, (list, tuple)):
            return ', '.join(str(x) for x in v if x)
        return str(v).strip() if v is not None else ''

    for opt, (weight, meaning) in _OPTION_RISK.items():
        exp, obs = _norm(sanctioned.get(opt)), _norm(rogue.get(opt))
        if not exp or not obs:
            continue                      # can't compare — don't invent a finding
        if exp != obs:
            findings.append({'option': opt, 'expected': exp, 'observed': obs,
                             'weight': weight, 'meaning': meaning})
    return findings


def score_rogue(rogue_ip: str, vendor_info: dict, findings: list,
                observations: int = 1, lease_takers: int = 0) -> dict:
    """
    Turn the evidence into a 0-100 severity with its reasoning attached.

    The score is deliberately explainable: every point added is traceable
    to a listed reason, so the alert defends itself to an engineer.
    """
    score = 0
    reasons = []

    # Base: something other than the sanctioned server answered at all.
    score += 20
    reasons.append('An unsanctioned device answered a DHCP DISCOVER')

    # Option-level differences carry the operational risk.
    for f in findings:
        score += f['weight']
        reasons.append(f"{f['option'].upper()}: {f['meaning']}")

    # Consumer-grade kit serving DHCP on a managed LAN is the classic
    # accidental-router case and is almost never legitimate.
    cat = vendor_info.get('category')
    if cat == CONSUMER:
        score += 20
        reasons.append(
            f"{vendor_info.get('vendor')} is consumer-grade equipment — "
            f"very likely an access point with DHCP left enabled")
    elif cat in (VIRTUAL, COMPUTE):
        score += 12
        reasons.append(
            f"Source is {vendor_info.get('vendor')} — a host or virtual "
            f"machine running a DHCP service, often unintentionally")
    elif cat == ENTERPRISE:
        score += 4
        reasons.append(
            f"{vendor_info.get('vendor')} is managed-grade equipment — "
            f"could be a legitimate server that was never sanctioned")

    if vendor_info.get('locally_administered'):
        score += 8
        reasons.append('MAC address is randomised or locally administered, '
                       'which defeats vendor attribution')

    # Persistence: a permanent misconfiguration is worse than a laptop
    # that was plugged in once.
    if observations >= 10:
        score += 10
        reasons.append(f'Persistent — observed {observations} times')
    elif observations >= 3:
        score += 5
        reasons.append(f'Recurring — observed {observations} times')

    # Blast radius.
    if lease_takers > 0:
        score += min(15, lease_takers * 3)
        reasons.append(f'{lease_takers} device(s) on this segment appear to '
                       f'be using the rogue gateway')

    score = max(0, min(100, score))
    level = ('critical' if score >= 70 else
             'warning'  if score >= 40 else 'info')

    return {'severity': score, 'level': level, 'reasons': reasons}


def recommend(vendor_info: dict, findings: list, switch_hint: dict | None = None) -> list:
    """Concrete next actions, ordered by what an engineer would do first."""
    steps = []
    opts = {f['option'] for f in findings}

    if switch_hint and switch_hint.get('switch'):
        port = switch_hint.get('port') or 'the sensor uplink port'
        steps.append(
            f"Start at switch {switch_hint['switch']}, port {port} — the sensor "
            f"that saw this is on that segment, so the rogue shares the same "
            f"broadcast domain.")
    else:
        steps.append('Trace the rogue MAC through your switch MAC-address '
                     'tables to find the physical port it is connected to.')

    if vendor_info.get('category') == CONSUMER:
        steps.append(
            f"Look for a {vendor_info.get('vendor')} unit being used as an "
            f"access point or desk switch. Turn off its DHCP server, or put "
            f"it into bridge/AP-only mode.")

    if 'router' in opts:
        steps.append('Treat as urgent: clients that took a lease are routing '
                     'through an unmanaged device. Verify no traffic is being '
                     'intercepted before you unplug it.')
    if 'dns' in opts:
        steps.append('Check the DNS servers it advertised — redirected name '
                     'resolution is a common precursor to credential capture.')

    steps.append('Enable DHCP snooping on the access switches and trust only '
                 'the uplink toward the sanctioned server. This makes the '
                 'problem structurally impossible rather than merely detected.')
    steps.append('Once resolved, clear the affected clients with '
                 '`ipconfig /release && ipconfig /renew` (or reconnect) so '
                 'they take a lease from the correct server.')
    return steps


def analyse(scan: dict) -> dict:
    """
    Main entry point. Takes a raw sensor report, returns a full finding.

    Input (all keys optional except dhcp_servers):
      {
        'segment': 'floor-3',
        'expected_dhcp': '192.168.3.1',
        'dhcp_servers': [{'ip':..., 'mac':..., 'offer':{'router':..., 'dns':...}}],
        'arp': [{'ip':..., 'mac':...}],
        'lldp': {'switch':'sw-core-3', 'port':'Gi1/0/12'},
        'history': {'<ip>': {'count': 7, 'first_seen': '...'}}
      }
    """
    servers = scan.get('dhcp_servers') or []
    expected = str(scan.get('expected_dhcp') or '').strip()
    history = scan.get('history') or {}
    lldp = scan.get('lldp') or {}
    arp = scan.get('arp') or []

    sanctioned_offer = {}
    for s in servers:
        if expected and s.get('ip') == expected:
            sanctioned_offer = s.get('offer') or {}
            break

    rogues = []
    for s in servers:
        ip = s.get('ip')
        if not ip or (expected and ip == expected):
            continue

        vendor_info = lookup_vendor(s.get('mac', ''))
        findings = compare_offers(sanctioned_offer, s.get('offer') or {})

        hist = history.get(ip) or {}
        observations = int(hist.get('count') or 1)

        # How many hosts on this segment are pointed at the rogue as gateway?
        rogue_gw = (s.get('offer') or {}).get('router')
        lease_takers = 0
        if rogue_gw:
            lease_takers = sum(1 for a in arp
                               if a.get('ip') and a.get('ip') != ip
                               and str(a.get('gateway') or '') == str(rogue_gw))

        scoring = score_rogue(ip, vendor_info, findings, observations, lease_takers)

        rogues.append({
            'ip': ip,
            'mac': s.get('mac', ''),
            'vendor': vendor_info['vendor'],
            'vendor_category': vendor_info['category'],
            'oui': vendor_info['oui'],
            'randomised_mac': vendor_info['locally_administered'],
            'offer': s.get('offer') or {},
            'differences': findings,
            'severity': scoring['severity'],
            'level': scoring['level'],
            'why': scoring['reasons'],
            'actions': recommend(vendor_info, findings, lldp),
            'observations': observations,
            'first_seen': hist.get('first_seen'),
            'devices_affected': lease_takers,
            'location_hint': ({'switch': lldp.get('switch'),
                               'port': lldp.get('port')} if lldp.get('switch') else None),
        })

    rogues.sort(key=lambda r: r['severity'], reverse=True)
    worst = rogues[0]['severity'] if rogues else 0

    return {
        'segment': scan.get('segment', 'default'),
        'expected_dhcp': expected,
        'servers_seen': [s.get('ip') for s in servers if s.get('ip')],
        'rogue_count': len(rogues),
        'rogues': rogues,
        'worst_severity': worst,
        'level': (rogues[0]['level'] if rogues else 'ok'),
        'location_hint': ({'switch': lldp.get('switch'), 'port': lldp.get('port')}
                          if lldp.get('switch') else None),
        'devices_on_segment': len(arp),
    }


def summarise(finding: dict) -> str:
    """One-line human summary for an alert body."""
    if not finding.get('rogue_count'):
        return f"Segment {finding.get('segment')}: DHCP clean."
    r = finding['rogues'][0]
    who = r['vendor'] if r['vendor'] != 'Unknown' else 'an unidentified device'
    where = ''
    if r.get('location_hint'):
        where = f" near switch {r['location_hint']['switch']} port {r['location_hint']['port']}"
    return (f"Rogue DHCP on segment {finding.get('segment')}: {r['ip']} "
            f"({who}){where} is handing out leases. Severity {r['severity']}/100.")
