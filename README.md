# Sentinel — Network Integrity Monitor

Finds the devices on your network that shouldn't be there — including the
router quietly handing out DHCP leases that traceroute can't see.

A cloud monitor cannot see inside your LAN and `tracert` only shows the
gateway *you* received. Sentinel runs a small sensor inside each broadcast
domain that listens for what is actually answering, attributes it, scores
it, locates it to a switch port, and shows what depends on it.

## Run locally
    pip install -r requirements.txt
    python3 run.py
First boot prints a one-time admin password. There is no default password.

## Structure
    sentinel/
      api/         HTTP surface (Flask) — 14 routes, each with a trust level
      detection/   net_intel (rogue DHCP) + blast_radius (dependency impact)
      storage/     SQLite: admin, enrolment codes, collectors, findings
      web/         single frontend + design system
    sensors/       net_sensor.py, lan_probe.py — run inside the LAN
    tests/         security boundaries, detection correctness, API contracts
    docs/          ARCHITECTURE, SECURITY, METHODOLOGY, SETUP

See docs/SETUP.md for the five-minute path to a first real finding.

## Status
Backend rebuild complete and verified (storage, security, API, detection,
blast-radius). Frontend, docs, tests, and load test in progress.
