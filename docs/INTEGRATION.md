# IISentinel — Mine & Telecom Integration Guide
### Connecting real operations (Unki, Blanket, Caledonia-class sites) to IISentinel

There are three integration paths. Pick per equipment class — they can run
simultaneously against one IISentinel instance.

---

## Path 1 — REST Collector API (any equipment, recommended start)

Anything that can make an HTTPS POST can feed IISentinel. This is how you
integrate an existing SCADA historian, PLC gateway, or NMS without touching
the equipment itself.

1. Register a collector (once, from the specialist panel or curl):
   ```
   POST /api/collector/register
   {"name": "unki-scada-gw-01", "sector": "mc"}
   → returns api_key (shown once)
   ```
2. Push readings (batch up to 500):
   ```
   POST /api/collector/ingest
   Header: X-Collector-Key: <key>
   {"readings": [{
      "device_id": "mc-shaft1-pump-01", "device_type": "pump",
      "metric_name": "temperature", "metric_value": 68.2,
      "temperature": 68.2, "cpu_load": 34, "signal_strength": 88,
      "latency_ms": 12, "packet_loss": 0.1
   }]}
   ```
3. Device appears on the dashboard within one poll cycle. Health scoring,
   anomaly detection, ETTF, incidents, and notifications all apply
   automatically.

Typical bridge: a 50-line Python script on the site's SCADA server reading
OPC-UA/Modbus tags and POSTing every 5–15 s. `collectors/demo_collector.py`
is the reference implementation of the client side.

## Path 2 — SNMP for network & telecom gear

Routers, switches, microwave links, and base station controllers already
speak SNMP. Two options:
- Use the built-in node monitor (dashboard → Network tab → add by IP) for
  reachability/latency health.
- For full SNMP metrics (CPU, memory, interface counters), deploy
  `backend/iis_snmp.py` on a collector host with `pip install easysnmp`
  and forward results through Path 1. Standard MIB-II OIDs are pre-mapped.

## Path 3 — Raspberry Pi edge nodes (physical sensing, ~$80/node)

For equipment with no digital telemetry (older pumps, conveyors, vent fans):
DHT22 (temperature/humidity) + MPU-6050 (vibration) on a Pi 4, running
`collectors/pi_collector.py`. Local LED/buzzer feedback for field crews,
disk buffering during network outages, auto-flush on reconnect.
See `collectors/pi_setup.sh` for the one-shot install.

Cost comparison worth citing: Pi node ≈ $80 vs traditional SCADA
instrumentation point ≈ $5,000+.

---

## Production checklist before a real site pilot

- [ ] Change the default Admin password immediately (Control Panel → Users)
- [ ] Set PRODUCTION=true (disables the /api/admin/token convenience endpoint)
- [ ] Set DATA_API_KEY env var to require a key on read endpoints
- [ ] Configure notification channels via env vars (SMTP_*, AT_API_KEY / TWILIO_*, WA_*)
- [ ] Deploy behind HTTPS (Render provides this automatically)
- [ ] Upgrade off the free tier for a real pilot — free instances sleep
      (~30 s cold start) which is unacceptable for safety monitoring
- [ ] For >50 devices or >30-day retention, plan migration SQLite → PostgreSQL
      (the SQL is standard; render.yaml can provision a managed Postgres)
- [ ] CBS integration: the blast-hold logic here is a monitoring-layer
      interlock. A real deployment must remain SUBORDINATE to the site's
      certified blasting system — IISentinel adds early warning, it does not
      replace certified safety PLCs. Say exactly this to any mine's
      engineering manager; it is the answer they need to hear.

## Honest capability statement (use this wording with clients/examiners)

IISentinel is a pilot-ready condition-monitoring and early-warning platform:
real-time ML health scoring, anomaly detection, trend-based failure
estimation, maintenance windows, audit logging, multi-channel alerting, and
a physical edge tier — suitable for a single-site pilot of tens of devices
today, with a defined scale-up path (Postgres, multiple collectors, per-sector
models via iis_features.py). It is not a certified safety system and not yet
a multi-tenant SaaS; those are the two boundaries to state up front.
