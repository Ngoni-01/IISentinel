# IISentinel™ v3.4 — Intelligent Infrastructure Sentinel

Real-time, AI-assisted infrastructure health monitoring for network,
telecom, and mining OT environments. Random Forest health scoring,
Isolation Forest anomaly detection, time-to-failure estimation, CBS
safety interlock, cascade failure engine, Raspberry Pi edge tier.

## Editions (modular licensing)
Set `ENABLED_MODULES` to sell/deploy sectors independently:
```bash
ENABLED_MODULES=net python app.py            # Network Edition
ENABLED_MODULES=tc python app.py             # Telecom Edition
ENABLED_MODULES=mc,cbs python app.py         # Mining OT + CBS Safety
# unset = full Enterprise Suite
```
Frontends adapt automatically (tabs hide, ingest rejects unlicensed types,
demo mode only injects licensed devices). See docs/SALES_PLAYBOOK.md.

## Honest AI pipeline
Day one: explainable rule-based scoring (no dummy-trained ML in charge).
Real telemetry is captured and persisted from the first reading; after 500
real samples the ML retrains on YOUR data and takes over. Model provenance
(`heuristic-coldstart` vs `ml-real-data`) is visible at /api/config and on
the Intelligence page.

## Quick start
```bash
cd backend
pip install -r requirements.txt
DEMO_MODE=true python app.py     # demo: 15 devices, 4 Zimbabwean sites
```
- Dashboard: http://localhost:5000  (cascade engine under the "Cascade" tab)
- Control panel: http://localhost:5000/admin
- Login: Admin / admin123 — **change this before any deployment**

## Deploy (Render)
Blueprint deploy with the included `render.yaml`, or manually with
root dir `backend` and start command:
```
gunicorn app:app --workers 1 --threads 16 --timeout 120 --bind 0.0.0.0:$PORT
```
The single-worker + threads config is required for SSE live updates.

## Repository layout
```
backend/      app.py, dashboard.html, controlpanel.html, models, helpers
collectors/   pi_collector.py (Pi edge node), demo_collector.py, pi_setup.sh
docs/         INTEGRATION.md — connecting real mines & telecoms
render.yaml   corrected production deploy config
```

## Integrating a real site
See `docs/INTEGRATION.md` — REST collector API, SNMP, and Pi edge paths,
plus the production checklist and the honest capability statement.

## Where does .env go?
`backend/.env` — copy `backend/.env.example` and fill it in. The app auto-loads
it via python-dotenv. On Render, skip the file and set the same variables in
the service's Environment tab.

## Do I need a Raspberry Pi?
Only for equipment with NO digital telemetry. The system has three data paths:
1. Modern gear (routers, PLCs, SCADA) → REST/SNMP bridge, no extra hardware
2. Existing historians/NMS → 50-line REST bridge script
3. Dumb equipment (old pumps, fans) → $80 Pi with temp/vibration sensors
A network-only or telecom-only deployment typically needs zero Pis.

## Opening experience
Fresh visit: I → II → IISentinel splash (2.6s, skippable) → iOS-style mode
selector showing only your licensed sections → straight into that section.
Same-session reloads skip the intro. Section banners pulse in their sector
colour (cyan network, gold mining, red CBS).

## v4 — SENTINEL X (all-new experience + innovation layer)
The classic engine is preserved; the experience was rebuilt from zero.
- `/` — Sentinel X: rail nav, command palette (Cmd/Ctrl+K), living system map,
  insight feed, device drawer with explainable-AI factor breakdown, Ask Sentinel
  natural-language copilot, time-travel replay (2h scrubber), voice shift
  briefing, CBS safety console, PWA installable.
- `/classic` — previous dashboard, untouched fallback.
- New APIs: /api/v4/brief · /api/v4/ask · /api/v4/explain/<id> · /api/v4/timeline

### Innovation → trend mapping (use this in your pitch/report)
| Trend | IISentinel implementation |
|---|---|
| Explainable AI (trust/regulation) | Per-device factor breakdown; score provenance shown live |
| Copilot / NL-ops | Ask Sentinel — deterministic, offline-capable, LLM-ready contract |
| Digital twins | Living system map as the primary surface + time-travel replay |
| Ambient computing | One-tap voice shift briefing (Web Speech, zero deps) |
| Edge/offline-first | Pi collectors with disk buffering; PWA shell |
| Modular SaaS | Editions via ENABLED_MODULES (Microsoft-style SKUs) |

## v5 — Cascade Studio, real LAN monitoring, full transparency
- `/cascade` — Cascade Studio: clean-room rebuild. Fluid full-container canvas
  (ResizeObserver — no more clipped/letterboxed nodes), aurora ambiance,
  breathing Sentinel watermark, per-sector failure simulations (Network outage,
  Telecom backhaul, Mining pump cascade, CBS breach) + Full-system storm +
  manual "fail this node", BFS propagation with particles, live event stream,
  $/hr impact accounting, automatic dependency-ordered recovery, edit mode.
- Real ICMP ping engine: LAN nodes are now pinged with the OS ping binary
  (TCP fallback for ICMP-blocked hosts); results ingest as real devices tagged
  data_source='lan-ping'. One-shot test: GET /api/net/ping?host=192.168.1.1
- Section banners: /static/{networkco,telecomco,miningco}.png layered under
  the pulsating sector glow in /classic.
- /api/v4/lineage — where every reading comes from (demo / LAN / collector /
  API), retrain history, continuous-learning statement. DEMO DATA badge shows
  whenever the simulator is the source. No ambiguity, by design.
- /api/v4/observability — per-route p50/p95 latency, worker heartbeats,
  queue depth, cache state. Surfaced on the Intelligence page.

## On the YouTube system-design diagram (analysed, not copied)
Adopted (right-sized): queue + write-behind flush (their Queueing Services),
multi-layer caching (their Redis role), observability endpoint + heartbeats
(their "Observability Across Systems" — theirs was a label, ours is code),
notification service, adaptive algorithm (our continuous retrain loop).
Rejected for now (with reasons): MySQL sharding/replication — premature at
tens of devices; our path is SQLite -> Postgres at >50 devices. CDN/blob
storage — no video payloads. Improved on its gaps: the diagram shows no
backpressure, no failure paths, no auth, and no data lineage — all four
exist here.
