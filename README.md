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
