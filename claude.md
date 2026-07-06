# IISentinel™ v3.4 — Project Context for Claude

## What this project is
IISentinel (Intelligent Infrastructure Sentinel) is a full-stack infrastructure
monitoring platform built as a final-year engineering dissertation project.
It targets network, telecommunications, and mining OT (operational technology)
environments in Zimbabwe. The system uses machine learning (Random Forest + Isolation
Forest) to score device health in real time, predict failures, and trigger automated
safety interlocks — including a Centralised Blasting System (CBS) hold at $450,000
per blast if integrity drops below 90%.

This is a dissertation deliverable, not a toy. Every design decision should be
defensible to an engineering examiner panel.

---

## Stack
- **Backend**: Python 3.10+, Flask, SQLite (WAL mode), scikit-learn, joblib, numpy
- **Frontend**: Vanilla HTML/CSS/JS — NO React, NO Vue, NO bundler
- **Charts**: Chart.js 4.4 loaded async from cdnjs CDN
- **Hardware**: Raspberry Pi 4 edge nodes (pi_collector.py)
- **Notifications**: Africa's Talking SMS, Twilio, WhatsApp Business API, SMTP

---

## File structure — place all files in the SAME directory
```
project-root/
├── app.py                  ← Flask backend, run this
├── dashboard.html          ← Main monitoring dashboard (served at /)
├── controlpanel.html       ← Admin console (served at /admin)
├── pi_collector.py         ← Raspberry Pi field collector script
├── pi_setup.sh             ← One-shot Pi setup script
├── pi_collector.service    ← Systemd service for Pi autostart
├── pi_wiring_reference.html← GPIO wiring guide
├── iisentinel.db           ← SQLite DB (auto-created on first run)
├── health_model.pkl        ← Trained Random Forest (auto-created)
├── anomaly_model.pkl       ← Trained Isolation Forest (auto-created)
└── claude.md               ← THIS FILE
```

---

## How to run

### Install dependencies
```bash
pip install flask flask-cors reportlab scikit-learn joblib numpy \
            requests werkzeug psutil
```

### Run normally
```bash
python app.py
```

### Run in demo mode (15 fake devices, 4 Zimbabwean sites)
```bash
DEMO_MODE=true python app.py
```

### URLs
- Dashboard:     http://localhost:5000
- Control panel: http://localhost:5000/admin
- Health check:  http://localhost:5000/health
- PDF report:    http://localhost:5000/api/export-pdf

### Default login
- Username: `Admin`
- Password: `admin123`
- Get token: `GET /api/admin/token`

---

## Architecture — three tiers

```
Tier 1  Raspberry Pi 4 Edge Nodes  →  physical GPIO sensors, LEDs, buzzer
           ↓  POST /api/collector/ingest  (X-Collector-Key header)
Tier 2  IISentinel Intelligence Platform  (app.py)
           Flask · SQLite WAL · Random Forest ML scoring
           SSE stream · CBS interlock · cascade model
           ↓  SSE /api/stream  +  REST /api/*
Tier 3  Command Layer
           dashboard.html  (live fleet view, cascade engine, CBS safety)
           controlpanel.html  (admin console, thresholds, maintenance)
```

---

## Key API endpoints

### Public
| Method | Path | Description |
|--------|------|-------------|
| GET | /api/data | Latest metric per device (cached 10s) |
| GET | /api/snapshot | data + intelligence in ONE call (dashboard uses this) |
| GET | /api/ping | Lightweight keepalive |
| GET | /api/intelligence | ML scores, ETTF, failure probabilities |
| POST | /api/metrics | Ingest single metric reading |
| POST | /api/metrics/bulk | Ingest up to 200 readings |
| GET | /api/stream | SSE stream (metric, cbs_hold, full_sync events) |
| GET | /api/weather?loc=byo | Weather for byo/hre/mut/mine |
| GET | /api/twin/<device_id> | Digital twin load simulation |
| POST | /api/login | Login → returns token |

### Collector (X-Collector-Key header)
| Method | Path | Description |
|--------|------|-------------|
| POST | /api/collector/ingest | Batch ingest from Pi collector |
| POST | /api/collector/register | Register new collector, returns API key |

### Specialist (X-Specialist-Token header)
| Method | Path | Description |
|--------|------|-------------|
| GET | /api/incidents | List incidents by status |
| POST | /api/incidents/<id>/resolve | Resolve incident |
| GET | /api/collectors | List all collectors |
| GET | /api/shift-report | Shift handover report |

### Admin (X-Specialist-Token header, /admin routes)
| Method | Path | Description |
|--------|------|-------------|
| GET | /api/admin/system | Live platform diagnostics |
| GET/POST | /api/admin/thresholds | Per-device-type alert thresholds |
| GET/POST/PUT/DELETE | /api/admin/devices | Device registry CRUD |
| GET/POST/DELETE | /api/admin/maintenance | Maintenance windows |
| GET/POST/DELETE | /api/admin/users | User management |
| GET | /api/admin/audit | Audit log (paginated) |
| POST | /api/admin/dispatch | Send webhook/SMS/email/WhatsApp command |
| POST | /api/admin/db/vacuum | Prune + VACUUM database |
| POST | /api/admin/retrain | Force ML model retrain |
| POST | /api/admin/cache/flush | Flush data cache |

---

## Device types and sectors

```python
NETWORK_TYPES = ['router','switch','firewall','wan_link','workstation']
TELECOM_TYPES = ['base_station','network_tower','microwave_link']
MINING_TYPES  = ['pump','conveyor','ventilation','power_meter','sensor','plc','scada_node']
CBS_TYPES     = ['cbs_controller']
```

Device IDs follow the pattern: `{sector}-{location}-{type}-{index}`
Examples: `net-byo-router-01`, `mc-shaft1-pump-01`, `cbs-dnp3-mine-ctrl`

---

## ML pipeline

1. Metric arrives at `/api/metrics`
2. `sanitize_metric()` validates and clamps field bounds
3. `build_features()` extracts 7 numeric features:
   `[cpu_load, bandwidth_mbps, latency_ms, packet_loss, connected_devices, temperature, signal_strength]`
4. `rf_model.predict()` → health score 0–100
5. `iso_model.predict()` → anomaly flag
6. `get_failure_probability()` uses linear regression on rolling 10-reading history
7. `get_ettf_minutes()` extrapolates slope to failure threshold (score ≤ 18)
8. CBS controller gets additional `get_cbs_integrity_score()`:
   Integrity = Link(55%) + Stability(30%) + Thermal(15%)
   Blast hold if integrity < 90%
9. `_in_maintenance()` suppresses all alerts during active maintenance windows
10. Results queued to SQLite via `flush_worker` background thread

---

## CBS Safety System — CRITICAL
- `CBS_SAFETY_THRESHOLD = 90.0` — blast hold fires below this
- CBS integrity is multi-factor: link health + vibration stability + thermal
- When hold fires: SSE `cbs_hold` event + SMS + WhatsApp sent immediately
- In demo mode: 0.8% chance per cycle of CBS degradation event
- Examiner talking point: $450,000 per misfire — zero tolerance system

---

## Database schema (SQLite, auto-migrated)
Key tables:
- `metrics` — all readings, indexed on device_id and created_at
- `incidents` — auto-created when health < 50
- `specialists` — users with bcrypt-hashed passwords and session tokens
- `collectors` — registered Pi collectors with API keys
- `maintenance_windows` — scheduled suppression windows
- `thresholds` — per-device-type alert config
- `audit_log` — every admin action with actor + timestamp
- `device_registry` — SNMP/OT device inventory
- `cascade_topology` — saved cascade engine node positions
- `dispatch_log` — all outbound commands

---

## Performance characteristics
- **Dashboard open time**: < 200ms. Chart.js loads async — gauges and KPIs appear immediately.
- **Control panel open**: Shell shows instantly on login click (optimistic display). System data loads in background. Admin system API < 5ms (psutil cached in background thread every 5s, no blocking calls).
- **Metric ingest**: < 10ms per reading end-to-end (DB write is async via queue)
- **SSE**: Push within 100ms of any CBS or critical event
- **Data cache TTL**: 10 seconds (intel cache 8 s; auth token cache 60 s)

---

## Raspberry Pi Edge Node
- Script: `pi_collector.py`
- Runs in simulation mode on any machine (no GPIO required)
- On real Pi: reads DHT22 (temp/humidity), MPU-6050 (vibration), drives LEDs + buzzer
- Registers via specialist panel → POST /api/collector/register → gets API key
- Sends batched readings to /api/collector/ingest every 5s
- Green LED = healthy (score ≥ 70)
- Amber LED = warning (score 35–70)
- Red LED + Buzzer = critical or CBS hold
- Blue LED = maintenance window active
- OLED shows live health score if SSD1306 connected
- Setup: `bash pi_setup.sh` on fresh Raspberry Pi OS

**Demo value**: Touch DHT22 sensor with warm hand → temperature rises →
health drops live on dashboard → CBS hold triggers on Pi 2 → buzzer sounds.

---

## Known quirks and gotchas
- FIXED in v3.4: resolveInc() Python-ism, toggleMaintenance() undefined ref,
  fetchAll wrapper recursion, GROUP BY random-row SQL bug, retrain-on-constants
  bug (retraining now uses live-captured feature vectors, needs 100+ readings)
- Chart.js initialises asynchronously — call `onChartReady(fn)` before using any chart
- The `in_maintenance` field comes from the backend SSE payload, not the metric table
- `_maintenance_active` dict is populated at startup from DB and refreshed every 60s
  by `maintenance_refresh_worker()`. Also refreshed immediately when window added/deleted.
- Weather API is open-meteo.com, no key needed, cached 60s per location
- PDF export requires `reportlab` — `pip install reportlab`
- If health_model.pkl and anomaly_model.pkl don't exist, they are built on first run
  (takes ~5 seconds on first launch, normal)
- DEMO_MODE injects readings every 3–5s for 15 devices across Bulawayo, Harare,
  Mutare and Mine Site

---

## Dissertation framing
- **Novel contribution**: Edge-to-cloud OT monitoring with physical actuation feedback
  using commodity hardware (Raspberry Pi 4) in a developing-economy mining context
- **Three-tier architecture**: Sensor layer → Intelligence platform → Command layer
- **Research context**: Zimbabwe mining sector, CBS safety-critical systems, DNP3 protocol
- **Cost argument**: Pi 4 + sensors ≈ $80 vs. traditional SCADA hardware ≈ $5,000+
- **Key metrics to cite**: < 60s event-to-decision, 72h+ acoustic pre-failure lead time,
  $450,000 blast exposure, 3 domains unified in one model

---

## What NOT to change without careful thought
- `CBS_SAFETY_THRESHOLD` — changing this affects physical safety logic
- `flush_worker` sleep interval — too fast causes DB lock contention
- The MAX(created_at) INNER JOIN in `get_cached_data()` — this is the "latest per device" query (v3.4 fix; the old GROUP BY returned arbitrary rows)
- `_in_maintenance()` check in `process_single_metric()` — must stay early in the pipeline
- The `X-Specialist-Token` header name — used in both dashboard and controlpanel JS
