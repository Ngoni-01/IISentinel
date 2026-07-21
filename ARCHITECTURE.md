# IISentinel — Architecture & Engineering Foundations

## Layered structure
```
┌─ Presentation ── sentinel-x.html (/) · cascade.html (/cascade)
│                  dashboard.html (/classic) · controlpanel.html (/admin)
├─ API ─────────── Flask routes: core · admin · v4 innovation · collector · nodes
│                  every response carries X-Request-ID
├─ Domain ──────── scoring pipeline · heuristic teacher · anomaly (IsolationForest)
│                  ETTF trend model · CBS interlock · cascade topology
├─ Workers ─────── flush · scorer · retrain · maintenance-refresh · node-poller
│                  demo-injector · psutil-sampler  (threads, heartbeat-tracked)
├─ Data ────────── SQLite (WAL) at DB_PATH · in-memory caches (data 10s /
│                  intel 8s / auth 60s / pages ETag / pdf 30s)
└─ Edge ────────── pi_collector.py (sensors) · lan_probe.py (LAN ping)
                   demo_collector.py — all push HTTPS-outbound only
```

## Data flow (one reading, end to end)
edge probe/sensor → POST /api/collector/ingest (X-Collector-Key)
→ [S04] sanitize (bounds, defaults — never midpoints) → build_features
→ heuristic score (teacher) + ML score + anomaly flag → device state
→ metric_queue → [S07] flush worker batches to SQLite (+ training_samples)
→ SSE push to dashboards → thresholds → notification dispatch
→ _train_buffer → retrain worker (≥500 real samples) → model_meta provenance

## Fault-tracing map (symptom → look here first)
| Symptom | First place to look |
|---|---|
| 500 to a user | server log: `[ERROR rid=xxxx]` — match the X-Request-ID from their response |
| Gauges frozen | /api/v4/observability → workers.flush_worker age; then queue_depth |
| Wrong health score | /api/v4/explain/<id> — factor penalties are the ground truth |
| LAN node "offline" | /api/nodes → `note` field (private-IP-from-cloud is the usual cause) |
| Model never learns | /api/v4/lineage → real_samples counter; DB_PATH set? disk mounted? |
| SSE dead in prod | gunicorn start command — must be 1 worker + threads |
| Slow everything | observability route p95s; then instance CPU (Render metrics) |

## Decision log (ADRs — the "why" behind the shape)
1. **Single-file backend, section-indexed** — deployment is one file + assets;
   the [S01–S12] grep-index in app.py is the module map. Package refactor is
   scheduled post-pilot when a second contributor exists, not before.
2. **SQLite over Postgres (for now)** — one pilot site, tens of devices,
   WAL mode + persistent disk. Migration trigger: >50 devices or multi-site.
3. **SSE over WebSockets** — one-directional push is all we need; survives
   proxies; no extra dependency. Trigger to revisit: bidirectional control.
4. **Heuristic-teacher ML** — no dummy training data ever authoritative;
   labels come from auditable rules until real failure labels exist (pilot).
5. **Outbound-only edge** — collectors push; the cloud never reaches into
   OT networks. This is the security posture, by construction.
6. **REST not MQTT for collectors** — no broker to run, passes any firewall,
   curl-debuggable. Trigger: hundreds of nodes.

## Change control
- CHANGELOG.md — every version's changes, dated.
- tests/test_smoke.py — run before every deploy: `pytest tests/ -q`
- Deploy = git push (Render auto-deploy) or scp + systemctl restart (VPS).
