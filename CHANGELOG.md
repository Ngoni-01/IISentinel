# Changelog
## v7 — foundations + LAN truth (current)
- lan_probe.py: LAN-side ping collector (fixes cloud-can't-ping-192.168.x)
- /api/nodes now explains private-IP unreachability in a `note` field
- Sentinel X: reference splash animation (zoom-pop I·I, shimmer wordmark,
  loader bar + status), compact sector segmented control (filters fleet,
  dims map), remaining side-accent borders removed platform-wide
- Cascade Studio: node search + zoom, minimap with viewport + click-to-jump,
  grid + snap, PNG export, undo for link edits, keyboard shortcuts (F/G/E/1-5/Ctrl+Z)
- Engineering: X-Request-ID on every response, traced 500s, [S01-S12]
  section index in app.py, ARCHITECTURE.md, smoke test suite
- Classic: weather tab demoted (API kept for risk alerts)
## v6 — pitch-ready
- Tower-power asset types (generator, fuel_tank) end-to-end; demo genset
- Projector/light mode; CBS advisory line; honest-AI copy; pitch deck +
  one-pager; PITCH.md
## v5.x — speed + permanence
- Real ICMP ping engine (budgeted); banner JPEG optimization + immutable
  caching; gunicorn thread tuning; workspace focus; VPS deploy kit; DB_PATH
## v4.x — Sentinel X
- New experience layer: living map, Ask Sentinel, XAI drawer, timeline,
  voice briefing, command palette, PWA; history-global crash fix + failsafe
## v3.x — engine hardening
- Fixed GROUP-BY random-row SQL, retrain-on-constants bug, gzip, snapshot
  endpoint, intel/auth caches, editions system, honest cold-start AI
