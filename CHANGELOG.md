# Changelog
## v10 — in-app email alerts (current)
- Email Alerts section in the control panel: enable/disable, SMTP host/port/
  user/password, from address, recipient list — a Send-test-email button that
  reports success or the exact SMTP error
- Config persists in the database and loads at boot (no redeploy to change
  where alerts go); passwords stored server-side, never sent back to the browser
- _dispatch_alert now actually emails — rogue-DHCP, and other alerts reach the
  inbox (critical also fires SMS/WhatsApp if those are configured)
- Verified: save, persist-across-restart, graceful failure on bad SMTP creds
## v9 — Apple-grey design + rogue DHCP detection (current)
- True iOS system greys: dark=#1C1C1E/#2C2C2E, light=#F2F2F7 (no navy/warm tint)
- All emoji icons replaced with clean SF-style SVG strokes (rail, buttons, toggles)
- Cascade notifications: from per-node flood to milestone-only + single-toast policy
- Telecom removed from default edition (Network + Mining wedge); NOCs own link mon
- ROGUE DHCP DETECTION: net_sensor.py (Pi/Linux) finds consumer routers that
  turn on DHCP and poison a LAN segment — invisible to cloud + tracert.
  Backend /api/net/scan + /api/net/dhcp-status; live Network dashboard card
- Pi reframed as dual sensor: mining telemetry + LAN watchdog, one device
- Production-ready: demo mode off by default; empty states guide real setup
## v8 — the design release (current)
- Light-first design system: white cards, soft shadows, warm gradient canvas,
  iOS tinted icon chips, human copy everywhere (jargon removed from screens)
- Navigation cut to 4: Home / Monitor / Cascade / Insights (Safety + Timeline
  folded in; labeled YouTube-style sidebar on desktop, iOS bottom tabs on mobile)
- Sector photo chips (Mining / Network / Telecom + live Blast-status chip)
  replace tab sprawl — one tap filters fleet and dims the map
- Cascade embedded in-app (iframe + full-screen button) — the dedicated-window
  failure mode is gone; standalone /cascade gets light chrome over dark stage
  and a friendly empty-state notice
- Dark mode is now the toggle, not the default
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
