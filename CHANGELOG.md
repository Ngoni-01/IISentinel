# Changelog

## Rebuild — network integrity monitor

A ground-up restructure. The product is now one thing: a network integrity
monitor that finds devices which should not be on a segment, explains them,
locates them, and shows what depends on them.

### Added
- **Authenticated enrolment.** Admin mints a single-use, segment-scoped,
  15-minute code; the sensor redeems it for a scoped key. No unauthenticated
  path to a credential exists.
- **Network blast-radius analysis** (`sentinel/detection/blast_radius.py`).
  A dependency model built entirely from what sensors observed, with
  time-to-impact derived from observed DHCP lease timers. Every node, edge
  and timing is labelled observed / derived / assumed; assumptions are
  surfaced, not hidden.
- **Single frontend** on one design system. Finding-as-hero, light default,
  guided empty-state onboarding, methodology panel.
- **Four docs**: SECURITY, METHODOLOGY, SETUP, and a rewritten ARCHITECTURE
  with ADRs (including the reasoning for every deletion) and a fault-tracing
  map that resolves to real code locations.
- **20-test suite** covering security boundaries, detection correctness and
  its refusal to guess, and blast-radius honesty.

### Changed
- Backend restructured from a single ~2,975-line file into
  `sentinel/{api,detection,storage,web}` + `sensors/`.
- Collector authentication is now O(1): a truncated one-way key lookup
  narrows to a single candidate row, so PBKDF2 is verified once per request
  rather than against every collector. (Found by the load test — see below.)
- First boot mints a random admin password and forces a change. No default
  credential exists anywhere.
- Rate limits on login, enrolment and ingest.

### Removed
- Blast-safety / CBS interlock (functional-safety liability).
- Mining OT sector, device types, demo devices; the mining cascade simulator
  (replaced by network blast-radius).
- Voice briefing, command palette, timeline replay, natural-language ask.
- PWA manifest / service worker; the `/classic` dashboard; demo-mode default.
- The unauthenticated collector-registration endpoint that returned a working
  key — the single most serious flaw in the prior build.

Route surface fell from ~65 to 14. Backend Python roughly halved.

### Load test / measured ceiling
`tests/load_test.py` ramps concurrent sensors and measures finding-write
latency. Its first run exposed an O(n) PBKDF2-per-collector auth cost, now
fixed. Absolute latencies depend heavily on host CPU (PBKDF2 is intentionally
expensive); the ceiling should be re-measured on the target instance and the
number recorded here. The workload is periodic per-segment findings, not
per-device high-frequency telemetry, so a modest instance serves a large
sensor fleet at realistic reporting intervals. When a real deployment
approaches the measured p95>50ms point, revisit ADR-003 (separate
time-series store).
