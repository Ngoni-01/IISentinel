# Architecture

## Layered structure

    sentinel/
      api/app.py          HTTP surface. 14 routes, each tagged with a trust
                          level. Request-ID on every response; 500s traced.
      detection/
        net_intel.py      Rogue-DHCP intelligence: vendor OUI lookup, DHCP
                          option diffing, explainable severity, localisation.
        blast_radius.py   Dependency-impact model over discovered topology,
                          with time-to-impact derived from observed leases.
      storage/db.py       SQLite (WAL). Admin, enrolment codes, collectors,
                          findings, rogue history. Enforces the trust boundary.
      web/                Single frontend (index.html) on one design system
                          (sentinel-ds.css). No override layer.
    sensors/
      net_sensor.py       Runs inside a broadcast domain. Enrols with a code,
                          listens for DHCP answers, reports out over HTTPS.
      lan_probe.py        Optional ICMP reachability probe for LAN devices.
    tests/                Security boundaries, detection correctness, honesty.
    docs/                 SECURITY, METHODOLOGY, SETUP.

## Data flow (one scan, end to end)

    sensor DHCP DISCOVER on segment
      -> observes answering servers + options, ARP, LLDP
      -> POST /api/scan  (X-Collector-Key, must be scoped to the segment)
         [sentinel/api/app.py::submit_scan]
      -> net_intel.analyse() attributes, diffs, scores, localises
         [sentinel/detection/net_intel.py::analyse]
      -> db.record_finding() persists finding + updates rogue history
         [sentinel/storage/db.py::record_finding]
      -> admin GET /api/findings renders the dashboard
      -> admin GET /api/blast-radius/<seg> builds the dependency timeline
         [sentinel/detection/blast_radius.py::analyse]

## Fault-tracing map (symptom -> where to look)

| Symptom                          | First location                                  |
|----------------------------------|-------------------------------------------------|
| 500 on a request                 | server log `[ERROR rid=...]`; match X-Request-ID |
| A sensor's scans are rejected    | `db.authenticate_collector` — key active? scoped?|
| Enrolment fails                  | `db.redeem_enrol_code` — code used/expired?      |
| Wrong vendor / "Unknown"         | `net_intel._OUI` registry coverage              |
| Severity looks off               | `net_intel.score_rogue` — every point is logged |
| Blast-radius timing wrong        | `blast_radius.build_graph` — check the observed lease |
| Findings not persisting          | `DB_PATH` set to a writable/persistent path?     |

## Decision log (ADRs)

Each records the trigger that would cause it to be revisited.

**ADR-001 — Single admin, token auth, no default password.**
A random password is minted on first boot and must be changed. Rationale:
the previous build shipped `admin123` and an unauthenticated enrolment
endpoint, which is disqualifying. Revisit when multi-user access is needed.

**ADR-002 — Enrolment codes as the only path to a collector key.**
Admin mints a single-use, segment-scoped, short-lived code; the sensor
redeems it. Rationale: no unauthenticated caller may ever receive a working
credential. Chosen over sensor-initiated approval because that requires an
unauthenticated write surface. Revisit if zero-touch provisioning at scale
is required.

**ADR-003 — SQLite (WAL), relational only, no separate time-series store.**
A network-integrity monitor receives periodic findings from a handful of
segment sensors, not a high-frequency telemetry firehose. Rationale: a
separate append store is unjustified moving parts on a single small
instance. The measured ceiling is in the load-test section below. Revisit
when a real deployment approaches that ceiling.

**ADR-004 — Cascade reborn as network blast-radius over discovered topology.**
The prior mining failure simulator used an invented topology. It is replaced
by a dependency model built entirely from sensor observations, with
time-to-impact derived from observed DHCP leases. Rationale: a panel
discounts a simulated demo; an observed one it cannot. Generality of the
engine (domain-agnostic graph + node health + edge weights) is documented
for the dissertation. Revisit if multi-segment topologies need deeper tiers.

**ADR-005 — One frontend, one design system, no override layer.**
The prior build had four frontends unified by a CSS compatibility layer.
Collapsed to one page that consumes design tokens directly. Rationale: the
system owns the components; a translated token means the component is wrong.

## Deletions (and why) — carried out in this rebuild

- **Blast-safety / CBS interlock** — functional-safety liability
  (IEC 61508/61511 territory) with no upside for a student project. Removed
  entirely; no substitute, because the product is now about networks.
- **Mining OT sector, device types, demo devices** — wrong beachhead; needs
  hardware on someone else's plant and site access unavailable here.
- **Cascade mining simulator** — replaced, not kept (ADR-004).
- **Voice briefing, command palette, timeline replay, NL "ask"** — serve no
  buyer and the NL endpoint overclaims. Cut.
- **PWA manifest / service worker** — maintenance cost, no demand.
- **Classic dashboard (`/classic`)** — a second design language. Cut.
- **Demo mode as the default** — real data is the default; there is no
  simulated mode in this build.

Net effect: backend Python fell from ~2,975 lines (app.py alone) to ~1,400,
and four frontends became one. The route surface fell from ~65 to 14.

## Load test / device ceiling

See `tests/load_test.py`. Result recorded in CHANGELOG under the current
version. SQLite/WAL on a single small instance sustains the sensor-reporting
workload (periodic findings, not per-device 5s telemetry) with headroom;
the documented ceiling is the point at which finding-write latency crosses
50 ms, measured, not guessed.
