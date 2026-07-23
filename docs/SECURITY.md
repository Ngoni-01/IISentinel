# Security Model

Sentinel's entire pitch is "the sensor only listens, and only reports out."
The security model has to make that literally true, and has to survive a
technical judge reading the code. This document states the trust boundaries
plainly.

## Trust levels

Every route is one of four levels. There is no route that issues a
credential without one of the levels above it.

| Level      | Proof required                          | Example routes            |
|------------|-----------------------------------------|---------------------------|
| PUBLIC     | none                                     | `/health`, the web shell  |
| CODE       | an admin-minted, single-use, segment-scoped enrolment code | `/api/enrol` |
| COLLECTOR  | an active collector key scoped to the claimed segment | `/api/scan` |
| ADMIN      | the admin token                          | everything under `/api/admin`, `/api/findings`, `/api/blast-radius` |

## The enrolment chain

A sensor cannot mint its own credential. The only path to a working key is:

1. An **admin** signs in and mints an enrolment code for a named segment.
   The code is single-use and expires in 15 minutes.
2. The **sensor** redeems that code once at `/api/enrol` and receives a key.
   Only the key's hash is stored; the raw key is shown once.
3. The key is **scoped**: a key enrolled for `floor-3` is rejected if it
   submits a scan claiming any other segment.

An unauthenticated caller at `/api/enrol` receives 401. This is enforced in
`sentinel/storage/db.py::redeem_enrol_code` and covered by
`tests/test_sentinel.py::test_unauthenticated_enrol_rejected`.

## No default password

First boot generates a random password (`sentinel/storage/db.py::init_db`),
prints it once, and sets `must_change`. There is no default credential in
the codebase. `admin123` returns 401 — see `test_no_default_password`.

## What the sensor can and cannot do

The sensor:
- **can** send a broadcast DHCP DISCOVER and record who answers
- **can** read its own ARP table and LLDP/CDP neighbour
- **sends** only what it heard, outbound over HTTPS, to one server
- **cannot** receive commands — there is no inbound control path
- **cannot** modify the network — it has no write capability of any kind
- **cannot** submit for a segment it was not enrolled for

## What the server stores

Device registry, users, enrolment codes, collector key **hashes**, and
findings. Raw collector keys are never stored. Passwords are hashed with
Werkzeug's PBKDF2. No packet payloads or user traffic are captured — only
DHCP-offer metadata and ARP/LLDP facts.

## Rate limiting

Login (10 / 5 min), enrolment (10 / 10 min) and ingest (120 / min) are
rate-limited per IP (`sentinel/api/app.py::rate_limit`).

## Known limits (stated, not hidden)

- Single admin account. Multi-user RBAC is out of scope for this release
  (ADR-006).
- The rate limiter is per-process and in-memory; it resets on restart. On a
  single instance this is sufficient. A shared store would be needed behind
  multiple instances.
- Enrolment codes are transmitted to the sensor operator out of band (the
  admin reads the code from the UI and pastes it). The channel security is
  the operator's existing admin session over TLS.
