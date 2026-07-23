# Methodology

Sentinel's credibility rests on never asserting more than a sensor observed.
Every value it shows is labelled by origin. This document states what is
measured, what is inferred, what is a rule, and what has not been validated.

## The three bases

Every node, edge and timing in a finding carries a `basis`:

- **observed** — the sensor saw it directly on the wire. A DHCP server
  answering a DISCOVER; a MAC address; a switch name via LLDP; a host's
  gateway from ARP.
- **derived** — computed from an observed value by a stated rule. Example:
  a client attempts DHCP renewal at half its lease (`T1`), so the renewal
  time is `observed_lease / 2`. The lease is observed; the halving is the
  rule.
- **assumed** — a stated default for something not observable from a DHCP
  scan. Example: DNS cache lifetime. These are surfaced in the UI's
  "assumptions" list so a reader can discount them. The only assumed value
  in the current model is `ASSUMED_DNS_CACHE_SECONDS = 300`
  (`sentinel/detection/blast_radius.py`).

## Rogue detection — what is measured

- **Presence**: a DHCP server other than the sanctioned one answered. Observed.
- **Vendor**: looked up from the MAC OUI against a curated registry. Returns
  `Unknown` for unrecognised prefixes — it never guesses. Consumer vs
  enterprise vs virtual is a property of the registry entry, not an inference.
- **Option differences**: gateway, DNS, subnet, lease and domain are compared
  against the sanctioned server's offer. Only options present in both are
  compared; a missing value produces no finding rather than a guessed one.
- **Affected hosts**: counted from ARP entries whose gateway matches the
  rogue. Observed.
- **Location**: switch and port from the sensor's own LLDP/CDP neighbour.
  Observed when the upstream switch speaks LLDP or CDP; absent otherwise,
  never fabricated.

## Severity — what is a rule

The 0–100 severity is **rule-based and fully explainable**. Every point added
is recorded with its reason (`sentinel/detection/net_intel.py::score_rogue`),
and the UI lists those reasons. You can read the formula in the source. It is
not a model and makes no probabilistic claim.

## What has NOT been validated

Stated plainly, because a panel rewards knowing your own limits:

- The severity weights are engineering judgement, not calibrated against a
  labelled corpus of real incidents. They order findings sensibly; they are
  not claimed to be an accuracy-validated risk score.
- The blast-radius **timing** is derived from protocol behaviour (lease
  timers) and is correct in principle, but the end-to-end time-to-impact has
  not been measured against instrumented real outages. It is presented as a
  model, labelled as such, with its assumptions surfaced.
- DNS cache lifetime is assumed, not measured (see above).
- The vendor registry is a curated subset of the IEEE OUI list. Coverage is
  good for common enterprise and consumer gear and incomplete by design;
  unrecognised prefixes are reported honestly as Unknown.

## What Sentinel deliberately does not claim

No accuracy percentage is stated anywhere, because none has been measured
against real data. No failure is "predicted". Nothing is described as AI. The
product does one thing — surface and explain devices that should not be on a
segment — and states exactly how it knows each thing it shows.
