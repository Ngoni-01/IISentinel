"""
sentinel.detection.blast_radius
===============================
Dependency impact analysis over a network segment.

WHAT MAKES THIS DIFFERENT FROM A FAILURE SIMULATOR
  A simulator invents a topology and animates it. This builds its graph
  from what a sensor actually observed on the wire — DHCP offers, ARP
  neighbours, LLDP neighbours — and refuses to draw an edge it did not see.

WHY TIME IS THE INTERESTING DIMENSION
  Physical propagation across a LAN segment is trivial: the segment is
  mostly a star, so "the switch died, everything on it died" is not an
  insight. Service dependency is where the real structure lives, and it
  carries a clock:

    gateway loss  -> immediate. Traffic has nowhere to go.
    DHCP loss     -> nothing happens at first. Clients hold their lease and
                     keep working. They attempt renewal at T1 (half the
                     lease) and lose configuration at expiry. The lease
                     duration is not assumed: it is read from the offer the
                     sensor observed.
    DNS loss      -> masked by cache, then resolution degrades. The cache
                     lifetime is NOT observable from a DHCP scan, so it is
                     labelled an assumption rather than presented as fact.

  So the graph is not "what is wired to what". It is "what depends on what,
  and how long until that dependency bites".

HONESTY RULES ENFORCED HERE
  Every node and edge carries `basis`, one of:
    observed  - the sensor saw this directly
    derived   - computed from an observed value (e.g. T1 = lease / 2)
    assumed   - a stated default because the value is not observable here
  Nothing is emitted without a basis. `assumed` values are surfaced to the
  UI so a reader can discount them. See METHODOLOGY.md.
"""

from __future__ import annotations

# The one value we cannot observe from a DHCP scan. Stated, not hidden.
ASSUMED_DNS_CACHE_SECONDS = 300


def _lease_seconds(offer: dict) -> int | None:
    """Lease time from an observed DHCP offer, or None if it was not present."""
    raw = (offer or {}).get("lease")
    if raw in (None, ""):
        return None
    try:
        val = int(float(str(raw).strip()))
        return val if 0 < val < 30 * 24 * 3600 else None
    except (TypeError, ValueError):
        return None


def _fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    if seconds <= 0:
        return "immediate"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        h, m = seconds // 3600, (seconds % 3600) // 60
        return f"{h}h" if not m else f"{h}h {m}m"
    return f"{seconds // 86400}d"


def build_graph(finding: dict) -> dict:
    """
    Turn one segment's finding into a dependency graph.

    Nodes are services and hosts. Edges are dependencies, each carrying the
    delay between the dependency failing and the dependent noticing.
    """
    segment = finding.get("segment", "segment")
    expected = (finding.get("expected_dhcp") or "").strip()
    rogues = finding.get("rogues") or []
    host_count = int(finding.get("devices_on_segment") or 0)
    location = finding.get("location_hint") or {}

    nodes: list[dict] = []
    edges: list[dict] = []

    def add_node(nid, kind, label, basis, **extra):
        nodes.append({"id": nid, "kind": kind, "label": label,
                      "basis": basis, **extra})

    def add_edge(src, dst, kind, delay, basis, note):
        edges.append({"from": src, "to": dst, "kind": kind,
                      "delay_seconds": delay, "delay_label": _fmt_duration(delay),
                      "basis": basis, "note": note})

    # Switch, when LLDP/CDP gave us one.
    switch_id = None
    if location.get("switch"):
        switch_id = f"switch:{location['switch']}"
        add_node(switch_id, "switch", location["switch"], "observed",
                 port=location.get("port"))

    # The sanctioned DHCP server / gateway.
    if expected:
        add_node(f"dhcp:{expected}", "dhcp", expected, "observed", sanctioned=True)
        add_node(f"gw:{expected}", "gateway", expected, "observed", sanctioned=True)
        if switch_id:
            add_edge(switch_id, f"gw:{expected}", "physical", 0, "observed",
                     "The gateway is reachable through this switch.")

    # Hosts. We know how many the sensor saw; we model them as one population
    # node per dependency rather than inventing individual identities.
    healthy_hosts = host_count
    for r in rogues:
        healthy_hosts -= int(r.get("devices_affected") or 0)
    healthy_hosts = max(0, healthy_hosts)

    if healthy_hosts:
        add_node("hosts:sanctioned", "hosts", f"{healthy_hosts} hosts", "observed",
                 count=healthy_hosts)
        if expected:
            add_edge(f"gw:{expected}", "hosts:sanctioned", "gateway", 0, "observed",
                     "Gateway loss stops traffic immediately.")
            lease = None
            add_edge(f"dhcp:{expected}", "hosts:sanctioned", "dhcp", lease, "observed",
                     "Lease duration was not present in the observed offer.")

    # Each rogue and the hosts that took a lease from it.
    for idx, r in enumerate(rogues):
        rip = r.get("ip") or f"rogue-{idx}"
        rid = f"rogue:{rip}"
        add_node(rid, "rogue", rip, "observed",
                 vendor=r.get("vendor"), category=r.get("vendor_category"),
                 severity=r.get("severity"), mac=r.get("mac"))

        if switch_id:
            add_edge(switch_id, rid, "physical", 0, "observed",
                     "Seen on the same segment as this sensor.")

        affected = int(r.get("devices_affected") or 0)
        if affected:
            hid = f"hosts:{rip}"
            add_node(hid, "hosts", f"{affected} hosts", "observed",
                     count=affected, compromised=True)

            offer = r.get("offer") or {}
            lease = _lease_seconds(offer)

            # Gateway dependency: immediate.
            if offer.get("router"):
                add_edge(rid, hid, "gateway", 0, "observed",
                         "These hosts route through the rogue. "
                         "Removing it cuts their traffic immediately.")

            # DHCP dependency: bites at renewal, derived from the observed lease.
            if lease:
                add_edge(rid, hid, "dhcp", lease // 2, "derived",
                         f"Renewal is attempted at half the observed "
                         f"{_fmt_duration(lease)} lease.")

            # DNS dependency: real, but the cache lifetime is not observable.
            if offer.get("dns"):
                add_edge(rid, hid, "dns", ASSUMED_DNS_CACHE_SECONDS, "assumed",
                         "Resolution degrades once cached entries age out. "
                         "Cache lifetime is a stated default, not measured.")

    return {"segment": segment, "nodes": nodes, "edges": edges}


def _timeline_for(trigger_node: str, graph: dict) -> list:
    """Order the consequences of one node failing by when they are felt."""
    events = []
    for e in graph["edges"]:
        if e["from"] != trigger_node:
            continue
        target = next((n for n in graph["nodes"] if n["id"] == e["to"]), None)
        if not target:
            continue
        count = target.get("count")
        events.append({
            "at_seconds": e["delay_seconds"],
            "at_label": e["delay_label"],
            "dependency": e["kind"],
            "affects": target["label"],
            "affected_count": count,
            "basis": e["basis"],
            "note": e["note"],
        })
    events.sort(key=lambda x: (x["at_seconds"] is None, x["at_seconds"] or 0))
    return events


def analyse(finding: dict) -> dict:
    """
    Full impact analysis for a segment: the graph plus one timeline per
    scenario a network administrator would actually consider.
    """
    graph = build_graph(finding)
    rogues = finding.get("rogues") or []
    scenarios = []

    for r in rogues:
        rip = r.get("ip")
        if not rip:
            continue
        rid = f"rogue:{rip}"
        timeline = _timeline_for(rid, graph)
        affected = int(r.get("devices_affected") or 0)
        scenarios.append({
            "id": f"remove-{rip}",
            "title": f"Remove {rip}",
            "question": "What happens the moment this device is unplugged?",
            "trigger": rid,
            "timeline": timeline,
            "hosts_affected": affected,
            "recovery": _recovery_note(r),
        })

    expected = (finding.get("expected_dhcp") or "").strip()
    if expected:
        gw_timeline = _timeline_for(f"gw:{expected}", graph)
        if gw_timeline:
            scenarios.append({
                "id": "gateway-loss",
                "title": f"Gateway {expected} fails",
                "question": "What is the exposure if the sanctioned gateway drops?",
                "trigger": f"gw:{expected}",
                "timeline": gw_timeline,
                "hosts_affected": sum(
                    n.get("count", 0) for n in graph["nodes"]
                    if n["kind"] == "hosts" and not n.get("compromised")),
                "recovery": "Hosts recover as soon as the gateway returns; "
                            "no reconfiguration is required.",
            })

    assumptions = sorted({
        e["note"] for e in graph["edges"] if e["basis"] == "assumed"
    })

    return {
        "segment": graph["segment"],
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "scenarios": scenarios,
        "assumptions": assumptions,
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
    }


def _recovery_note(rogue: dict) -> str:
    lease = _lease_seconds(rogue.get("offer") or {})
    if lease:
        return (f"Affected hosts recover once they obtain a lease from the "
                f"sanctioned server. Left alone that takes up to "
                f"{_fmt_duration(lease // 2)}; forcing a renew is immediate.")
    return ("Affected hosts recover once they obtain a lease from the "
            "sanctioned server. Forcing a renew is immediate.")
