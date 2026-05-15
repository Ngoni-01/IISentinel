"""
iis_features.py — IISentinel device-type feature extractors
============================================================
Drop this file next to app.py. Import with:
    from iis_features import extract_features, FEATURE_NAMES, pivot_metrics_rows

Why this file exists
--------------------
The original app used a single 7-feature vector for every device type:
    [cpu_load, bandwidth_mbps, latency_ms, packet_loss,
     connected_devices, temperature, signal_strength]

A pump's health has nothing to do with 'connected_devices'.
A router's health has nothing to do with 'signal_strength'.
This file gives each sector its own feature schema so models
can actually learn something real.

Usage in app.py
---------------
Replace the inline feature list in score_device() and retrain_worker()
with calls to extract_features(device_type, data_dict).

    from iis_features import extract_features, pivot_metrics_rows

    # In score_device / ingest endpoint:
    arr = np.array([extract_features(device_type, data)], dtype=float)

    # In retrain_worker (fixed pivot from DB rows):
    rows = [dict(r) for r in con.execute("SELECT * FROM metrics ...")]
    X, y, types = pivot_metrics_rows(rows)
"""

from __future__ import annotations
import numpy as np
from typing import Any

# ── Feature schemas ────────────────────────────────────────────────────────────
# Each entry: (metric_key, default_value, min_clip, max_clip)
# The metric_key matches what collectors POST in 'metric_name' / data dict keys.

_SCHEMAS: dict[str, list[tuple[str, float, float, float]]] = {

    # ── Mining ────────────────────────────────────────────────────────────────
    # Pumps, conveyors, ventilation fans, crushers
    "mining": [
        ("current_amps",          30.0,   0.0,  1000.0),
        ("vibration_g",            0.5,   0.0,    50.0),
        ("bearing_temp_c",        45.0,   0.0,   200.0),
        ("flow_rate_lpm",        200.0,   0.0, 10000.0),
        ("differential_pressure", 2.0,   0.0,   100.0),
        ("runtime_hours",          0.0,   0.0,  9000.0),  # hours since last service
        ("motor_temp_c",          55.0,   0.0,   200.0),
    ],

    # CBS (Controlled Blasting System) keeps its own deterministic logic in app.py
    # but expose the same feature schema so the ML model can cross-validate.
    "cbs": [
        ("link_health",          100.0,   0.0,   100.0),
        ("vibration_g",            0.1,   0.0,    50.0),
        ("temperature_c",         35.0,   0.0,   150.0),
        ("battery_pct",          100.0,   0.0,   100.0),
        ("signal_strength",       80.0,   0.0,   100.0),
        ("latency_ms",             5.0,   0.0,  5000.0),
        ("packet_loss",            0.0,   0.0,   100.0),
    ],

    # ── Network ───────────────────────────────────────────────────────────────
    # Routers, switches, firewalls
    "net": [
        ("interface_util_pct",    20.0,   0.0,   100.0),
        ("error_rate_ppm",         0.0,   0.0,  1000.0),
        ("cpu_pct",               30.0,   0.0,   100.0),
        ("mem_pct",               40.0,   0.0,   100.0),
        ("packet_loss",            0.0,   0.0,   100.0),
        ("latency_ms",             5.0,   0.0, 60000.0),
        ("uptime_s",          86400.0,   0.0,   1e8),
    ],

    # ── Telecom ───────────────────────────────────────────────────────────────
    # Base stations, microwave links, repeaters
    "telecom": [
        ("rssi_dbm",             -70.0, -150.0,     0.0),
        ("ber",                    0.0,   0.0,     1.0),   # bit error rate
        ("link_util_pct",         30.0,   0.0,   100.0),
        ("tx_power_dbm",          20.0, -10.0,    50.0),
        ("temperature_c",         35.0,   0.0,   100.0),
        ("uptime_s",          86400.0,   0.0,     1e8),
        ("packet_loss",            0.0,   0.0,   100.0),
    ],

    # ── Power / SCADA / PLC ───────────────────────────────────────────────────
    "power": [
        ("voltage_v",            230.0,   0.0,  1000.0),
        ("current_amps",          10.0,   0.0,  1000.0),
        ("frequency_hz",          50.0,  45.0,    55.0),
        ("power_factor",           0.9,   0.0,     1.0),
        ("temperature_c",         40.0,   0.0,   200.0),
        ("uptime_s",          86400.0,   0.0,     1e8),
        ("battery_pct",          100.0,   0.0,   100.0),
    ],

    # Fallback — used when device_type is unknown
    "generic": [
        ("cpu_load",              50.0,   0.0,   100.0),
        ("bandwidth_mbps",       100.0,   0.0, 100000.0),
        ("latency_ms",            10.0,   0.0, 60000.0),
        ("packet_loss",            0.0,   0.0,   100.0),
        ("connected_devices",     10.0,   0.0,  1000.0),
        ("temperature",           40.0, -50.0,   200.0),
        ("signal_strength",       80.0,   0.0,   100.0),
    ],
}

# Aliases — map app.py device_type strings to schema keys
_ALIASES: dict[str, str] = {
    "router": "net", "switch": "net", "firewall": "net",
    "ap": "net", "wifi": "net", "network": "net",
    "base_station": "telecom", "microwave": "telecom",
    "repeater": "telecom", "tower": "telecom",
    "pump": "mining", "conveyor": "mining",
    "ventilation": "mining", "crusher": "mining",
    "fan": "mining", "hoist": "mining",
    "plc": "power", "scada_node": "power",
    "generator": "power", "ups": "power",
    "cbs_controller": "cbs",
}


def _resolve_schema(device_type: str) -> list[tuple[str, float, float, float]]:
    """Return the feature schema for a given device_type string."""
    dt = (device_type or "generic").lower().strip()
    key = _ALIASES.get(dt, dt)
    return _SCHEMAS.get(key, _SCHEMAS["generic"])


def FEATURE_NAMES(device_type: str) -> list[str]:
    """Return the list of feature names for a device type."""
    return [f[0] for f in _resolve_schema(device_type)]


def extract_features(device_type: str, data: dict[str, Any]) -> list[float]:
    """
    Build a fixed-length feature vector from a data dict.

    `data` can come from:
      - A collector POST body (keys like 'cpu_load', 'vibration_g', ...)
      - A dict already built from metric_name/metric_value pairs
      - app.py's existing data dict (falls back gracefully)

    Always returns a list of floats — never None, never NaN.
    """
    schema = _resolve_schema(device_type)
    vec = []
    for key, default, lo, hi in schema:
        raw = data.get(key)
        if raw is None:
            raw = default
        try:
            val = float(raw)
        except (TypeError, ValueError):
            val = default
        if not np.isfinite(val):
            val = default
        val = float(np.clip(val, lo, hi))
        vec.append(val)
    return vec


# ── Pivot helper for retrain_worker ───────────────────────────────────────────

def pivot_metrics_rows(
    rows: list[dict],
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Convert raw DB rows from the metrics table into training arrays.

    The metrics table stores ONE metric per row:
        device_id | device_type | metric_name | metric_value | health_score

    This function groups by (device_id, created_at minute) to reconstruct
    the full feature vector for each reading, then returns:
        X     — (n_samples, n_features) float array
        y     — (n_samples,) health_score array
        types — (n_samples,) list of device_type strings

    Only rows with a non-null health_score are included.

    Usage in retrain_worker:
        rows = [dict(r) for r in con.execute(
            "SELECT * FROM metrics ORDER BY created_at DESC LIMIT 5000")]
        X, y, types = pivot_metrics_rows(rows)
        if len(X) < 50:
            continue  # not enough real data yet
    """
    from collections import defaultdict

    # Group readings: key = (device_id, device_type, timestamp_minute)
    # Each group accumulates {metric_name: metric_value} and health_score
    groups: dict[tuple, dict] = defaultdict(lambda: {"metrics": {}, "health_score": None, "device_type": "generic"})

    for r in rows:
        did   = r.get("device_id", "")
        dtype = r.get("device_type", "generic") or "generic"
        ts    = (r.get("created_at") or "")[:16]  # truncate to minute
        hs    = r.get("health_score")
        mname = r.get("metric_name", "")
        mval  = r.get("metric_value")

        key = (did, ts)
        g   = groups[key]
        g["device_type"] = dtype

        if mname and mval is not None:
            try:
                g["metrics"][mname] = float(mval)
            except (TypeError, ValueError):
                pass

        # A row may have health_score set even when metric_name is null
        if hs is not None:
            try:
                g["health_score"] = float(hs)
            except (TypeError, ValueError):
                pass

    X_list, y_list, type_list = [], [], []

    for (did, ts), g in groups.items():
        hs = g["health_score"]
        if hs is None:
            continue
        dtype = g["device_type"]
        data  = g["metrics"]
        vec   = extract_features(dtype, data)
        X_list.append(vec)
        y_list.append(hs)
        type_list.append(dtype)

    if not X_list:
        # Return empty arrays with correct shapes
        return np.empty((0, 7), dtype=float), np.empty(0, dtype=float), []

    return np.array(X_list, dtype=float), np.array(y_list, dtype=float), type_list


# ── Quick self-test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== iis_features self-test ===")
    for dt in ["mining", "net", "telecom", "cbs", "power", "pump", "router", "unknown"]:
        vec = extract_features(dt, {})
        names = FEATURE_NAMES(dt)
        print(f"\n{dt:20s} → {len(vec)} features")
        for n, v in zip(names, vec):
            print(f"  {n:30s} = {v}")

    # Test pivot
    fake_rows = [
        {"device_id": "pump-01", "device_type": "mining", "created_at": "2024-01-01T08:00",
         "metric_name": "vibration_g",    "metric_value": 2.5, "health_score": 72.0},
        {"device_id": "pump-01", "device_type": "mining", "created_at": "2024-01-01T08:00",
         "metric_name": "bearing_temp_c", "metric_value": 68.0, "health_score": None},
        {"device_id": "router-01", "device_type": "net",  "created_at": "2024-01-01T08:01",
         "metric_name": "cpu_pct",        "metric_value": 45.0, "health_score": 85.0},
    ]
    X, y, types = pivot_metrics_rows(fake_rows)
    print(f"\nPivot test: {len(X)} samples")
    for i in range(len(X)):
        print(f"  [{types[i]}] y={y[i]:.1f}  X={X[i].tolist()}")
