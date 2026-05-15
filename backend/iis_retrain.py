"""
iis_retrain.py — IISentinel fixed retrain worker
=================================================
Drop next to app.py. Replace the retrain_worker() function in app.py
with the one in this file.

THE BUG THIS FIXES
------------------
Original retrain_worker (lines ~494-497 of app.py v3.3):

    f = [r.get('cpu_load', 50) or 50,
         r.get('bandwidth_mbps', 100) or 100,
         ...]

The metrics table does NOT have columns named 'cpu_load' or
'bandwidth_mbps'. It stores ONE metric per row as:
    metric_name = 'cpu_load'
    metric_value = 45.2

So r.get('cpu_load', 50) ALWAYS returns 50 (the default).
Every retrain trains on 2000 rows of [50, 100, 10, 0, 10, 40, 80].
The model becomes progressively more broken on each retrain.

HOW TO INTEGRATE
----------------
In app.py, find the retrain_worker() function and replace it:

    # DELETE the old retrain_worker() function
    # ADD this at the top of app.py:
    from iis_retrain import make_retrain_worker
    retrain_worker = make_retrain_worker(
        get_rf=lambda: rf_model,
        get_iso=lambda: iso_model,
        set_rf=lambda m: globals().__setitem__('rf_model', m),
        set_iso=lambda m: globals().__setitem__('iso_model', m),
        get_anomaly_count=lambda: anomaly_count,
        reset_anomaly_count=lambda: globals().__setitem__('anomaly_count', 0),
        get_retrain_flag=lambda: _retrain_in_progress,
        set_retrain_flag=lambda v: globals().__setitem__('_retrain_in_progress', v),
        db_conn=_db_conn,
        retrain_lock=_retrain_lock,
        platform_stats=platform_stats,
        retrain_threshold=RETRAIN_THRESHOLD,
    )

Or, simpler — just copy the retrain_worker() function body below
into app.py and replace the existing one.
"""

from __future__ import annotations
import time, threading
import numpy as np
import joblib
from datetime import datetime, timezone
from sklearn.ensemble import RandomForestRegressor, IsolationForest

from iis_features import pivot_metrics_rows


# ── Per-sector model store ─────────────────────────────────────────────────────
# This replaces the single health_model.pkl / anomaly_model.pkl pair.
# Each sector (mining, net, telecom, etc.) gets its own model pair.
# Falls back to the global model if a sector has too few samples.

_SECTOR_MODELS: dict[str, tuple] = {}   # sector -> (rf, iso)
_SECTOR_LOCK   = threading.Lock()


def get_model_for_type(device_type: str, global_rf, global_iso):
    """
    Return (rf, iso) for the given device_type.
    Falls back to global models if no sector-specific model exists yet.
    """
    sector = _map_to_sector(device_type)
    with _SECTOR_LOCK:
        if sector in _SECTOR_MODELS:
            return _SECTOR_MODELS[sector]
    return global_rf, global_iso


def _map_to_sector(device_type: str) -> str:
    dt = (device_type or "generic").lower()
    for sector in ("mining", "cbs", "net", "telecom", "power"):
        if sector in dt:
            return sector
    aliases = {
        "router": "net", "switch": "net", "firewall": "net",
        "pump": "mining", "conveyor": "mining", "ventilation": "mining",
        "base_station": "telecom", "microwave": "telecom",
        "plc": "power", "scada_node": "power", "generator": "power",
    }
    return aliases.get(dt, "generic")


# ── Fixed retrain worker ───────────────────────────────────────────────────────

def retrain_worker_fixed(
    *,
    db_conn,
    retrain_lock,
    platform_stats: dict,
    retrain_threshold: int,
    get_rf,
    get_iso,
    set_rf,
    set_iso,
    get_anomaly_count,
    reset_anomaly_count,
    get_retrain_flag,
    set_retrain_flag,
):
    """
    Fixed retrain loop. Run in a daemon thread exactly as before:
        t = threading.Thread(target=retrain_worker_fixed, kwargs={...}, daemon=True)
        t.start()
    """
    while True:
        time.sleep(60)

        if get_anomaly_count() < retrain_threshold:
            continue

        with retrain_lock:
            if get_retrain_flag():
                continue
            set_retrain_flag(True)

        try:
            platform_stats['last_retrain_attempt'] = datetime.now(timezone.utc).isoformat()

            # Pull recent metrics from DB
            with db_conn() as con:
                rows = [dict(r) for r in con.execute(
                    "SELECT device_id, device_type, metric_name, metric_value, "
                    "health_score, created_at FROM metrics "
                    "ORDER BY created_at DESC LIMIT 5000"
                )]

            if len(rows) < 20:
                print(f"[Retrain] Only {len(rows)} rows — skipping (need ≥20)")
                continue

            # ── THE FIX: use pivot_metrics_rows instead of r.get('cpu_load') ──
            X, y, types = pivot_metrics_rows(rows)

            if len(X) < 20:
                platform_stats['retrain_skip_reason'] = (
                    f"Only {len(X)} pivoted samples after grouping {len(rows)} rows. "
                    "Collectors may not be sending named metric readings yet."
                )
                print(f"[Retrain] {platform_stats['retrain_skip_reason']}")
                continue

            print(f"[Retrain] Training on {len(X)} real samples from {len(rows)} rows")

            # ── Global model (all device types) ───────────────────────────────
            nrf = RandomForestRegressor(n_estimators=150, max_depth=12, random_state=42,
                                        n_jobs=-1, min_samples_leaf=3)
            nrf.fit(X, y)

            healthy_mask = y >= 50
            niso = IsolationForest(n_estimators=150, contamination=0.08, random_state=42)
            niso.fit(X[healthy_mask] if healthy_mask.sum() >= 20 else X)

            joblib.dump(nrf,  'health_model.pkl')
            joblib.dump(niso, 'anomaly_model.pkl')
            set_rf(nrf)
            set_iso(niso)

            # ── Per-sector models (if enough data per sector) ─────────────────
            unique_sectors = set(_map_to_sector(t) for t in types)
            for sector in unique_sectors:
                mask = np.array([_map_to_sector(t) == sector for t in types])
                Xs, ys = X[mask], y[mask]
                if len(Xs) < 30:
                    print(f"[Retrain] Sector '{sector}': only {len(Xs)} samples — skipping sector model")
                    continue
                srf = RandomForestRegressor(n_estimators=100, max_depth=10, random_state=42,
                                            n_jobs=-1, min_samples_leaf=2)
                srf.fit(Xs, ys)
                hmask = ys >= 50
                siso = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
                siso.fit(Xs[hmask] if hmask.sum() >= 10 else Xs)
                joblib.dump(srf,  f'health_model_{sector}.pkl')
                joblib.dump(siso, f'anomaly_model_{sector}.pkl')
                with _SECTOR_LOCK:
                    _SECTOR_MODELS[sector] = (srf, siso)
                print(f"[Retrain] Sector '{sector}' model trained on {len(Xs)} samples")

            reset_anomaly_count()
            platform_stats['last_retrain_success'] = datetime.now(timezone.utc).isoformat()
            platform_stats['retrain_count']        = platform_stats.get('retrain_count', 0) + 1
            platform_stats['model_is_synthetic']   = False   # real data now
            platform_stats['retrain_sample_count'] = int(len(X))
            platform_stats.pop('retrain_skip_reason', None)

            print(f"[Retrain] ✓ Done — {len(X)} samples, sectors: {list(unique_sectors)}")

        except Exception as e:
            print(f"[Retrain] ERROR: {e}")
            import traceback; traceback.print_exc()
        finally:
            with retrain_lock:
                set_retrain_flag(False)


# ── Convenience factory ────────────────────────────────────────────────────────

def make_retrain_worker(**kwargs):
    """
    Returns a zero-argument callable suitable for threading.Thread(target=...).
    Pass all the app.py globals as keyword arguments (see module docstring).
    """
    def _worker():
        retrain_worker_fixed(**kwargs)
    return _worker


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== iis_retrain self-test (pivot only) ===")
    from iis_features import pivot_metrics_rows

    # Simulate what the DB actually returns
    fake_rows = []
    import random, uuid
    devices = [
        ("pump-01",   "mining",  {"vibration_g": 1.2, "bearing_temp_c": 55, "current_amps": 35}),
        ("pump-02",   "mining",  {"vibration_g": 8.5, "bearing_temp_c": 92, "current_amps": 70}),
        ("router-01", "net",     {"cpu_pct": 45, "mem_pct": 60, "packet_loss": 0.1}),
        ("bts-01",    "telecom", {"rssi_dbm": -75, "link_util_pct": 40}),
    ]
    base_ts = "2024-06-01T08:00"
    for did, dtype, metrics in devices:
        hs = random.uniform(50, 95)
        for mn, mv in metrics.items():
            fake_rows.append({
                "device_id": did, "device_type": dtype,
                "created_at": base_ts, "metric_name": mn,
                "metric_value": mv, "health_score": hs,
            })

    X, y, types = pivot_metrics_rows(fake_rows)
    print(f"Pivoted {len(fake_rows)} rows → {len(X)} samples")
    for i in range(len(X)):
        print(f"  [{types[i]:10s}] health={y[i]:.1f}  features={X[i].tolist()}")

    if len(X) >= 2:
        from sklearn.ensemble import RandomForestRegressor
        rf = RandomForestRegressor(n_estimators=10, random_state=42)
        rf.fit(X, y)
        preds = rf.predict(X)
        print(f"\nTest fit OK. Predictions: {preds.tolist()}")
    else:
        print("Not enough samples for test fit — add more fake_rows")
