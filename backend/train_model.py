"""
IISentinel™ — AI Model Training Script
Trains RandomForest (health scorer) + IsolationForest (anomaly detector)
Run once before starting app.py:  python train_models.py
"""

import numpy as np
import joblib
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.preprocessing import StandardScaler

print("IISentinel™ Model Training")
print("══════════════════════════")

# ── FEATURE SCHEMA ────────────────────────────────────────────────────────────
# [cpu_load, bandwidth_mbps, latency_ms, packet_loss,
#  connected_devices, temperature, signal_strength]
# Health score target: 0–100 (higher = healthier)

np.random.seed(42)
N = 3000

def make_dataset(n):
    rows, labels = [], []
    for _ in range(n):
        # Healthy device (70–100)
        if np.random.random() < 0.60:
            cpu  = np.random.uniform(5,  55)
            bw   = np.random.uniform(50, 800)
            lat  = np.random.uniform(1,  45)
            loss = np.random.uniform(0,  0.8)
            devs = np.random.randint(5,  60)
            temp = np.random.uniform(20, 45)
            sig  = np.random.uniform(65, 98)
            score= np.random.uniform(70, 99)
        # Warning device (35–70)
        elif np.random.random() < 0.75:
            cpu  = np.random.uniform(50, 82)
            bw   = np.random.uniform(600,950)
            lat  = np.random.uniform(40, 180)
            loss = np.random.uniform(0.8, 4)
            devs = np.random.randint(1,  20)
            temp = np.random.uniform(44, 72)
            sig  = np.random.uniform(35, 65)
            score= np.random.uniform(35, 69)
        # Critical device (0–35)
        else:
            cpu  = np.random.uniform(82, 100)
            bw   = np.random.uniform(900,1000)
            lat  = np.random.uniform(180,500)
            loss = np.random.uniform(4,  20)
            devs = np.random.randint(0,  5)
            temp = np.random.uniform(72, 110)
            sig  = np.random.uniform(5,  35)
            score= np.random.uniform(2,  34)
        rows.append([cpu, bw, lat, loss, devs, temp, sig])
        labels.append(score)
    return np.array(rows), np.array(labels)

X, y = make_dataset(N)
print(f"Training dataset: {N} samples")
print(f"  Healthy (≥70):  {(y>=70).sum()}")
print(f"  Warning (35-70):{((y>=35)&(y<70)).sum()}")
print(f"  Critical (<35): {(y<35).sum()}")

# ── SCALER ────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, 'scaler.pkl')
print("\n✓ scaler.pkl saved")

# ── RANDOM FOREST HEALTH SCORER ───────────────────────────────────────────────
rf = RandomForestRegressor(
    n_estimators=120,
    max_depth=10,
    min_samples_leaf=3,
    random_state=42,
    n_jobs=-1,
)
rf.fit(X, y)
joblib.dump(rf, 'health_model.pkl')

# Quick accuracy check
from sklearn.metrics import mean_absolute_error
pred = rf.predict(X)
mae  = mean_absolute_error(y, pred)
print(f"✓ health_model.pkl saved  (train MAE: {mae:.2f} points)")

# Feature importance
feat_names = ['cpu_load','bandwidth_mbps','latency_ms','packet_loss',
              'connected_devices','temperature','signal_strength']
importances = sorted(zip(feat_names, rf.feature_importances_),
                     key=lambda x: -x[1])
print("  Feature importances:")
for name, imp in importances:
    bar = '█' * int(imp*40)
    print(f"    {name:<22} {bar} {imp:.3f}")

# ── ISOLATION FOREST ANOMALY DETECTOR ────────────────────────────────────────
# Train on the healthy portion only so it learns what "normal" looks like
X_normal = X[y >= 60]
iso = IsolationForest(
    n_estimators=100,
    contamination=0.08,   # expect ~8% anomalies in production data
    random_state=42,
    n_jobs=-1,
)
iso.fit(X_normal)
joblib.dump(iso, 'anomaly_model.pkl')

# Sanity check
n_anom_in_healthy = (iso.predict(X_normal) == -1).sum()
n_anom_in_critical= (iso.predict(X[y<35])  == -1).sum()
print(f"\n✓ anomaly_model.pkl saved")
print(f"  False positives on healthy data: {n_anom_in_healthy}/{len(X_normal)}")
print(f"  True  positives on critical data:{n_anom_in_critical}/{(y<35).sum()}")

print("""
══════════════════════════════════════════
  Training complete. Files created:
    health_model.pkl
    anomaly_model.pkl
    scaler.pkl
  Now run:  python app.py
══════════════════════════════════════════
""")
