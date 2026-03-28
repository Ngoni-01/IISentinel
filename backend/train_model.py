import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.preprocessing import MinMaxScaler

np.random.seed(42)
n = 2000

# Normal operation (70% of data)
n_normal = int(n * 0.7)
normal = pd.DataFrame({
    'cpu_load': np.random.uniform(10, 50, n_normal),
    'bandwidth_mbps': np.random.uniform(10, 300, n_normal),
    'latency_ms': np.random.uniform(1, 20, n_normal),
    'packet_loss': np.random.uniform(0, 0.5, n_normal),
    'connected_devices': np.random.randint(5, 30, n_normal),
    'temperature': np.random.uniform(20, 60, n_normal),
    'signal_strength': np.random.uniform(70, 100, n_normal),
})
normal['health_score'] = np.random.uniform(75, 100, n_normal)

# Congestion event (20% of data)
n_congestion = int(n * 0.2)
congestion = pd.DataFrame({
    'cpu_load': np.random.uniform(70, 90, n_congestion),
    'bandwidth_mbps': np.random.uniform(800, 1000, n_congestion),
    'latency_ms': np.random.uniform(50, 200, n_congestion),
    'packet_loss': np.random.uniform(1, 5, n_congestion),
    'connected_devices': np.random.randint(50, 100, n_congestion),
    'temperature': np.random.uniform(60, 80, n_congestion),
    'signal_strength': np.random.uniform(40, 70, n_congestion),
})
congestion['health_score'] = np.random.uniform(35, 60, n_congestion)

# Critical failure (10% of data)
n_critical = n - n_normal - n_congestion
critical = pd.DataFrame({
    'cpu_load': np.random.uniform(90, 100, n_critical),
    'bandwidth_mbps': np.random.uniform(950, 1000, n_critical),
    'latency_ms': np.random.uniform(200, 500, n_critical),
    'packet_loss': np.random.uniform(5, 20, n_critical),
    'connected_devices': np.random.randint(80, 150, n_critical),
    'temperature': np.random.uniform(80, 100, n_critical),
    'signal_strength': np.random.uniform(10, 40, n_critical),
})
critical['health_score'] = np.random.uniform(0, 35, n_critical)

# Combine all scenarios
df = pd.concat([normal, congestion, critical], ignore_index=True)
df = df.sample(frac=1).reset_index(drop=True)

features = ['cpu_load', 'bandwidth_mbps', 'latency_ms',
            'packet_loss', 'connected_devices', 'temperature', 'signal_strength']

X = df[features]
y = df['health_score']

# Train Model 1: RandomForest health score predictor
rf_model = RandomForestRegressor(n_estimators=100, random_state=42)
rf_model.fit(X, y)
joblib.dump(rf_model, 'health_model.pkl')
print("Model 1 saved: health_model.pkl")

# Train Model 2: Isolation Forest anomaly detector
iso_model = IsolationForest(contamination=0.1, random_state=42)
iso_model.fit(X)
joblib.dump(iso_model, 'anomaly_model.pkl')
print("Model 2 saved: anomaly_model.pkl")

# Save feature scaler
scaler = MinMaxScaler()
scaler.fit(X)
joblib.dump(scaler, 'scaler.pkl')
print("Scaler saved: scaler.pkl")

print("\nTraining complete!")
print(f"Total samples: {len(df)}")
print(f"Normal: {n_normal} | Congestion: {n_congestion} | Critical: {n_critical}")