import numpy as np
import pandas as pd
import joblib
import threading
import time
import os
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error
from datetime import datetime

FEATURES = ['cpu_load','bandwidth_mbps','latency_ms',
            'packet_loss','connected_devices','temperature','signal_strength']
MODEL_PATH = 'health_model.pkl'
ISO_PATH = 'anomaly_model.pkl'
SCALER_PATH = 'scaler.pkl'
DRIFT_THRESHOLD = 8.0
MIN_SAMPLES_RETRAIN = 100
RETRAIN_INTERVAL = 300

real_data_buffer = []
drift_errors = []
is_retraining = False
retrain_count = 0
last_retrain = datetime.now()
lock = threading.Lock()

def generate_bootstrap_data(n=1500):
    n_normal = int(n * 0.60)
    n_congest = int(n * 0.20)
    n_degrade = int(n * 0.12)
    n_critical = n - n_normal - n_congest - n_degrade

    def make(cpu, bw, lat, pl, dev, temp, sig, score_range):
        size = locals().get('cpu', (10,50))
        return None

    def block(c,b,l,p,d,t,s,sr,n):
        data = {
            'cpu_load':np.random.uniform(*c,n),
            'bandwidth_mbps':np.random.uniform(*b,n),
            'latency_ms':np.random.uniform(*l,n),
            'packet_loss':np.random.uniform(*p,n),
            'connected_devices':np.random.randint(*d,n),
            'temperature':np.random.uniform(*t,n),
            'signal_strength':np.random.uniform(*s,n),
        }
        df = pd.DataFrame(data)
        df['health_score'] = np.random.uniform(*sr,n)
        return df

    normal    = block((5,50),(10,300),(1,20),(0,0.5),(5,30),(20,60),(70,100),(75,100),n_normal)
    congestion= block((70,90),(800,1000),(80,250),(2,8),(60,120),(65,85),(35,60),(30,60),n_congest)
    degraded  = block((50,75),(400,800),(30,100),(1,3),(30,70),(55,80),(50,70),(45,75),n_degrade)
    critical  = block((90,100),(950,1000),(250,600),(8,25),(80,150),(85,105),(5,30),(0,30),n_critical)

    df = pd.concat([normal,congestion,degraded,critical],ignore_index=True)
    return df.sample(frac=1).reset_index(drop=True)

def train_models(df):
    X = df[FEATURES]
    y = df['health_score']
    X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2,random_state=42)
    rf = RandomForestRegressor(n_estimators=120,max_depth=12,random_state=42,n_jobs=-1)
    rf.fit(X_train,y_train)
    mae = mean_absolute_error(y_test,rf.predict(X_test))
    iso = IsolationForest(contamination=0.1,random_state=42)
    iso.fit(X)
    return rf,iso,mae

def pseudo_label(reading, current_model):
    features = np.array([[
        reading.get('cpu_load',50),
        reading.get('bandwidth_mbps',100),
        reading.get('latency_ms',10),
        reading.get('packet_loss',0),
        reading.get('connected_devices',10),
        reading.get('temperature',40),
        reading.get('signal_strength',80)
    ]])
    predicted = float(current_model.predict(features)[0])
    temp = reading.get('temperature',40)
    packet_loss = reading.get('packet_loss',0)
    cpu = reading.get('cpu_load',50)
    if temp > 90 or packet_loss > 10 or cpu > 95:
        predicted = min(predicted, 25.0)
    elif temp < 60 and packet_loss < 0.5 and cpu < 40:
        predicted = max(predicted, 65.0)
    return max(0.0, min(100.0, predicted))

def detect_drift(predictions, actuals):
    if len(predictions) < 10:
        return False
    errors = [abs(p-a) for p,a in zip(predictions,actuals)]
    recent_error = np.mean(errors[-10:])
    drift_errors.append(recent_error)
    if len(drift_errors) > 50:
        drift_errors.pop(0)
    baseline = np.mean(drift_errors[:-10]) if len(drift_errors) > 10 else recent_error
    drift_detected = recent_error > baseline + DRIFT_THRESHOLD
    if drift_detected:
        print(f"\n[AutoTrainer] Drift detected — error {recent_error:.2f} vs baseline {baseline:.2f}")
    return drift_detected

def retrain_background():
    global is_retraining, retrain_count, last_retrain
    is_retraining = True
    print(f"\n[AutoTrainer] Background retraining started — {len(real_data_buffer)} real samples")
    try:
        bootstrap = generate_bootstrap_data(1000)
        with lock:
            real_df = pd.DataFrame(real_data_buffer[-500:])
        current_model = joblib.load(MODEL_PATH)
        real_df['health_score'] = real_df.apply(
            lambda row: pseudo_label(row.to_dict(), current_model), axis=1
        )
        combined = pd.concat([bootstrap,real_df],ignore_index=True)
        combined = combined.sample(frac=1).reset_index(drop=True)
        new_rf, new_iso, mae = train_models(combined)
        X_eval = real_df[FEATURES]
        y_eval = real_df['health_score']
        old_mae = mean_absolute_error(y_eval, current_model.predict(X_eval))
        new_mae = mean_absolute_error(y_eval, new_rf.predict(X_eval))
        print(f"[AutoTrainer] Old MAE: {old_mae:.2f} | New MAE: {new_mae:.2f}")
        if new_mae <= old_mae + 2.0:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            joblib.dump(current_model, f'health_model_v{ts}.pkl')
            joblib.dump(new_rf, MODEL_PATH)
            joblib.dump(new_iso, ISO_PATH)
            retrain_count += 1
            last_retrain = datetime.now()
            print(f"[AutoTrainer] Model updated — version {retrain_count} deployed")
        else:
            print(f"[AutoTrainer] New model underperforms — keeping current model")
    except Exception as e:
        print(f"[AutoTrainer] Retraining error: {e}")
    finally:
        is_retraining = False

def ingest_reading(reading):
    with lock:
        real_data_buffer.append(reading)
        if len(real_data_buffer) > 2000:
            real_data_buffer.pop(0)

def check_and_retrain():
    global is_retraining
    while True:
        time.sleep(RETRAIN_INTERVAL)
        if is_retraining:
            continue
        with lock:
            buffer_size = len(real_data_buffer)
        if buffer_size >= MIN_SAMPLES_RETRAIN:
            thread = threading.Thread(target=retrain_background, daemon=True)
            thread.start()
        else:
            print(f"[AutoTrainer] Waiting for more data — {buffer_size}/{MIN_SAMPLES_RETRAIN} samples")

def bootstrap_on_startup():
    if not os.path.exists(MODEL_PATH):
        print("[AutoTrainer] No model found — bootstrapping from synthetic data...")
        df = generate_bootstrap_data(1500)
        rf, iso, mae = train_models(df)
        joblib.dump(rf, MODEL_PATH)
        joblib.dump(iso, ISO_PATH)
        print(f"[AutoTrainer] Bootstrap complete — MAE: {mae:.2f}")
    else:
        print("[AutoTrainer] Existing model found — autonomous trainer standing by")

def start_autonomous_trainer():
    bootstrap_on_startup()
    monitor_thread = threading.Thread(target=check_and_retrain, daemon=True)
    monitor_thread.start()
    print(f"[AutoTrainer] Autonomous self-training active — retrains every {RETRAIN_INTERVAL}s when {MIN_SAMPLES_RETRAIN}+ samples available")

if __name__ == '__main__':
    print("IISentinel Autonomous Trainer — standalone test mode")
    print("Simulating 200 readings arriving over time...")
    bootstrap_on_startup()
    model = joblib.load(MODEL_PATH)
    predictions = []
    actuals = []
    for i in range(200):
        reading = {
            'cpu_load': np.random.uniform(10,95),
            'bandwidth_mbps': np.random.uniform(10,1000),
            'latency_ms': np.random.uniform(1,400),
            'packet_loss': np.random.uniform(0,15),
            'connected_devices': np.random.randint(5,150),
            'temperature': np.random.uniform(25,100),
            'signal_strength': np.random.uniform(10,100),
        }
        ingest_reading(reading)
        pred = pseudo_label(reading, model)
        actual = pred + np.random.gauss(0, 5)
        predictions.append(pred)
        actuals.append(actual)
        if i % 20 == 0:
            drift = detect_drift(predictions, actuals)
            print(f"Reading {i+1}/200 — buffer: {len(real_data_buffer)} — drift: {drift}")
    print(f"\nTest complete — {len(real_data_buffer)} readings in buffer")
    print("In production, retraining triggers automatically in background thread")