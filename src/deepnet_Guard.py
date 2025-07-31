import os
import time
import requests
import pandas as pd
import numpy as np
import tensorflow.lite as tflite
import concurrent.futures
from datetime import datetime
from sklearn.preprocessing import MinMaxScaler

# Paths
ddos_model_path = "src/Models/Trained-Models/dos_attack_model.tflite"
port_scan_model_path = "src/Models/Trained-Models/port_scan_model.tflite"
log_file_ddos = "logs/ddos_log.csv"
log_file_portscan = "logs/portscan_log.csv"

# Features
ddos_features = [
    'Flow Bytes/s', 'Total Fwd Packet', 'Packet Length Std', 
    'SYN Flag Count', 'ACK Flag Count', 'FIN Flag Count', 'PSH Flag Count', 
    'RST Flag Count', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 
    'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Min', 
    'Fwd IAT Max', 'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Total', 
    'Bwd IAT Min', 'Bwd IAT Max', 'Bwd IAT Mean', 'Bwd IAT Std', 
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 
    'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
    'Down/Up Ratio', 'Average Packet Size', 'Fwd Segment Size Avg'
]

port_scan_features = [
    'Flow Packets/s', 'SYN Flag Count', 'Flow IAT Mean', 'Subflow Fwd Packets', 
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Fwd Init Win Bytes',
    'Bwd Init Win Bytes', 'Fwd Seg Size Min', 'Active Min', 'Active Mean', 'Active Max', 
    'Active Std', 'Idle Min', 'Idle Mean', 'Idle Max', 'Idle Std', 'Fwd Act Data Pkts', 
    'Fwd Seg Size Min'
]

def fetch_network_data(url="http://localhost:8000/extract_features"):
    try:
        response = requests.get(url)
        if response.status_code == 200 and "flows" in response.json():
            return pd.DataFrame(response.json()["flows"])
    except Exception as e:
        print(f"[ERROR] Failed to fetch data: {e}")
    return pd.DataFrame()

def create_sequences(data: pd.DataFrame, feature_list: list, scaler: MinMaxScaler, sequence_length: int):
    if data is None or len(data) < sequence_length:
        return None
    selected_data = data[feature_list].copy()
    scaled = scaler.fit_transform(selected_data)
    return np.expand_dims(scaled[-sequence_length:], axis=0).astype(np.float32)

def run_tflite_model(interpreter, input_data: np.ndarray) -> float:
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    interpreter.set_tensor(input_details[0]['index'], input_data)
    interpreter.invoke()
    return float(interpreter.get_tensor(output_details[0]['index'])[0][0])

def load_tflite_model(model_path: str):
    interpreter = tflite.Interpreter(model_path=model_path)
    interpreter.allocate_tensors()
    return interpreter

def classify_threat(score: float) -> str:
    if score < 0.4:
        return "NEUTRAL"
    elif score >= 0.4 and score <= 0.7:
        return "MODERATE"
    else:
        return "ATTACK"

def log_prediction(log_path, threat_type, label, output_score, shape):
    with open(log_path, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{timestamp},{threat_type},{label},{output_score},{shape}\n")

def ddos_detection(df, ddos_interpreter, scaler):
    seq = create_sequences(df, ddos_features, scaler, 15)
    if seq is None:
        return "[DDoS] Insufficient data"
    score = run_tflite_model(ddos_interpreter, seq)
    label = classify_threat(score)
    log_prediction(log_file_ddos, "DDoS", label, score, seq.shape)
    return f"DDoS: {label} ({score})"

def portscan_detection(df, port_scan_interpreter, scaler):
    seq = create_sequences(df, port_scan_features, scaler, 15)
    if seq is None:
        return "[PortScan] Insufficient data"
    score = run_tflite_model(port_scan_interpreter, seq)
    label = classify_threat(score)
    log_prediction(log_file_portscan, "PortScan", label, score, seq.shape)
    return f"PortScan: {label} ({score})"

# Load interpreters
ddos_interpreter = load_tflite_model(ddos_model_path)
port_scan_interpreter = load_tflite_model(port_scan_model_path)
scaler_ddos = MinMaxScaler()
scaler_portscan = MinMaxScaler()

spinner = ['-', '\\', '|', '/']
i = 0

if __name__ == "__main__":
    print("Starting real-time detection...\n")

    while True:
        df = fetch_network_data()
        if df.empty or len(df) < 15:
            print("Waiting for enough flow data... ", end='\r')
            time.sleep(1)
            continue

        with concurrent.futures.ThreadPoolExecutor() as executor:
            f1 = executor.submit(ddos_detection, df, ddos_interpreter, scaler_ddos)
            f2 = executor.submit(portscan_detection, df, port_scan_interpreter, scaler_portscan)

            ddos_result = f1.result()
            portscan_result = f2.result()

        spin = spinner[i % len(spinner)]
        print(f"Detecting {spin} | {ddos_result} | {portscan_result}     ", end='\r')
        i += 1
        time.sleep(1)
