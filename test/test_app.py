import pytest
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from deepnet_Guard import create_sequences, classify_threat, run_tflite_model

class DummyInterpreter:
    def __init__(self, output=0.8):
        self.output = output
    def allocate_tensors(self):
        pass
    def get_input_details(self):
        return [{"index": 0}]
    def get_output_details(self):
        return [{"index": 0}]
    def set_tensor(self, index, value):
        self.input = value
    def invoke(self):
        pass
    def get_tensor(self, index):
        return np.array([[self.output]])

@pytest.fixture
def mock_dataframe():
    return pd.DataFrame([{
        'Flow Bytes/s': 12345,
        'Total Fwd Packet': 50,
        'Packet Length Std': 15,
        'SYN Flag Count': 5,
        'ACK Flag Count': 10,
        'FIN Flag Count': 2,
        'PSH Flag Count': 3,
        'RST Flag Count': 1,
        'Flow Packets/s': 100,
        'Flow IAT Mean': 10,
        'Flow IAT Std': 1,
        'Flow IAT Max': 15,
        'Flow IAT Min': 5,
        'Fwd IAT Total': 1000,
        'Fwd IAT Min': 2,
        'Fwd IAT Max': 20,
        'Fwd IAT Mean': 7,
        'Fwd IAT Std': 1,
        'Bwd IAT Total': 500,
        'Bwd IAT Min': 2,
        'Bwd IAT Max': 10,
        'Bwd IAT Mean': 4,
        'Bwd IAT Std': 0.5,
        'Fwd PSH Flags': 1,
        'Bwd PSH Flags': 0,
        'Fwd URG Flags': 0,
        'Bwd URG Flags': 0,
        'Packet Length Min': 60,
        'Packet Length Max': 1500,
        'Packet Length Mean': 700,
        'Down/Up Ratio': 0.5,
        'Average Packet Size': 750,
        'Fwd Segment Size Avg': 300,
    }] * 20)  # 20 rows

def test_create_sequence(mock_dataframe):
    scaler = MinMaxScaler()
    sequence = create_sequences(mock_dataframe, mock_dataframe.columns.tolist(), scaler, sequence_length=15)
    assert sequence.shape == (1, 15, len(mock_dataframe.columns))

def test_classify_threat():
    assert classify_threat(0.2) == "NEUTRAL"
    assert classify_threat(0.5) == "MODERATE"
    assert classify_threat(0.8) == "ATTACK"

def test_run_tflite_model():
    dummy = DummyInterpreter(output=0.85)
    dummy.allocate_tensors()
    dummy.set_tensor(0, np.ones((1, 15, 33)).astype(np.float32))
    dummy.invoke()
    score = run_tflite_model(dummy, np.ones((1, 15, 33), dtype=np.float32))
    assert 0 <= score <= 1
