import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_MODEL_FILENAME = os.getenv("ML_MODEL_FILENAME", "portscan_detector_model.pkl")
ML_SCALER_FILENAME = os.getenv("ML_SCALER_FILENAME", "scaler.pkl")
ML_MODEL_PATH = os.path.join(BASE_DIR, ML_MODEL_FILENAME)
ML_SCALER_PATH = os.path.join(BASE_DIR, ML_SCALER_FILENAME)

print(ML_MODEL_PATH)
print(ML_SCALER_PATH)
