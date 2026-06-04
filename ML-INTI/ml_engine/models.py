from .model_loader import load_models

# Load models sekali saat modul di-import
loaded_models = load_models()
model_if = loaded_models.get("iforest")
model_ocsvm = loaded_models.get("ocsvm")
model_ae = loaded_models.get("autoencoder")
scaler_ocsvm = loaded_models.get("svm_scaler")
scaler_ae = loaded_models.get("ae_scaler")
ae_threshold = loaded_models.get("ae_threshold", 0.1)