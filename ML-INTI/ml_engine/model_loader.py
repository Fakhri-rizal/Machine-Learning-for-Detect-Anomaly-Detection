import pickle
from tensorflow.keras.models import load_model
from utils.logger import setup_logger

logger = setup_logger()


def load_models():

    models = {}

    try:
        with open("models/isoforest_sampled.pkl", "rb") as f:
            models["iforest"] = pickle.load(f)
        logger.info("Isolation Forest model loaded successfully")

    except Exception as e:
        logger.error(f"Error loading Isolation Forest: {str(e)}")
        models["iforest"] = None


    try:
        with open("models/ocsvm.pkl", "rb") as f:
            models["ocsvm"] = pickle.load(f)
        logger.info("OneClassSVM model loaded successfully")

    except Exception as e:
        logger.error(f"Error loading OCSVM: {str(e)}")
        models["ocsvm"] = None


    try:
        with open("models/scaler_svm.pkl", "rb") as f:
            models["svm_scaler"] = pickle.load(f)
        logger.info("SVM scaler loaded successfully")

    except Exception as e:
        logger.error(f"Error loading SVM scaler: {str(e)}")
        models["svm_scaler"] = None


    try:
        models["autoencoder"] = load_model("models/autoencoder_final.keras")
        logger.info("Autoencoder model loaded successfully")

    except Exception as e:
        logger.error(f"Error loading Autoencoder: {str(e)}")
        models["autoencoder"] = None


    try:
        with open("models/scaler_ae.pkl", "rb") as f:
            models["ae_scaler"] = pickle.load(f)

        logger.info("AE scaler loaded successfully")

    except Exception as e:

        logger.error(f"Error loading AE scaler: {str(e)}")
        models["ae_scaler"] = None


    models["ae_threshold"] = 0.1

    return models