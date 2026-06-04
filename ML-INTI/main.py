from ml_engine.model_loader import load_models
from file_analysis.document_analyzer import (
    extract_text_from_pdf,
    extract_text_from_docx,
    is_malicious_file_content
)
from detection.session_monitor import (
    user_sessions,
    login_attempts,
    BF_THRESHOLD,
    BF_WINDOW
)
from detection.payload_analyzer import (
    count_special_chars,
    count_sql_keywords,
    payload_entropy
)
from ueba_engine.ueba_engine import analyze_user_behavior
from detection.analyzer import extract_features, classify_anomaly
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from api.routers import register_routes
from utils.logger import setup_logger
from config.settings import CERT_DIR
from flask import Response
import numpy as np
import logging
import json
import ssl
import os
import pytz

app = Flask(__name__)

logger = setup_logger()

# Load models dan simpan ke variabel global
loaded_models = load_models()
model_if = loaded_models.get("iforest")
model_ocsvm = loaded_models.get("ocsvm")
model_ae = loaded_models.get("autoencoder")
scaler_ocsvm = loaded_models.get("svm_scaler")
scaler_ae = loaded_models.get("ae_scaler")
ae_threshold = loaded_models.get("ae_threshold", 0.1)

register_routes(app)

def predict_with_models(X):
    """Helper function to make predictions with all models"""
    if_pred = 0
    oc_pred = 0
    ae_pred = 0
    mse = 0.0

    if model_if is not None:
        try:
            if_pred = int(model_if.predict(X)[0] == -1)
        except Exception as e:
            logger.error(f"Error in Isolation Forest prediction: {str(e)}")
            if_pred = 0

    if model_ocsvm is not None and scaler_ocsvm is not None:
        try:
            oc_scaled = scaler_ocsvm.transform(X)
            oc_pred = int(model_ocsvm.predict(oc_scaled)[0] == -1)
        except Exception as e:
            logger.error(f"Error in OneClassSVM prediction: {str(e)}")
            oc_pred = 0

    if model_ae is not None and scaler_ae is not None:
        try:
            ae_scaled = scaler_ae.transform(X)
            recon = model_ae.predict(ae_scaled, verbose=0)
            mse = float(np.mean(np.square(ae_scaled - recon)))
            ae_pred = int(mse > ae_threshold)
        except Exception as e:
            logger.error(f"Error in Autoencoder prediction: {str(e)}")
            ae_pred = 0
            mse = 0.0

    votes = if_pred + oc_pred + ae_pred
    final_decision = int(votes >= 2)
    
    return {
        "final_decision": final_decision,
        "mse_value": mse,
        "model_votes": {
            "isolation_forest": "anomaly" if if_pred else "normal",
            "one_class_svm": "anomaly" if oc_pred else "normal",
            "autoencoder": "anomaly" if ae_pred else "normal",
        }
    }


def check_concurrent_login(username, timestamp, ip, location):
    """Check if same user logged in from different locations at similar times"""
    if not username or not timestamp:
        return 0
    
    try:
        # Parse timestamp (handle different formats)
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    # Fallback to current time if parsing fails
                    timestamp = datetime.now()
        
        # Add current session
        user_sessions[username].append((timestamp, ip, location))
        
        # Clean old sessions (older than 1 hour)
        hour_ago = timestamp - timedelta(hours=1)
        user_sessions[username] = [
            (ts, ip, loc) for ts, ip, loc in user_sessions[username]
            if ts >= hour_ago
        ]
        
        # Check for concurrent sessions from different locations
        if len(user_sessions[username]) > 1:
            locations = set(loc for _, _, loc in user_sessions[username] if loc)
            
            if len(locations) > 1:
                logger.info(
                    f"Concurrent login detected for user {username} from locations: {locations}"
                )
                return 1
        
        return 0
    
    except Exception as e:
        logger.error(f"Error checking concurrent login: {str(e)}")
        return 0


@app.route('/analyze-integrated', methods=['POST'])
def analyze_integrated_request():
    """
    Endpoint ORKESTRATOR UTAMA yang menggabungkan analisis mendalam dan UEBA.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    # --- Ekstrak Data dari Request ---
    username = data.get('username')
    ip_address = data.get('ip')
    timestamp_str = data.get('timestamp', datetime.now(pytz.utc).isoformat())
    payload = data.get('payload', '')
    # Data tambahan yang mungkin dikirim untuk analisis mendalam
    file_hash = data.get("file_hash", "")
    file_name = data.get("file_name", "")
    role = data.get("role", "user")

    # --- INISIALISASI HASIL ---
    final_risk_score = 0
    alerts = []
    
    # --- FASE 1: ANALISIS MENDALAM (DEEP ANALYSIS) ---
    # Ini adalah logika yang sebelumnya ada di /detect
    try:
        features = extract_features(
            username, "", ip_address, timestamp_str, "", 
            file_hash, file_name, "", role, payload
        )
        X = features[:, :-1] 
        
        deep_analysis_results = predict_with_models(X)

        if deep_analysis_results["final_decision"] == 1:
            detail, severity = classify_anomaly(features[0], deep_analysis_results["mse_value"], username)
            
            # Berikan skor berdasarkan tingkat keparahan
            if severity == "high":
                final_risk_score += 70
            elif severity == "medium":
                final_risk_score += 40
            else: # low
                final_risk_score += 20

            alerts.append(f"Deep Analysis Alert: {', '.join(detail)} (Severity: {severity})")

    except Exception as e:
        logger.error(f"Error during deep analysis phase: {str(e)}")
        deep_analysis_results = {"final_decision": 0, "severity": "none", "details": ["Error in analysis"]}

    # --- FASE 2: ANALISIS PERILAKU (UEBA) ---
    ueba_results = analyze_user_behavior(username, ip_address, timestamp_str)
    if "error" in ueba_results:
        logger.warning(f"UEBA analysis failed: {ueba_results['error']}")
        ueba_results = {"is_anomaly": False, "ueba_score": 0, "anomalies": []}

    # Tambahkan skor dan alert dari UEBA
    if ueba_results.get("is_anomaly"):
        final_risk_score += ueba_results.get("ueba_score", 0)
        alerts.extend(ueba_results.get("anomalies"))

    # --- FASE 3: GABUNGKAN HASIL DAN TENTUKAN RISIKO AKHIR ---
    risk_level = "Low"
    if final_risk_score > 80:
        risk_level = "Critical"
    elif final_risk_score > 50:
        risk_level = "High"
    elif final_risk_score > 20:
        risk_level = "Medium"

    # --- KEMBALIKAN RESPONSE JSON ---
    response = {
        "timestamp": timestamp_str,
        "user": username,
        "ip": ip_address,
        "risk_level": risk_level,
        "risk_score": final_risk_score,
        "analysis": {
            "deep_analysis": deep_analysis_results, # Hasil dari /detect
            "ueba_results": ueba_results
        },
        "alerts": alerts
    }
    
    # --- LOGGING ---
    server_processing_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if final_risk_score > 0:
        print(f"\n[{server_processing_time}] ALERT DETECTED - User: {username}, IP: {ip_address}, Risk: {risk_level} (Score: {final_risk_score})")
        print(json.dumps(response, indent=2))
        print("-" * 80)
    else:
        print(f"[{server_processing_time}] OK - User: {username}, IP: {ip_address}, Risk: {risk_level}")

    return jsonify(response)




# if __name__ == "__main__":
#     # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

#     # context.load_cert_chain(
#     #     certfile=os.path.join(os.path.dirname(__file__), "sertif", "ml-server.crt"),
#     #     keyfile=os.path.join(os.path.dirname(__file__), "sertif", "ml-server.key")
#     # )

#     # # context.load_verify_locations(
#     # #     cafile=os.path.join(CERT_DIR, "ml-server-chain.crt")
#     # # )

#     # context.verify_mode = ssl.CERT_NONE

#     # logger.info("SAWIT-IDS API Started")

if __name__ == "__main__":

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    context.load_cert_chain(
        certfile=os.path.join(CERT_DIR, "ml-server.crt"),
        keyfile=os.path.join(CERT_DIR, "ml-server.key")
    )

    logger.info("SAWIT-IDS API Started")

    app.run(
        host="0.0.0.0",
        port=5500,
        ssl_context=context,
        debug=False
    )

    # app.run(
    #     host="0.0.0.0", 
    #     port=5500, 
    #     ssl_context=context, 
    #     debug=False
    # )