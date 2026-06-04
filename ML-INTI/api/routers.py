from flask import request, jsonify, Response
from config.settings import OPNSENSE_FEED_FILE, UPLOAD_DIR
from datetime import datetime, timedelta
from utils.validator import get_real_ip
from config.settings import auth_failures
import numpy as np
import traceback
import os
from responders.mikrotik import block_ip_mikrotik
from responders.opnsense import block_ip_opnsense
from notifications.telegram import (
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_IDS,
    send_telegram_notification
)
from file_analysis.document_analyzer import (
    calculate_file_hash,
    is_malicious_file
)
from utils.logger import setup_logger, color_text
from detection.analyzer import extract_features, classify_anomaly
from ml_engine.models import (
    model_if, model_ocsvm, model_ae, 
    scaler_ocsvm, scaler_ae, ae_threshold
)

logger = setup_logger()

def predict_with_models(X):
    """Helper function to make predictions with all models"""
    # Initialize predictions
    if_pred = 0
    oc_pred = 0
    ae_pred = 0
    mse = 0.0

    # Isolation Forest
    if model_if is not None:
        try:
            if_pred = int(model_if.predict(X)[0] == -1)
            logger.debug(f"Isolation Forest prediction: {if_pred}")
        except Exception as e:
            logger.error(f"Error in Isolation Forest prediction: {str(e)}")
            if_pred = 0

    # OneClassSVM
    if model_ocsvm is not None and scaler_ocsvm is not None:
        try:
            oc_scaled = scaler_ocsvm.transform(X)
            oc_pred = int(model_ocsvm.predict(oc_scaled)[0] == -1)
            logger.debug(f"OneClassSVM prediction: {oc_pred}")
        except Exception as e:
            logger.error(f"Error in OneClassSVM prediction: {str(e)}")
            oc_pred = 0

    # Autoencoder
    if model_ae is not None and scaler_ae is not None:
        try:
            ae_scaled = scaler_ae.transform(X)
            recon = model_ae.predict(ae_scaled, verbose=0)
            mse = float(np.mean(np.square(ae_scaled - recon)))
            ae_pred = int(mse > ae_threshold)
            logger.debug(f"Autoencoder MSE: {mse}, prediction: {ae_pred}")
        except Exception as e:
            logger.error(f"Error in Autoencoder prediction: {str(e)}")
            ae_pred = 0
            mse = 0.0

    # Voting System (2 of 3)
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

def register_routes(app):

    @app.route("/alert", methods=["POST"])
    def alert():
        data = request.json
        ip = data.get("ip")
        severity = data.get("severity")
        reason = data.get("reason")

        block_ip_opnsense(ip, severity, reason)

        if severity == "high":
            block_ip_mikrotik(ip, reason)

        return jsonify({"status": "processed"})
    
    @app.route("/detect", methods=["POST"])
    def detect():
        try:
            data = request.json
            username = data.get("username", "")
            password = data.get("password", "")
            ip = get_real_ip(request)
            timestamp = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            location = data.get("location", "")
            file_hash = data.get("file_hash", "")
            file_name = data.get("file_name", "")
            file_path = data.get("file_path", "")
            role = data.get("role", "")
            resource = data.get("resource", "")

            is_auth_failure = data.get("auth_failed", False)
            
            if is_auth_failure:
                now = datetime.now()
                auth_failures[ip].append(now)
                # Bersihkan kegagalan yang sudah lama (misal > 30 menit)
                auth_failures[ip] = [t for t in auth_failures[ip] if now - t <= timedelta(minutes=30)]
                
                logger.info(f"[AUTH FAILURE] IP {ip} gagal login. Total kegagalan: {len(auth_failures[ip])}")

            logger.debug(f"Received request: username={username}, ip={ip}")

            features = extract_features(
                username, password, ip, timestamp, location, 
                file_hash, file_name, file_path, role, resource
            )

            logger.debug(f"Extracted features shape: {features.shape}")

            # 16 feature input for ML (exclude label)
            X = features[:, :-1]
            logger.debug(f"Input features shape: {X.shape}")

            # Get predictions from all models
            prediction_results = predict_with_models(X)
            
            # Log results
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if prediction_results["final_decision"] == 1:
                detail, severity = classify_anomaly(features[0], prediction_results["mse_value"], username)

                if severity == "high":
                    try:
                        block_ip_mikrotik(ip, reason="IDS ML High Severity")
                    except Exception as e:
                        logger.warning(f"[MIKROTIK SKIPPED] {e}")

                    # 2️⃣ OPNsense (perimeter/external)
                    block_ip_opnsense(
                        ip=ip,
                        severity=severity,
                        reason="ML detected high severity attack"
                    )

                message = f"""
                    *⚠️ ANOMALI TERDETEKSI* 
                    *Severity:* {severity.upper()}
                    *Waktu:* {timestamp_str}
                    *IP:* {ip}
                    *User:* {username}
                    *Detail:* {', '.join(detail)}
                                """

                send_telegram_notification(
                    message=message,
                    chat_ids=TELEGRAM_CHAT_IDS,
                    token=TELEGRAM_BOT_TOKEN
                )

                if severity == "high":
                    detail_color = 'red'
                elif severity == "medium":
                    detail_color = 'yellow'
                else:
                    detail_color = 'green'
            
                logger.info(f"[ANOMALY] {timestamp_str} — IP: {ip} — User: {username} — Severity: {color_text(severity.upper(), detail_color)}")
                for d in detail:
                    logger.info(f"  ↳ {color_text(d, detail_color)}")
            else:
                logger.info(f"[{color_text('NORMAL', 'green')}] {timestamp_str} — IP: {ip} — User: {username}")

            # JSON output
            return jsonify({
                **prediction_results,
                "severity": severity if prediction_results["final_decision"] else "none",
                "details": detail if prediction_results["final_decision"] else ["Normal"],
                "features_used": features.tolist()
            })
        
        except Exception as e:
            logger.error(f"Error in /detect endpoint: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": "Internal server error",
                "message": str(e)
            }), 500
        
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "service": "ml-detection",
            "status": "ok",
            "models": {
                "isolation_forest": model_if is not None,
                "ocsvm": model_ocsvm is not None,
                "autoencoder": model_ae is not None
            }
        }), 200
    
    @app.route("/upload", methods=["POST"])
    def upload_file():
        try:
            if 'file' not in request.files:
                return jsonify({"error": "No file part"}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({"error": "No selected file"}), 400
            
            # Pastikan direktori upload ada
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            
            file = request.files['file']
            save_path = os.path.join(UPLOAD_DIR, file.filename) 
            file.save(save_path)

            if file:
                # Calculate file hash
                file_hash = calculate_file_hash(save_path)
                
                # Check if file is malicious
                is_malicious = is_malicious_file(file_hash, file.filename, save_path)
                
                # Extract features for ML models
                features = extract_features(
                    username=request.form.get("username", ""),
                    password=request.form.get("password", ""),
                    ip=request.form.get("ip", "unknown"),
                    timestamp=request.form.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    location=request.form.get("location", ""),
                    file_hash=file_hash,
                    file_name=file.filename,
                    file_path=save_path,
                    role=request.form.get("role", ""),
                    resource=request.form.get("resource", "")
                )
                
                X = features[:, :-1]
                
                # Get predictions from all models
                prediction_results = predict_with_models(X)
                
                # Classify anomaly
                if prediction_results["final_decision"] == 1:
                    detail, severity = classify_anomaly(features[0], prediction_results["mse_value"], request.form.get("username", ""))
                else:
                    detail, severity = ["Normal"], "none"
                
                # Clean up - remove the temporary file
                try:
                    os.remove(save_path)
                except Exception as e:
                    logger.error(f"Error removing temporary file: {str(e)}")
                
                return jsonify({
                    **prediction_results,
                    "severity": severity,
                    "details": detail,
                    "file_hash": file_hash,
                    "is_malicious": bool(is_malicious)
                })
        
        except Exception as e:
            logger.error(f"Error in /upload endpoint: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                "error": "Internal server error",
                "message": str(e)
            }), 500

    @app.route("/opnsense_feed", methods=["GET"])
    def opnsense_feed():
        try:
            with open(OPNSENSE_FEED_FILE) as f:
                return Response(f.read(), mimetype="text/plain")
        except FileNotFoundError:
            return Response("", mimetype="text/plain")