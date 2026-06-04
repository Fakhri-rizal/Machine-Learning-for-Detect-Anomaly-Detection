import numpy as np
import os
from detection.session_monitor import (
    user_sessions, 
    login_attempts, 
    BF_THRESHOLD, 
    BF_WINDOW
)
from file_analysis.document_analyzer import is_malicious_file
from utils.logger import setup_logger
from detection.payload_analyzer import (
    count_special_chars, 
    count_sql_keywords, 
    payload_entropy
)
from datetime import datetime, timedelta

logger = setup_logger

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

def extract_features(username, password, ip, timestamp=None, location=None, 
                    file_hash=None, file_name=None, file_path=None, role=None, resource=None):
    """
    Extract features from login attempt data for anomaly detection
    
    Args:
        username (str): Username attempting to log in
        password (str): Password provided
        ip (str): IP address of the login attempt
        timestamp (str/datetime, optional): Timestamp of the login attempt. Defaults to current time.
        location (str, optional): Location of the login attempt. Defaults to "".
        file_hash (str, optional): Hash of uploaded file. Defaults to "".
        file_name (str, optional): Name of uploaded file. Defaults to "".
        file_path (str, optional): Path to uploaded file. Defaults to "".
        role (str, optional): User role. Defaults to "".
        resource (str, optional): Resource being accessed. Defaults to "".
    
    Returns:
        numpy.ndarray: Array of features for ML models
    """
    try:
        # Ensure all parameters are strings
        username = username or ""
        password = password or ""
        ip = ip or "0.0.0.0"
        timestamp = timestamp or datetime.now()
        location = location or ""
        file_hash = file_hash or ""
        file_name = file_name or ""
        file_path = file_path or ""
        role = role or ""
        resource = resource or ""

        # --- brute force detector ---
        now = datetime.now()
        login_attempts.setdefault(ip, []).append(now)
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t <= BF_WINDOW]
        bf_flag = 1 if len(login_attempts[ip]) > BF_THRESHOLD else 0

        # --- concurrent login detector ---
        concurrent_login = check_concurrent_login(username, timestamp, ip, location)
        
        # --- malicious file detector ---
        file_malicious = is_malicious_file(file_hash, file_name, file_path)
        
        # --- unauthorized access detector ---
        unauthorized_access = 0
        if role and resource:
            # Simple heuristic: if role is 'student' and accessing 'admin' resources
            if "student" in role.lower() and any(admin in resource.lower() 
                                                for admin in ["admin", "root", "config", "settings"]):
                unauthorized_access = 1

        # --- Web login → fill dataset features ---
        bytes_total = len(username) + len(password)                # approximate – realistic enough
        dur = len(password) / 10                                   # fake duration
        proto_len = 4                                              # "HTTP" length
        state_len = 2                                              # 200 / OK
        ip_len = len(ip)
        url_len = len(username)
        param_count = username.count("=") + username.count("&")
        ent = payload_entropy(username + password)
        sql_kw = count_sql_keywords(username + password)
        special = count_special_chars(username + password)
        username_len = len(username)
        password_len = len(password)

        # Final 17 features (16 features + label)
        features = np.array([[
            bytes_total,     # 0
            dur,             # 1
            proto_len,       # 2
            state_len,       # 3
            ip_len,          # 4
            url_len,         # 5
            param_count,     # 6
            ent,             # 7
            sql_kw,          # 8
            special,         # 9
            bf_flag,         # 10
            concurrent_login, # 11
            file_malicious,   # 12
            username_len,     # 13
            password_len,     # 14
            unauthorized_access, # 15
            0                # 16 label placeholder
        ]], dtype=float)

        return features
    
    except Exception as e:
        logger.error(f"Error extracting features: {str(e)}")
        # Return default features if error occurs
        return np.zeros((1, 17), dtype=float)

def classify_anomaly(features, mse, username):
    """
    Classify anomaly based on extracted features and determine severity
    
    Args:
        features (numpy.ndarray): Feature array
        mse (float): Mean squared error from autoencoder model
        username (str): Username for context
    
    Returns:
        tuple: (list of flags, severity level)
    """
    try:
        # Unpack features
        (
            bytes_total, dur, proto_len, state_len, ip_len,
            url_len, param_count, ent, sql_kw, special, bf_flag, 
            concurrent_login, file_malicious, username_len, password_len, 
            unauthorized_access, label
        ) = features

        flags = []

        # Check for various anomaly indicators
        if bf_flag == 1:
            flags.append("Brute-force terdeteksi")
        if sql_kw > 0:
            flags.append("Keyword SQL mencurigakan")
        if sql_kw > 0 or special > 0:
            flags.append("Karakter berbahaya terdeteksi") 
            if sql_kw == 0 and special > 0:
                flags.append("Kemungkinan percobaan SQL injection")
        if ent > 5:
            flags.append("Payload entropy tinggi (mirip malware encoding)")
        if concurrent_login == 1:
            flags.append("Login ganda dari lokasi berbeda")
        if file_malicious == 1:
            flags.append("File berpotensi malware terdeteksi")
        if unauthorized_access == 1:
            flags.append("Akses tidak sah ke resource terlarang")
        if username_len < 4:
            flags.append("Username terlalu pendek")
        if password_len < 6:
            flags.append("Password terlalu pendek")

        # Determine severity based on flags
        high_severity_flags = [
            "Brute-force terdeteksi",
            "File berpotensi malware terdeteksi",
            "Akses tidak sah ke resource terlarang"
        ]
        
        medium_severity_flags = [
            "Login ganda dari lokasi berbeda",
            "Keyword SQL mencurigakan",
            "Payload entropy tinggi (mirip malware encoding)",
            "Karakter berbahaya terdeteksi",
            "Kemungkinan percobaan SQL injection"
        ]

        if any(flag in flags for flag in high_severity_flags):
            return flags, "high"
        elif any(flag in flags for flag in medium_severity_flags):
            return flags, "medium"
        elif flags:
            return flags, "low"
        else:
            return ["Normal"], "none"
    
    except Exception as e:
        logger.error(f"Error classifying anomaly: {str(e)}")
        return ["Error processing anomaly"], "low"