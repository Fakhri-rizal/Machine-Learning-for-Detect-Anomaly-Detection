import pandas as pd
import numpy as np
import pickle
import os
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from datetime import datetime, timedelta
import hashlib

# -----------------------------
# CONFIG
# -----------------------------
CHUNK_SIZE = 120000         # rows per chunk (adjust jika perlu)
BUFFER_LIMIT = 250000       # rows accumulated untuk melatih AE sekali (batch)
SAMPLE_PER_CHUNK = 5000     # sample rows per chunk untuk koleksi isoforest/ocsvm
MAX_SAMPLES_FOR_ISO = 200000  # limit total sample utk IsolationForest agar RAM aman
MAX_NORMALS_FOR_OCSVM = 100000

DATASETS = [
    "./dataset/UNSW-NB15_1.csv",
    "./dataset/UNSW-NB15_2.csv",
    "./dataset/UNSW-NB15_3.csv",
    "./dataset/UNSW-NB15_4.csv",
    "./dataset/csic_database.csv",
    "./dataset/rba-dataset.csv",
]

os.makedirs("models", exist_ok=True)

# -----------------------------
# Global state for tracking logins
# -----------------------------
user_sessions = defaultdict(list)  # {username: [(timestamp, ip, location), ...]}

# -----------------------------
# Utilities & feature extractors
# -----------------------------
def detect_label_from_row(row):
    """Try to detect label (0 normal, 1 attack). Defaults to 0 if unknown."""
    # common label columns
    for k in ("label", "attack", "attack_cat", "is_attack"):
        if k in row:
            v = row.get(k)
            try:
                iv = int(float(v))
                return 1 if iv != 0 else 0
            except Exception:
                s = str(v).lower()
                if "normal" in s or s in ("0","benign"):
                    return 0
                if "attack" in s or "anomaly" in s or s in ("1","malicious"):
                    return 1
    # fallback: if any column contains suspicious keywords -> mark attack
    joined = " ".join([str(x).lower() for x in row.values()])
    if any(w in joined for w in ("attack","sql","ddos","dos","malware","botnet","injection","xss")):
        return 1
    return 0

def payload_entropy(s):
    # approximate entropy of string s
    if not s:
        return 0.0
    s = str(s)
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    ent = -sum(p * np.log2(p) for p in probs if p > 0)
    return ent

def count_sql_keywords(s):
    if not s:
        return 0
    s = str(s).upper()
    keywords = ("OR","AND","UNION","SELECT","DROP","DELETE","INSERT","UPDATE","WHERE","LIMIT","ORDER")
    return sum(1 for k in keywords if k in s)

def count_special_chars(s):
    if not s:
        return 0
    return sum(1 for c in str(s) if c in ("'", '"', ";", "-", "#", "/", "\\", "%"))

def is_malicious_file(file_hash, file_name=None):
    """Simple heuristic to detect potentially malicious files"""
    if not file_hash:
        return 0
    
    # Check for known malicious file patterns
    suspicious_patterns = [
        ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", 
        ".jar", ".app", ".deb", ".pkg", ".dmg", ".vbs",
        ".js", ".wsf", ".ps1", ".sh", ".php"
    ]
    
    if file_name:
        if any(file_name.lower().endswith(pattern) for pattern in suspicious_patterns):
            return 1
    
    # Check for common malware hashes (simplified example)
    known_malware_hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",  # Example empty file hash
        "44d88612fea8a8f36de82e1278abb02f",  # Example EICAR test hash
    ]
    
    if file_hash.lower() in known_malware_hashes:
        return 1
    
    return 0

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
            # Get all unique locations in the last hour
            locations = set(loc for _, _, loc in user_sessions[username] if loc)
            if len(locations) > 1:
                return 1
                
        return 0
    except Exception:
        return 0

def extract_from_unsw(row):
    try:
        ip = str(row.get("srcip", ""))
        sbytes = float(row.get("sbytes", 0) or 0)
        dbytes = float(row.get("dbytes", 0) or 0)
        dur = float(row.get("dur", 0) or 0)
        proto = str(row.get("proto", ""))
        state = str(row.get("state", ""))
        label = detect_label_from_row(row)
        bytes_total = sbytes + dbytes
        
        # New features
        username = str(row.get("user", row.get("username", "")))
        password = str(row.get("password", ""))
        username_len = len(username)
        password_len = len(password)
        
        # Get timestamp and location if available
        timestamp = row.get("time", row.get("timestamp", datetime.now()))
        location = str(row.get("location", row.get("country", "")))
        
        # Check for concurrent login
        concurrent_login = check_concurrent_login(username, timestamp, ip, location)
        
        # Check for file upload (if available)
        file_hash = str(row.get("file_hash", ""))
        file_name = str(row.get("file_name", ""))
        file_malicious = is_malicious_file(file_hash, file_name)
        
        # Check for unauthorized access
        role = str(row.get("role", ""))
        accessed_resource = str(row.get("resource", row.get("endpoint", "")))
        unauthorized_access = 0
        if role and accessed_resource:
            # Simple heuristic: if role is 'student' and accessing 'admin' resources
            if "student" in role.lower() and any(admin in accessed_resource.lower() 
                                                 for admin in ["admin", "root", "config", "settings"]):
                unauthorized_access = 1

        # Features (consistent order)
        return [
            bytes_total,                 # 0
            dur,                         # 1
            len(proto),                  # 2
            len(state),                  # 3
            len(ip),                     # 4
            0.0,                         # 5 placeholder url_len
            0.0,                         # 6 placeholder param_count
            payload_entropy(""),         # 7 payload_entropy
            count_sql_keywords(""),      # 8 sql_keywords
            count_special_chars(""),     # 9 special_chars
            0,                           # 10 brute_force_flag (not from UNSW)
            concurrent_login,            # 11 concurrent login flag
            file_malicious,              # 12 malicious file flag
            username_len,                # 13 username length
            password_len,                # 14 password length
            unauthorized_access,         # 15 unauthorized access flag
            label                        # 16 label
        ]
    except Exception:
        return None

def extract_from_csic(row):
    # CSIC dataset is HTTP oriented; try to find request/url/payload fields
    try:
        # attempt common column names
        url_candidates = []
        for k in ("url", "uri", "request", "query", "path"):
            if k in row:
                url_candidates.append(str(row.get(k, "")))
        joined_url = " ".join(url_candidates)

        payload_candidates = []
        for k in ("payload","data","post","body","request_body"):
            if k in row:
                payload_candidates.append(str(row.get(k, "")))
        payload = " ".join(payload_candidates) or joined_url

        # label
        label = detect_label_from_row(row)
        
        # New features
        username = str(row.get("user", row.get("username", "")))
        password = str(row.get("password", ""))
        username_len = len(username)
        password_len = len(password)
        
        # Get timestamp and location if available
        timestamp = row.get("time", row.get("timestamp", datetime.now()))
        location = str(row.get("location", row.get("country", "")))
        ip = str(row.get("ip", row.get("client_ip", "")))
        
        # Check for concurrent login
        concurrent_login = check_concurrent_login(username, timestamp, ip, location)
        
        # Check for file upload (if available)
        file_hash = str(row.get("file_hash", ""))
        file_name = str(row.get("file_name", ""))
        file_malicious = is_malicious_file(file_hash, file_name)
        
        # Check for unauthorized access
        role = str(row.get("role", ""))
        accessed_resource = joined_url
        unauthorized_access = 0
        if role and accessed_resource:
            # Simple heuristic: if role is 'student' and accessing 'admin' resources
            if "student" in role.lower() and any(admin in accessed_resource.lower() 
                                                 for admin in ["admin", "root", "config", "settings"]):
                unauthorized_access = 1

        # features
        url_len = len(joined_url)
        param_count = joined_url.count("&") + joined_url.count("=")
        ent = payload_entropy(payload)
        sql_kw = count_sql_keywords(joined_url + " " + payload)
        special = count_special_chars(joined_url + " " + payload)

        # basic placeholders for network features missing in CSIC
        return [
            0.0,        # bytes_total
            0.0,        # dur
            0.0,        # proto_len
            0.0,        # state_len
            0.0,        # ip_len
            url_len,    # url_len
            param_count,# param_count
            ent,        # payload_entropy
            sql_kw,     # sql_keywords
            special,    # special_chars
            0,          # brute_force_flag
            concurrent_login,  # concurrent login flag
            file_malicious,    # malicious file flag
            username_len,      # username length
            password_len,      # password length
            unauthorized_access, # unauthorized access flag
            label
        ]
    except Exception:
        return None

def extract_from_rba(row):
    # RBA (behavior) generic extractor
    try:
        # try to collect basic numeric features if exist
        bytes_total = float(row.get("bytes", 0) or row.get("sbytes", 0) or 0)
        dur = float(row.get("duration", 0) or row.get("dur", 0) or 0)
        proto = str(row.get("proto", ""))
        state = str(row.get("state", ""))
        ip = str(row.get("ip", "")) if "ip" in row else str(row.get("srcip", ""))
        
        # New features
        username = str(row.get("user", row.get("username", "")))
        password = str(row.get("password", ""))
        username_len = len(username)
        password_len = len(password)
        
        # Get timestamp and location if available
        timestamp = row.get("time", row.get("timestamp", datetime.now()))
        location = str(row.get("location", row.get("country", "")))
        
        # Check for concurrent login
        concurrent_login = check_concurrent_login(username, timestamp, ip, location)
        
        # Check for file upload (if available)
        file_hash = str(row.get("file_hash", ""))
        file_name = str(row.get("file_name", ""))
        file_malicious = is_malicious_file(file_hash, file_name)
        
        # Check for unauthorized access
        role = str(row.get("role", ""))
        accessed_resource = str(row.get("resource", row.get("endpoint", "")))
        unauthorized_access = 0
        if role and accessed_resource:
            # Simple heuristic: if role is 'student' and accessing 'admin' resources
            if "student" in role.lower() and any(admin in accessed_resource.lower() 
                                                 for admin in ["admin", "root", "config", "settings"]):
                unauthorized_access = 1

        # maybe contains user/username/password fields -> count suspicious
        joined = " ".join([str(row.get(c, "")) for c in row.keys() if c in ("user","username","password","ua","user_agent")])
        ent = payload_entropy(joined)
        sql_kw = count_sql_keywords(joined)
        special = count_special_chars(joined)

        label = detect_label_from_row(row)

        return [
            bytes_total,        # 0
            dur,                # 1
            len(proto),         # 2
            len(state),         # 3
            len(ip),            # 4
            0.0,                # url_len
            0.0,                # param_count
            ent,                # payload_entropy
            sql_kw,             # sql_keywords
            special,            # special_chars
            0,                  # brute_force_flag
            concurrent_login,   # concurrent login flag
            file_malicious,     # malicious file flag
            username_len,       # username length
            password_len,       # password length
            unauthorized_access, # unauthorized access flag
            label
        ]
    except Exception:
        return None

# choose extractor based on columns present
def extract_generic_from_chunk_row(row):
    if "srcip" in row:
        return extract_from_unsw(row)
    # heuristics for CSIC: presence of 'url' or 'request'
    if any(k in row for k in ("url","uri","request","payload","method")):
        return extract_from_csic(row)
    # fallback: use RBA style
    return extract_from_rba(row)

# -----------------------------
# Autoencoder creation
# -----------------------------
def create_autoencoder(input_dim):
    model = Sequential([
        Dense(32, activation='relu', input_shape=(input_dim,)),
        Dense(16, activation='relu'),
        Dense(8, activation='relu'),
        Dense(16, activation='relu'),
        Dense(32, activation='relu'),
        Dense(input_dim, activation='linear'),
    ])
    model.compile(optimizer=Adam(0.001), loss='mse')
    return model

# -----------------------------
# MAIN training loop
# -----------------------------
buffer_list = []              # accumulate arrays for AE training
samples_for_iso = []          # sampled rows for IsolationForest (features only, no label)
normals_for_ocsvm = []        # accumulate normal rows for OCSVM training (features only)
total_samples_iso = 0

autoencoder = None
scaler_ae = StandardScaler()  # we will use partial_fit on batches
scaler_ae_is_fitted = False

print("[START]", datetime.now())

for file in DATASETS:
    print(f"\n[INFO] Processing {file} ...")
    if not os.path.isfile(file):
        print(f"[WARN] File not found: {file} -- skipping")
        continue

    # read in chunks; set low_memory False to avoid DtypeWarning splitting
    for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE, low_memory=False, dtype=str):
        print(f"[+] Chunk loaded: {len(chunk)} rows from {file}")

        features_rows = []
        # iterate rows safely (row is a Series of strings because dtype=str)
        for _, row in chunk.iterrows():
            # convert Series to dict for easier get()
            row_dict = row.to_dict()
            feat = extract_generic_from_chunk_row(row_dict)
            if feat is not None:
                features_rows.append(feat)

        if len(features_rows) == 0:
            print("[WARN] no valid features extracted in this chunk, skipping")
            continue

        features = np.array(features_rows, dtype=float)  # shape (n, 17) - now 17 features
        # init autoencoder if not exist
        if autoencoder is None:
            input_dim = features.shape[1] - 1  # last col is label, now 16 features
            autoencoder = create_autoencoder(input_dim)
            print(f"[INFO] Autoencoder created with input_dim={input_dim}")

        # split features/label
        X_chunk = features[:, :-1]   # input features (16 features)
        y_chunk = features[:, -1].astype(int)

        # -----------------------------
        # Prepare scaler_ae (partial fit)
        # -----------------------------
        if not scaler_ae_is_fitted:
            # partial_fit expects 2D array; StandardScaler supports partial_fit
            scaler_ae.partial_fit(X_chunk)
            scaler_ae_is_fitted = True
        else:
            scaler_ae.partial_fit(X_chunk)

        # scale X for AE training
        X_scaled = scaler_ae.transform(X_chunk)

        # accumulate into buffer_list for AE training
        buffer_list.append(X_scaled)

        # -----------------------------
        # Sampling for IsolationForest & OneClassSVM (memory-friendly)
        # -----------------------------
        # sample up to SAMPLE_PER_CHUNK rows from this chunk (random sample)
        n_rows = X_chunk.shape[0]
        sample_n = min(SAMPLE_PER_CHUNK, n_rows)
        idx = np.random.choice(n_rows, sample_n, replace=False)
        sampled = features[idx, :]   # includes label as last col

        # add to samples_for_iso (features-only)
        for row_sample in sampled:
            feat_only = row_sample[:-1]
            label = int(row_sample[-1])
            if total_samples_iso < MAX_SAMPLES_FOR_ISO:
                samples_for_iso.append(feat_only)
                total_samples_iso += 1
            # if normal, keep for ocsvm sampling
            if label == 0 and len(normals_for_ocsvm) < MAX_NORMALS_FOR_OCSVM:
                normals_for_ocsvm.append(feat_only)

        # -----------------------------
        # If buffer_list big enough → train AE on concatenated buffer
        # -----------------------------
        current_buffer_rows = sum(b.shape[0] for b in buffer_list)
        print(f"[DEBUG] buffer rows accumulated for AE: {current_buffer_rows}")
        if current_buffer_rows >= BUFFER_LIMIT:
            print("[TRAIN] Training autoencoder on batch ...")
            buffer_cat = np.vstack(buffer_list)
            # shuffle to improve training
            np.random.shuffle(buffer_cat)
            # train AE for a few epochs
            autoencoder.fit(buffer_cat, buffer_cat, epochs=3, batch_size=256, verbose=1)
            # clear buffer
            buffer_list = []

# End for all files
print("\n[INFO] Finished streaming chunks. Finalizing models...")

# If any remaining buffer -> final AE train
if buffer_list:
    print("[TRAIN] Final AE training on remaining buffer ...")
    buffer_cat = np.vstack(buffer_list)
    np.random.shuffle(buffer_cat)
    autoencoder.fit(buffer_cat, buffer_cat, epochs=3, batch_size=256, verbose=1)
    buffer_list = []

# -----------------------------
# IsolationForest training (from sampled data)
# -----------------------------
if len(samples_for_iso) == 0:
    raise SystemExit("[FATAL] No samples collected for IsolationForest. Check extractors / datasets.")

X_iso = np.vstack(samples_for_iso)
print(f"[INFO] Training IsolationForest on {X_iso.shape[0]} sampled rows ...")
isoforest = IsolationForest(contamination=0.05, n_estimators=200, random_state=42, n_jobs=-1)
isoforest.fit(X_iso)

# -----------------------------
# OneClassSVM (train only on normal samples)
# -----------------------------
if len(normals_for_ocsvm) == 0:
    print("[WARN] No normal samples collected for OneClassSVM; skipping OCSVM training.")
    ocsvm = None
    scaler_svm = None
else:
    X_normals = np.vstack(normals_for_ocsvm)
    print(f"[INFO] Training OneClassSVM on {X_normals.shape[0]} normal rows ...")
    scaler_svm = StandardScaler()
    X_normals_scaled = scaler_svm.fit_transform(X_normals)
    ocsvm = OneClassSVM(kernel='rbf', nu=0.05, gamma='scale')
    ocsvm.fit(X_normals_scaled)

# -----------------------------
# Save models & scalers
# -----------------------------
print("[INFO] Saving models to ./models ...")
autoencoder.save("models/autoencoder_final.keras")
pickle.dump(scaler_ae, open("models/scaler_ae.pkl", "wb"))
pickle.dump(isoforest, open("models/isoforest_sampled.pkl", "wb"))
if ocsvm is not None:
    pickle.dump(ocsvm, open("models/ocsvm.pkl", "wb"))
    pickle.dump(scaler_svm, open("models/scaler_svm.pkl", "wb"))

print("[DONE] All done.", datetime.now())