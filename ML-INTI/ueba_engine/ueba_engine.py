import requests
from datetime import datetime, timedelta
import pytz
import logging

logger = logging.getLogger('UEBA_Engine')

USER_PROFILES = {}

GEOIP_API_URL = "https://ipapi.co/"

def get_location_from_ip(ip_address):
    if ip_address in ["127.0.0.1", "localhost", "::1"]:
        return {"country": "Localhost", "city": "Localhost", "lat": 0, "lon": 0}

    try:
        api_url = f"{GEOIP_API_URL}{ip_address}/json"
        response = requests.get(api_url, timeout=5)

        if response.status_code == 200:
            data = response.json()

            return {
                "country": data.get('country_name', 'Unknown'),
                "city": data.get('city', 'Unknown'),
                "lat": data.get('latitude', 0),
                "lon": data.get('longitude', 0),
                "org": data.get('org', 'Unknown'),
                "asn": data.get('asn', 'Unknown')
            }
        else:
            logger.error(f"[GEOIP ERROR] {ip_address} -> HTTP {response.status_code}")
    
    except Exception as e:
        logger.error(f"[GEOIP FAILED] {ip_address} -> {str(e)}")

    return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}

def format_log(result):
    risk_level = "LOW"
    if result["ueba_score"] >= 70:
        risk_level = "HIGH"
    elif result["ueba_score"] >= 30:
        risk_level = "MEDIUM"

    location = result["current_location"]
    
    log_output = f"""
================= UEBA ANALYSIS =================
User        : {result['username']}
IP Address  : {result['ip']}
Location    : {location['city']}, {location['country']}
Coordinates : ({location['lat']}, {location['lon']})
Risk Score  : {result['ueba_score']} ({risk_level})
=================================================
"""

    if result["anomalies"]:
        log_output += "\n⚠️  Detected Anomalies:\n"
        for a in result["anomalies"]:
            log_output += f"   - {a}\n"
    else:
        log_output += "\n✅ Normal Behavior\n"

    log_output += "=================================================\n"

    return log_output

def haversine(lat1, lon1, lat2, lon2):
    from math import radians, cos, sin, asin, sqrt
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    km = 6371 * c
    return km

def analyze_user_behavior(username, ip_address, timestamp_str):
    # ... (Sisanya dari fungsi analyze_user_behavior tidak perlu diubah) ...
    if not username or not ip_address:
        return {"error": "Username atau IP tidak ada"}
    
    try:
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        timestamp = datetime.now(pytz.utc)

    if username not in USER_PROFILES:
        USER_PROFILES[username] = {
            "seen_ips": set(),
            "seen_locations": set(),
            "last_login_ts": None,
            "last_login_location": None,
            "login_history_hours":[],
        }

    profile = USER_PROFILES[username]
    # Fungsi get_location_from_ip yang baru akan dipanggil di sini
    current_location = get_location_from_ip(ip_address)

    anomalies = []
    anomaly_score = 0

    location_key = f"{current_location['country']}-{current_location['city']}"
    if location_key not in profile["seen_locations"] and profile["seen_locations"]:
        anomalies.append(f"First time login from new location: {location_key}")
        anomaly_score += 30

    if profile["last_login_ts"] and profile["last_login_location"]:
        time_diff = (timestamp - profile["last_login_ts"]).total_seconds() / 3600
        if time_diff > 0:
            distance = haversine(
                profile["last_login_location"]["lat"], profile["last_login_location"]["lon"],
                current_location["lat"], current_location["lon"]
            )

            if distance / time_diff > 900:
                anomalies.append(f"Impossible travel detected: {distance:.2f} km in {time_diff:.2f} hours")
                anomaly_score += 70

    current_hour_utc = timestamp.hour
    if profile["login_history_hours"]:
        avg_hour = sum(profile["login_history_hours"]) / len(profile["login_history_hours"])
        if abs(current_hour_utc - avg_hour) > 8:
            anomalies.append(f"Unusual login time: {current_hour_utc}:00 UTC (normal avg: {avg_hour:.0f}:00 UTC)")
            anomaly_score += 20

    profile ["seen_ips"].add(ip_address)
    profile ["seen_locations"].add(location_key)
    profile ["last_login_ts"] = timestamp
    profile ["last_login_location"] = current_location
    profile ["login_history_hours"].append(current_hour_utc)

    if len(profile["login_history_hours"]) > 30:
        profile["login_history_hours"] = profile["login_history_hours"][-30]

    return {
        "username": username,
        "ip": ip_address,
        "current_location": current_location,
        "anomalies": anomalies,
        "is_anomaly": len(anomalies) > 0,
        "ueba_score": anomaly_score
    }