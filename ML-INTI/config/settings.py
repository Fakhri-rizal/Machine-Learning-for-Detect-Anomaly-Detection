from collections import defaultdict
import os

auth_failures = defaultdict(list)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CERT_DIR = os.path.join(BASE_DIR, "sertif")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DATA_DIR = os.path.join(BASE_DIR, "data")

OPNSENSE_FEED_FILE = os.path.join(DATA_DIR, "opnsense_blacklist.txt")

# Threshold
AUTH_FAILURE_THRESHOLD = 3

# Mikrotif Config
MIKROTIK_IP = os.getenv("MIKROTIK_IP", "192.168.8.1")
MIKROTIK_USER = os.getenv("MIKROTIK_USER", "rks-408")
MIKROTIK_PASS = os.getenv("MIKROTIK_PASS", "rks-408")
MIKROTIK_PORT = os.getenv("MIKROTIK_PORT", 8728)

# Fail2ban API
NGINX_FAIL2BAN_API_URL = os.getenv(
    "NGINX_FAIL2BAN_API_URL",
    "http://100.71.98.79/api/fail2ban/block"
)