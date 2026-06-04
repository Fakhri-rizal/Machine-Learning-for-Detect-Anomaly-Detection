import threading
from utils.validator import validate_ip
from config.settings import OPNSENSE_FEED_FILE
from utils.logger import setup_logger

logger = setup_logger()
lock = threading.Lock()

def block_ip_opnsense(ip, severity, reason):

    if severity.lower() != "high":
        return
    
    if not validate_ip(ip):
        logger.warning(f"Invalid IP detected: {ip}")
        return
    
    ip = ip.strip()

    try:
        with lock:
            with open(OPNSENSE_FEED_FILE, "a+") as f:
                f.seek(0)
                existing = set(f.read().splitlines())

                if ip in existing:
                    logger.info(f"[OPNsense] IP {ip} already exist")
                    return
                f.write(ip + "\n")

            logger.info(f"[OPNsense] IP {ip} added to blacklist")
    except Exception:
        logger.exception("[OPNsense FEED ERROR]")