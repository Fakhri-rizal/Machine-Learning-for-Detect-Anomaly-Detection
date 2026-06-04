import requests
from datetime import datetime
from utils.logger import setup_logger
from config.settings import NGINX_FAIL2BAN_API_URL

logger = setup_logger()


def block_ip_nginx(ip, reason):

    try:

        payload = {

            "ip": ip,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }

        response = requests.post(
            NGINX_FAIL2BAN_API_URL,
            data=payload,
            timeout=5
        )

        if response.status_code == 200:

            logger.info(f"[NGINX] IP {ip} blocked")

        else:

            logger.error(f"[NGINX ERROR] {response.text}")

    except Exception as e:

        logger.error(f"[NGINX FAIL2BAN ERROR] {str(e)}")