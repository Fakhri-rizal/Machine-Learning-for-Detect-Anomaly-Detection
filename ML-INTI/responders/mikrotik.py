from librouteros import connect
from utils.logger import setup_logger
from config.settings import *

logger = setup_logger()

def block_ip_mikrotik(ip, reason="Security High"):

    try:

        ip = ip.strip()

        logger.info(f"[IDS] Mengirim block IP [{ip}] ke MikroTik")

        api = connect(
            host=MIKROTIK_IP,
            username=MIKROTIK_USER,
            password=MIKROTIK_PASS,
            port=MIKROTIK_PORT
        )

        list(api(
            '/ip/firewall/address-list/add',
            list='BLACKLIST_IDS',
            address=ip,
            comment=reason
        ))

    except Exception as e:

        logger.error(f"[MIKROTIK ERROR] {str(e)}")