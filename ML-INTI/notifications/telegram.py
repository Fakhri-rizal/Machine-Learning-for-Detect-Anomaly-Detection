import requests
from utils.logger import setup_logger

logger = setup_logger()

TELEGRAM_BOT_TOKEN = "8007280791:AAGSkx_KwPdTForuZfEQhbCPii3G9CPGu-M"

TELEGRAM_CHAT_IDS = [
    "5085281646",
#    "5908266524",
#    "1830588752"
]

def send_telegram_notification(message, chat_ids=None, token=None):
    token = token or TELEGRAM_BOT_TOKEN
    chat_ids = chat_ids or TELEGRAM_CHAT_IDS

    if not chat_ids or not token:
        logger.error("Telegram chat_ids or token not set.")
        return
    
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    for chat_id in chat_ids:
        payload = {
            "chat_id": chat_id.strip(),
            "text": message,
            "parse_mode": "Markdown"
        }

        try:
            response = requests.post(url, json=payload, timeout=5)

            if response.status_code != 200:
                logger.error(f"Failed send to {chat_id}: {response.text}")

            else:
                logger.info(f"Telegram sent to {chat_id}")

        except Exception as e:
            logger.error(f"Telegram error ({chat_id}): {str(e)}")