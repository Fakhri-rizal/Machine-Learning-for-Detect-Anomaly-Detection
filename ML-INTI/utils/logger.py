import logging

def color_text(text, color):
    colors = {
        'green': '\033[92m]',
        'yellow': '\033[93m',
        'red': '\033[91m',
        'reset': '\033[0m'
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

def setup_logger():
    logger = logging.getLogger("SAWIT-IDS")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)

    logger.addHandler(ch)

    logger.propagate = False

    return logger