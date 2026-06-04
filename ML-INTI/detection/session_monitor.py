from collections import defaultdict
from datetime import timedelta

user_sessions = defaultdict(list)

login_attempts = {}

BF_WINDOW = timedelta(minutes=10)

BF_THRESHOLD = 10