import os

DRY_RUN = os.getenv("DRY_RUN", "False").lower() == "true"

MAX_WORKERS = int(os.getenv("MAX_WORKERS", 10))

VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
