import os
from dotenv import load_dotenv

DRY_RUN = os.getenv("DRY_RUN", "False").lower() == "true"

MAX_WORKERS = int(os.getenv("MAX_WORKERS", 10))

VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

load_dotenv()

NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
