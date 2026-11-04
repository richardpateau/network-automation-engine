import os
from pathlib import Path

import pynetbox
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


def get_netbox_client():
    netbox_url = os.getenv("NETBOX_URL")
    netbox_token = os.getenv("NETBOX_TOKEN")

    return pynetbox.api(
        url=netbox_url,
        token=netbox_token,
    )
