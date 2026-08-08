import pynetbox
from src.core.settings import NETBOX_URL, NETBOX_TOKEN


def get_netbox():
    return pynetbox.api(
        url=NETBOX_URL,
        token=NETBOX_TOKEN,
    )