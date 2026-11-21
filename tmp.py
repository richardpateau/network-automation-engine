import os
import json
import requests
from dotenv import load_dotenv
import pynetbox

load_dotenv()

url = os.getenv("NETBOX_URL", "").rstrip("/")
token = os.getenv("NETBOX_TOKEN")

nb = pynetbox.api(url=url, token=token)

vlans = nb.ipam.vlans.all()
devices = nb.dcim.devices.all()
interfaces = nb.dcim.interfaces.all()
vlan_data = [vlan.serialize() for vlan in interfaces]

print(json.dumps(vlan_data, indent=4))