from contextlib import contextmanager
import requests
from netmiko import ConnectHandler
from ncclient import manager

def get_session(device):
    transport = device.get("transport")

    if transport == "RESTCONF":
        return create_restconf_session(device)

    if transport == "NETMIKO":
        return create_ssh_session(device)

    if transport == "NETCONF":
        return create_netconf_session(device)

    raise ValueError(f"Unsupported transport: {transport}")
@contextmanager
def create_ssh_session(device):
    connection = {
        "device_type": "cisco_ios",
        "ip": device["device_ip"],
        "username": device["username"],
        "password": device["password"],
        "secret": device.get("secret"),
    }

    session = ConnectHandler(**connection)

    try:
        if device.get("secret"):
            session.enable()
        yield session
    finally:
        session.disconnect()
@contextmanager
def create_restconf_session(device):
    session = requests.Session()

    session.auth = (device["username"], device["password"])
    session.headers.update({
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json"
    })

    base_url = f"https://{device['ip']}/restconf/data"

    try:
        yield SessionContext(
        		session=session,
        		base_url=base_url,
        		device_ip=device["ip"]
        	)
    finally:
        session.close()
@contextmanager
def create_netconf_session(device):
    session = manager.connect(
        host=device["ip"],
        port=830,
        username=device["ssh_username"],
        password=device["ssh_password"],
        secret=device["ssh_secret"],
        hostkey_verify=False,
    )

    try:
        yield {
            "session": session,
            "device_ip": device["ip"]
        }
    finally:
        session.close_session()