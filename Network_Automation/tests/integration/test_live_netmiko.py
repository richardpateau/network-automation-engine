import os
import pytest
from netmiko import ConnectHandler
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_vlan, build_interface, build_access
from src.compliance.switching.vlan.check import check_vlan
pytestmark = pytest.mark.live

def _creds():
    return {
        "device_type": os.environ.get("NA_TYPE", "cisco_ios"),
        "host": os.environ.get("NA_HOST", "192.168.255.11"),
        "username": os.environ["NA_USER"],
        "password": os.environ["NA_PASS"],
        "fast_cli": False,
    }

@pytest.fixture(scope="module")
def conn():
    c = ConnectHandler(**_creds())
    yield c
    c.disconnect()

def test_live_show_version(conn):
    out = conn.send_command("show version")
    assert "Cisco" in out or "IOS" in out or "Software" in out

def test_live_show_vlan(conn):
    out = conn.send_command("show vlan brief")
    assert "VLAN" in out or "default" in out.lower() or out.strip()

def test_live_build_vlan(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn
    state = collect_device_state(S())
    actual = build_vlan(state)

    assert actual
    assert 98 in actual
    assert actual[98]["name"] == "Management"

def test_live_build_interfaces(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn

    state = collect_device_state(S())
    actual = build_interface(state)

    assert actual
    assert "gigabitethernet0/0" in actual
    assert actual["gigabitethernet0/0"]["is_up"] == True

def test_live_build_interfaces(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn

    state = collect_device_state(S())
    actual = build_access(state)

    assert actual
    assert actual "gi0/1" in actual
    assert actual["gi0/1"]["operational_mode"] == "static access"
    assert actual["git0/1"]["access_vlan"] == 10