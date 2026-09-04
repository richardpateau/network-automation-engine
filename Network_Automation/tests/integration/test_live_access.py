import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_access
from src.compliance.switching.access.check import check_access
from src.compliance.switching.interface.compliance import compliance_access
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

@pytest.fixture
def sesh(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn
    return S()

def test_live_build_access(sesh): 
	state = collect_device_state(sesh)
	actual = build_access(state)

	assert actual
	assert "gi0/0" in actual 
	assert actual["gi0/0"]["operational_mode"] == "static access"
	assert actual["gi0/0"]["access_vlan"] == 98

def test_live_check_access(sesh):