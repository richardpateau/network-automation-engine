import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_port_security
from src.compliance.security.port_security.check import check_port_security
from src.compliance.security.port_security.compliance import compliance_port_security
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

def test_live_build_port_security(sesh): 
    state = collect_device_state(sesh)
    actual = build_port_security(state)

    assert actual 
    assert "gigabitethernet0/1" in actual["interfaces"]
    assert actual["interfaces"]["gigabitethernet0/1"]["enabled"] == True
    assert actual["interfaces"]["gigabitethernet0/1"]["maximum"] == 2
    assert actual["interfaces"]["gigabitethernet0/1"]["violation"] == "restrict"
    assert actual["interfaces"]["gigabitethernet0/1"]["sticky"] == False
    assert actual["interfaces"]["gigabitethernet0/1"]["mac_addresses"] == ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]

def test_live_check_port_security(sesh):
    state = collect_device_state(sesh)
    actual = build_port_security(state)

    expected = {
        "interfaces": {
            "gigabitethernet0/1": {
                "enabled": True,
                "maximum": 2,
                "violation": "restrict",
                "sticky": False,
                "mac_addresses": ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]
            }
        }
    }

    ok, failures = check_port_security(expected, actual)
    print(failures)
    assert ok is True
    assert failures == []

def test_live_compliance_port_security(sesh):
    context = {
        "port_security": {
        "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    "maximum": 2,
                    "violation": "restrict",
                    "sticky": False,
                    "mac_addresses": ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]
                }
            }
        }
    }

    state = collect_device_state(sesh)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_port_security(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert result["status"] == "SUCCESS"
    assert all(
            "Port Security Configuration Already Compliant" in r for r in result["initial_issues"]
        )
    assert any(
            "Interface: gigabitethernet0/1" in r for r in result["initial_issues"]
        )
    assert any(
            "PS Enabled: True" in r for r in result["initial_issues"]
        )