import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_interface
from src.compliance.switching.interface.check import check_interface
from src.compliance.switching.interface.compliance import compliance_interface
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

def test_live_build_interface(conn, sesh): 
    state = collect_device_state(sesh)
    actual = build_interface(state)

    assert actual 
    assert "gigabitethernet0/0" in actual
    assert actual["gigabitethernet0/0"]["is_up"] == True

def test_live_check_interface(conn, sesh):
    state = collect_device_state(sesh)
    actual = build_interface(state)

    expected =  [
        {
            "interface": "gigabitethernet0/1",
            "should_be_up": True
        },
        {
            "interface": "gigabitethernet0/2",
            "should_be_up": True
        }
    ]

    for exp in expected:
        ok, failures = check_interface([exp], actual)

        assert ok is True 
        assert failures == []

def test_live_compliance_interface(conn, sesh): 
    state = collect_device_state(sesh)
    actual = build_interface(state)

    context = {
             "interfaces": [
            {
                "interface": "gigabitethernet0/1",
                "should_be_up": True
            },
            {
                "interface": "gigabitethernet0/2",
                "should_be_up": True
            }
                ]
        }

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }
    log = MagicMock()

    result = compliance_interface(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert result["status"] == "SUCCESS"
    assert result["critical_issues"] == []
    assert any(
            "Interface Configuration Already Compliant" in r
            for r in result["actions_taken"]
        )

@patch("src.compliance.switching.interface.compliance.DRY_RUN", True)
def test_live_missing_interface(conn, sesh): 
    state = collect_device_state(sesh)

    context = {
             "interfaces": [
            {
                "interface": "gigabitethernet0/1",
                "should_be_up": True
            },
            {
                "interface": "gigabitethernet2/1",
                "should_be_up": True
            }
                ]
        }

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }
    log = MagicMock()

    result = compliance_interface(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
            "(Interface) Missing Interface | gigabitethernet2/1" in r 
            for r in result["initial_issues"]
        )
    assert any(
            "[DRY_RUN] Would Configure Interface" in r 
            for r in result["actions_taken"]
        )
   

@patch("src.compliance.switching.interface.compliance.DRY_RUN", True)
def test_live_up_mismatch(conn, sesh): 
    state = collect_device_state(sesh)
    actual = build_interface(state)

    context = {
             "interfaces": [
            {
                "interface": "gigabitethernet0/1",
                "should_be_up": True
            },
            {
                "interface": "gigabitethernet0/3",
                "should_be_up": True
            }
                ]
        }

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }
    log = MagicMock()

    result = compliance_interface(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
            "Mismatched Interface Operational State" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected Should Be Up/Up: True" in r for r in result["initial_issues"]
        )
    assert any(
            "Actual Should be Up/Up: False" in r for r in result["initial_issues"]
        )