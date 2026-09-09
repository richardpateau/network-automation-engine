import os
import pytest
from netmiko import ConnectHandler
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_vlan
from src.compliance.switching.vlan.check import check_vlan
from src.compliance.switching.vlan.compliance import compliance_vlan
from unittest.mock import MagicMock, patch
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

def test_live_check_vlan(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn
    state = collect_device_state(S())
    actual = build_vlan(state)

    expected = [
        {"vlan_id": 1, "name": "default"},
        {"vlan_id": 10, "name": "VLAN0010"},
        {"vlan_id": 98, "name": "Management"},
    ]
    for exp in expected:
        ok, failures = check_vlan([exp], actual)

        assert ok is True
        assert failures == []

def test_live_compliance_vlan(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn

    context = {
        "vlans": [
            {"vlan_id": 1, "name": "default"},
            {"vlan_id": 10, "name": "VLAN0010"},
            {"vlan_id": 98, "name": "Management"},
            {"vlan_id": 1002, "name": "fddi-default"},
            {"vlan_id": 1003, "name": "token-ring-default"},
            {"vlan_id": 1004, "name": "fddinet-default"},
            {"vlan_id": 1005, "name": "trnet-default"},
        ]
    }
    device_state = collect_device_state(S())

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_vlan(
        sesh,
        "192.168.255.11",
        context,
        device_state,
        device_result,
        log
    )
    assert result["status"] == "SUCCESS"
    assert result["critical_issues"] == []
    assert len(result["actions_taken"]) == 7
    assert all(
        "VLAN Already Compliant" in action
        for action in result["actions_taken"]
    )

def test_live_rogue_vlan(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn

    context = {
        "vlans": [
            {"vlan_id": 1, "name": "default"},
            {"vlan_id": 98, "name": "Management"},
            {"vlan_id": 1002, "name": "fddi-default"},
            {"vlan_id": 1003, "name": "token-ring-default"},
            {"vlan_id": 1004, "name": "fddinet-default"},
            {"vlan_id": 1005, "name": "trnet-default"},
        ]
    }
    device_state = collect_device_state(S())

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_vlan(
        S(),
        "192.168.255.11",
        context,
        device_state,
        device_result,
        log
    )
    assert result["status"] == "SUCCESS"
    assert any(
        f"Rogue VLAN Detected" in r
        for r in result["initial_issues"]
    )
    assert any("VLAN: 10" in r
               for r in result["initial_issues"]
               )
    assert any("VLAN0010" in r for r in result["initial_issues"])

def test_live_missing_vlan(conn):
    class S:
        transport = "NETMIKO"
        device_ip = "192.168.255.11"
        connection = conn

    context = {
        "vlans": [
            {"vlan_id": 1, "name": "default"},
            {"vlan_id": 10, "name": "VLAN0010"},
            {"vlan_id": 98, "name": "Management"},
            {"vlan_id": 200, "name": "cisco"},
            {"vlan_id": 1002, "name": "fddi-default"},
            {"vlan_id": 1003, "name": "token-ring-default"},
            {"vlan_id": 1004, "name": "fddinet-default"},
            {"vlan_id": 1005, "name": "trnet-default"},
        ]
    }
    device_state = collect_device_state(S())

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_vlan(
        S(),
        "192.168.255.11",
        context,
        device_state,
        device_result,
        log
    )

    assert any("Missing VLAN 200" in r
                for r in result["initial_issues"]
               )
    assert any(
            "cisco" in r
            for r in result["initial_issues"]
    )
    assert any(
        f"[DRY_RUN] Would Configure VLAN | VLAN: 200" in r
        for r in result["actions_taken"]
    )

def test_live_name_mismatch(conn, sesh):
    context = {
        "vlans": [
            {"vlan_id": 1, "name": "default"},
            {"vlan_id": 98, "name": "mgmt"},
            {"vlan_id": 1002, "name": "fddi-default"},
            {"vlan_id": 1003, "name": "token-ring-default"},
            {"vlan_id": 1004, "name": "fddinet-default"},
            {"vlan_id": 1005, "name": "trnet-default"},
        ]
    }
    device_state = collect_device_state(sesh)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_vlan(
        sesh,
        "192.168.255.11",
        context,
        device_state,
        device_result,
        log
    )

    assert any(
        "VLAN Name Mismatch" in r
        for r in result["initial_issues"]
    )
    assert (
        "Expected: mgmt | Actual: Management" in r
        for r in result["initial_issues"]
    )