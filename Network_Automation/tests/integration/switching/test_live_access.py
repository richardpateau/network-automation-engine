import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_access
from src.compliance.switching.access.check import check_access
from src.compliance.switching.access.compliance import compliance_access

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
    assert "gigabitethernet0/1" in actual
    assert actual["gigabitethernet0/1"]["operational_mode"] == "static access"
    assert actual["gigabitethernet0/1"]["access_vlan"] == 98


def test_live_check_access(sesh):
    state = collect_device_state(sesh)
    actual = build_access(state)

    expected = [
        {"access_interface": "gigabitethernet0/0", "access_vlan": 1, "mode": "static access"},
        {"access_interface": "gigabitethernet0/1", "access_vlan": 98, "mode": "static access"}
    ]

    for exp in expected:
        ok, failures = check_access([exp], actual)

        assert ok is True
        assert failures == []


def test_live_compliance_access(sesh):
    context = {
        "access_ports": [
            {"access_interface": "gigabitethernet0/0", "access_vlan": 1, "mode": "static access"},
            {"access_interface": "gigabitethernet0/1", "access_vlan": 98, "mode": "static access"}
        ]
    }

    state = collect_device_state(sesh)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_access(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert result["status"] == "SUCCESS"
    assert result["critical_issues"] == []
    assert all(
        "Access Interface Already Compliant" in r for r in result["actions_taken"]
    )


def test_live_rogue_access(sesh):
    context = {
        "access_ports": [
            {"access_interface": "gigabitethernet0/0", "access_vlan": 1, "mode": "static access"},
        ]
    }

    state = collect_device_state(sesh)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_access(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert result["status"] == "SUCCESS"
    assert any(
        "(Access) Rogue Interface Configured" in r for r in result["initial_issues"]
    )
    assert any("Interface: gigabitethernet0/1" in r for r in result["initial_issues"])


@patch("src.compliance.switching.access.compliance.DRY_RUN", True)
def test_live_missing_access(sesh):
    context = {
        "access_ports": [
            {"access_interface": "gigabitethernet0/0", "access_vlan": 1, "mode": "static access"},
            {"access_interface": "gigabitethernet0/1", "access_vlan": 98, "mode": "static access"},
            {"access_interface": "gigabitethernet2/0", "access_vlan": 1, "mode": "static access"}
        ]
    }

    state = collect_device_state(sesh)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_access(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(Access) Missing Interface | gigabitethernet2/0" in r for r in result["initial_issues"]
    )
    assert any(
        "[DRY_RUN] Would Configure Access Port" in r for r in result["actions_taken"]
    )
    assert any(
        "Interface: gigabitethernet2/0 | VLAN: 1" in r for r in result["actions_taken"]
    )


@patch("src.compliance.switching.access.compliance.DRY_RUN", True)
def test_live_mismatched_vlan(sesh):
    context = {
        "access_ports": [
            {"access_interface": "gigabitethernet0/0", "access_vlan": 1, "mode": "static access"},
            {"access_interface": "gigabitethernet0/1", "access_vlan": 20, "mode": "static access"},
        ]
    }


    state = collect_device_state(sesh)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_access(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    assert any(
        "(Access) Mismatched VLAN" in r for r in result["initial_issues"]
    )
    assert any(
        "Expected: 20 | Actual: 98" in r for r in result["initial_issues"]
    )
    assert any("gigabitethernet0/1" in r for r in result["initial_issues"])
