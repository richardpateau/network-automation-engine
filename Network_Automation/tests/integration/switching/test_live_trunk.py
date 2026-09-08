import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_trunk
from src.compliance.switching.trunk.check import check_trunk
from src.compliance.switching.trunk.compliance import compliance_trunk
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

def test_live_build_trunk(sesh): 
    state = collect_device_state(sesh)
    actual = build_trunk(state)

    assert actual
    assert "gigabitethernet1/0" in actual 
    assert actual["gigabitethernet1/0"]["allowed_vlans"] == "1,10,20,30,40"

def test_live_check_trunk(sesh):
    state = collect_device_state(sesh)
    actual = build_trunk(state)

    expected = [
                    {"trunk_interface": "gigabitethernet1/0", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"},
                    {"trunk_interface": "gigabitethernet1/1", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"}
               ]    

    for exp in expected: 
        ok, failures = check_trunk([exp], actual)

        assert ok is True 
        assert failures == []

def test_live_compliance_trunk(sesh): 
    context = {
        "trunk_ports":  [
                    {"trunk_interface": "gigabitethernet1/0", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"},
                    {"trunk_interface": "gigabitethernet1/1", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"}
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
    
    result = compliance_trunk(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert result["status"] == "SUCCESS"
    assert result["critical_issues"] == []
    assert result["initial_issues"] == []
    assert any(
            "Trunk Interface Already Compliant | Interface: gigabitethernet1/0" in r
            for r in result["actions_taken"]
        )
def test_live_rogue_trunk(sesh): 
    context = {
        "trunk_ports":  [
                    {"trunk_interface": "gigabitethernet1/0", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"}
                   
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
    
    result = compliance_trunk(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )
    assert result["status"] == "SUCCESS"
    assert any(
            "(Trunk) Rogue Interface Configured in Trunk Mode" in r for r in result["initial_issues"]
        )
    assert any("gigabitethernet1/1" in r for r in result["initial_issues"])

@patch("src.compliance.switching.trunk.compliance.DRY_RUN", True)
def test_live_missing_interface(sesh):
    context = {
        "trunk_ports":  [
                    {"trunk_interface": "gigabitethernet1/0", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"},
                    {"trunk_interface": "gigabitethernet1/1", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"},
                    {"trunk_interface": "gigabitethernet2/1", "allowed_vlans": "1,10,20,30,40"}
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
    
    result = compliance_trunk(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(Trunk) Missing Interface | gigabitethernet2/1" in r for r in result["initial_issues"]
        )
    assert any(
            "[DRY_RUN] Would Configure_Trunk Port" in r for r in result["actions_taken"]
        )
    assert any(
            "Interface: gigabitethernet2/1 | Allowed VLAN(s): 1,10,20,30,40" in r 
            for r in result["actions_taken"]
        )

@patch("src.compliance.switching.trunk.compliance.DRY_RUN", True)
def test_live_mismatched_operational_mode(sesh):
    context = {
        "trunk_ports":  [
                    {"trunk_interface": "gigabitethernet1/0", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"},
                    {"trunk_interface": "gigabitethernet1/1", "allowed_vlans": "1,10,20,30,40", "mode": "access"},
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
    
    result = compliance_trunk(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
           "(Trunk) Mismatched Operational Mode" in r for r in result["initial_issues"] 
        )
    assert any(
            "Expected: access | Actual: trunk" in r for r in result["initial_issues"]
        )

@patch("src.compliance.switching.trunk.compliance.DRY_RUN", True)
def test_live_mismatched_allowed_vlans(sesh):
    context = {
        "trunk_ports":  [
                    {"trunk_interface": "gigabitethernet1/0", "allowed_vlans": "1,10,20,30,40,50", "mode": "trunk"},
                    {"trunk_interface": "gigabitethernet1/1", "allowed_vlans": "1,10,20,30,40", "mode": "trunk"}
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
    
    result = compliance_trunk(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(Trunk) Mismatched Allowed VLANs" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: 1,10,20,30,40,50" in r for r in result["initial_issues"]
        )
    assert any(
            "Actual: 1,10,20,30,40" in r for r in result["initial_issues"]
        )