import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_syslog_netmiko
from src.compliance.services.syslog.check import check_syslog
from src.compliance.services.syslog.compliance import compliance_syslog
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

def test_live_build_syslog_netmiko(sesh):
    state = collect_device_state(sesh)
    actual = build_syslog_netmiko(state)

    assert actual
    assert actual["hosts"] == ["10.10.10.50", "10.10.10.60"]
    assert actual["trap_level"] == "warnings"
    assert actual["source_interface"] == "gigabitethernet0/0"
    assert actual["facility"] == "local4"
    assert actual["timestamps"] is True

def test_live_check_syslog_netmiko(sesh): 
    expected = {
        "hosts": [
            "10.10.10.50",
            "10.10.10.60"
        ],
        "trap_level": "warnings",
        "source_interface": "gigabitethernet0/0",
        "facility": "local4",
        "timestamps": True
    }

    state = collect_device_state(sesh)
    actual = build_syslog_netmiko(state)

    ok, failures = check_syslog(expected, actual)

    assert ok is True 
    assert failures == []

def test_live_compliance_syslog(sesh): 
    context = {
            "syslog": {
                "hosts": [
                    "10.10.10.50",
                    "10.10.10.60"
                ],
                "trap_level": "warnings",
                "source_interface": "gigabitethernet0/0",
                "facility": "local4",
                "timestamps": True
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

    result = compliance_syslog(
            sesh,
            "192.168.255.11",
            context, 
            state,
            device_result,
            log
        )

    assert result["status"] == "SUCCESS"
    assert all(
            "Syslog Configuration Already Compliant" in r for r in result["initial_issues"]
        )
    assert any(
            "Facility: local4" in r for r in result["initial_issues"]
        )
    assert any(
            "Syslog Host IP: 10.10.10.50, 10.10.10.60" in r for r in result["initial_issues"]
        )

def test_live_missing_host(sesh): 
     context = {
            "syslog": {
                "hosts": [
                    "10.10.10.50",
                    "10.10.10.60",
                    #adding host 
                    "10.20.20.10"
                ],
                "trap_level": "warnings",
                "source_interface": "gigabitethernet0/0",
                "facility": "local4",
                "timestamps": True
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

    result = compliance_syslog(
            sesh,
            "192.168.255.11",
            context, 
            state,
            device_result,
            log
        )

    assert any(
            "(Syslog) Missing Host | IP: 10.20.20.10" in r for r in result["initial_issues"]
        )
    assert any(
            "[DRY_RUN] Would Configure Syslog" in r for r in result["actions_taken"]
        )
     assert any(
            "Syslog Host IP: 10.10.10.50, 10.10.10.60" in r for r in result["actions_taken"]
        )

def test_live_rogue_host_ip(sesh): 
    context = {
            "syslog": {
                "hosts": [
                    "10.10.10.50",
                    #"10.10.10.60",
                ],
                "trap_level": "warnings",
                "source_interface": "gigabitethernet0/0",
                "facility": "local4",
                "timestamps": True
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

    result = compliance_syslog(
            sesh,
            "192.168.255.11",
            context, 
            state,
            device_result,
            log
        )

    assert any(
            "(Syslog) Drift: Rogue Host | 10.10.10.60" in r for r in result["initial_issues"]
        )

def test_live_mismatched_facility(sesh): 
    context = {
            "syslog": {
                "hosts": [
                    "10.10.10.50",
                    "10.10.10.60",
                ],
                "trap_level": "warnings",
                "source_interface": "gigabitethernet0/0",
                #changing local4 to local7
                "facility": "local7",
                "timestamps": True
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

    result = compliance_syslog(
            sesh,
            "192.168.255.11",
            context, 
            state,
            device_result,
            log
        )

    assert any(
            "(Syslog) Mismatched Facility" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: local7 | Actual: local4" in r for r in result["initial_issues"]
        )

def test_live_mismatched_source_interface(sesh): 
    context = {
            "syslog": {
                "hosts": [
                    "10.10.10.50",
                    "10.10.10.60",
                ],
                "trap_level": "warnings",
                #changing 0/0 to 0/1
                "source_interface": "gigabitethernet0/1",
                "facility": "local4",
                "timestamps": True
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

    result = compliance_syslog(
            sesh,
            "192.168.255.11",
            context, 
            state,
            device_result,
            log
        )

    assert any(
            "(Syslog) Mismatched Source Interface" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: gigabitethernet0/1 | Actual: gigabitethernet0/0" in r 
            for r in result["initial_issues"]
        )

def test_live_mismatched_trap_level(sesh): 
    context = {
            "syslog": {
                "hosts": [
                    "10.10.10.50",
                    "10.10.10.60",
                ],
                #changing warnings to alert 
                "trap_level": "alert",
                "source_interface": "gigabitethernet0/0",
                "facility": "local4",
                "timestamps": True
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

    result = compliance_syslog(
            sesh,
            "192.168.255.11",
            context, 
            state,
            device_result,
            log
        )

    assert any(
            "(Syslog) Mismatched Trap Level" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: alert | Actual: warninigs" in r for r in result["initial_issues"]
        )