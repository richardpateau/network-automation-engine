import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_etherchannel
from src.compliance.switching.etherchannel.check import check_etherchannel
from src.compliance.switching.etherchannel.compliance import compliance_etherchannel

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

def test_live_build_etherchannel(sesh):
    state = collect_device_state(sesh)
    actual = build_etherchannel(state)

    assert actual
    assert 1 in actual["groups"]
    assert actual["groups"][1]["mode"] == "active"
    assert actual["groups"][1]["interfaces"] == ["gigabitethernet0/1", "gigabitethernet0/2"]
    assert actual["groups"][1]["switchport_mode"] == "access"
    assert actual["groups"][1]["type"] == "lacp"
    assert actual["groups"][1]["description"] == "switch_link"

def test_live_check_etherchannel(sesh): 
    state = collect_device_state(sesh)
    actual = build_etherchannel(state)

    expected = {
        "enabled": True,
        "groups": {
            1: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2"],
                "description": "switch_link",
                "switchport_mode": "access"
            },
        2: {
            "mode": "desirable",
            "type": "pagp",
            "interfaces": ["gigabitethernet1/0", "gigabitethernet1/1"],
            "description": "link to router",
            "switchport_mode": "trunk"
            }
        }
    }
    print(actual)
    ok, failures = check_etherchannel(expected, actual)

    assert ok is True 
    assert failures == []

def test_live_compliance_etherchannel(sesh):
    state = collect_device_state(sesh) 
    context = {
        "etherchannel": {
        "enabled": True,
        "groups": {
            1: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2"],
                "description": "switch_link",
                "switchport_mode": "access"
                },

            2: {
                "mode": "desirable",
                "type": "pagp",
                "interfaces": ["gigabitethernet1/0", "gigabitethernet1/1"],
                "description": "link to router",
                "switchport_mode": "trunk"
                }
            }
        }
    }
    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_etherchannel(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )
    print(result["initial_issues"])
    assert result["status"] == "SUCCESS"
    assert result["critical_issues"] == []
    assert result["initial_issues"] == []
    assert all(
            "Etherchannel Configuration Already Compliant" in r for r in result["actions_taken"]
        )

@patch("src.compliance.switching.etherchannel.compliance.DRY_RUN", True)
def test_live_rogue_etherchannel(sesh): 
    state = collect_device_state(sesh)
    context = {
        "etherchannel": {
        "enabled": True,
        "groups": {
            1: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2"],
                "description": "switch_link",
                "switchport_mode": "access"
                }
            }
        }
    }

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_etherchannel(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )
    assert any(
            "(Etherchannel) Drift: Rogue Port Channel(s)" in r for r in result["initial_issues"]
        )
    assert  any("2" in r for r in result["initial_issues"])

@patch("src.compliance.switching.etherchannel.compliance.DRY_RUN", True)
def test_live_missing_etherchannel(sesh):
    state = collect_device_state(sesh)
    context = {
        "etherchannel": {
        "enabled": True,
        "groups": {
            1: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2"],
                "description": "switch_link",
                "switchport_mode": "access"
                },
            2: {
                "mode": "desirable",
                "type": "pagp",
                "interfaces": ["gigabitethernet1/0", "gigabitethernet1/1"],
                "description": "link to router",
                "switchport_mode": "trunk"
            },
            3: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2"],
                "description": "switch_link",
                "switchport_mode": "access"
                }
            }
        }
    }


    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_etherchannel(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )
    print(result["initial_issues"])
    print(result["actions_taken"])
    assert any(
            "(Etherchannel) Missing Port Channel Group | 3" in r for r in result["initial_issues"]
        )
    assert any(
            "[DRY_RUN] Would Configure Etherchannel" in r for r in result["actions_taken"]
        )
    assert any(
            "Group Number: 3" in r for r in result["actions_taken"]
        )
    assert any(
        "Type/Mode: lacp - active" in r for r in result["actions_taken"]
    )

@patch("src.compliance.switching.etherchannel.compliance.DRY_RUN", True)
def test_live_missing_interface(sesh): 
    state = collect_device_state(sesh)
    context = {
        "etherchannel": {
        "enabled": True,
        "groups": {
            1: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2", "gigabitethernet0/3"],
                "description": "switch_link",
                "switchport_mode": "access"
                },
            2: {
                "mode": "desirable",
                "type": "pagp",
                "interfaces": ["gigabitethernet1/0", "gigabitethernet1/1"],
                "description": "link to router",
                "switchport_mode": "trunk"
                }
            }
        }
    }

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_etherchannel(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
          "(Etherchannel) Missing Interface" in r for r in result["initial_issues"]
        )
    assert any(
            "Group: 1 | Interface: gigabitethernet0/3" in r for r in result["initial_issues"]
        )

@patch("src.compliance.switching.etherchannel.compliance.DRY_RUN", True)
def test_live_mismatched_mode(sesh): 
    state = collect_device_state(sesh)
    context = {
        "etherchannel": {
        "enabled": True,
        "groups": {
            1: {
                "mode": "passive",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2"],
                "description": "switch_link",
                "switchport_mode": "access"
                },
            2: {
                "mode": "desirable",
                "type": "pagp",
                "interfaces": ["gigabitethernet1/0", "gigabitethernet1/1"],
                "description": "link to router",
                "switchport_mode": "trunk"
                }
            }
        }
    }


    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_etherchannel(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(Etherchannel) Mode Mismatch" in r for r in result["initial_issues"]
        )
    assert any(
            "Group: 1" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: passive | Actual: active" in r for r in result["initial_issues"]
        )

@patch("src.compliance.switching.etherchannel.compliance.DRY_RUN", True)
def test_live_mismatched_description(sesh): 
    state = collect_device_state(sesh)
    context = {
        "etherchannel": {
        "enabled": True,
        "groups": {
            1: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/1", "gigabitethernet0/2"],
                "description": "link to router",
                "switchport_mode": "access"
                },
            2: {
                "mode": "desirable",
                "type": "pagp",
                "interfaces": ["gigabitethernet1/0", "gigabitethernet1/1"],
                "description": "link to router",
                "switchport_mode": "trunk"
                }
            }
        }
    }


    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_etherchannel(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )
    print(result["initial_issues"])
    assert any(
            "(Etherchannel) Mismatched Description" in r for r in result["initial_issues"]
        )
    assert any(
            "Group: 1" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: link to router | Actual: switch_link" in r for r in result["initial_issues"]
        )