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
    assert "gigabitethernet0/2" in actual["interfaces"]

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
            },
             "gigabitethernet0/2": {
                "enabled": True,
                "maximum": 1,
                "violation": "shutdown",
                "sticky": True,
                "mac_addresses": []
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
                },
                 "gigabitethernet0/2": {
                    "enabled": True,
                    "maximum": 1,
                    "violation": "shutdown",
                    "sticky": True,
                    "mac_addresses": []
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
            "Port Security Configuration Already Compliant" in r for r in result["actions_taken"]
        )
    assert any(
            "Interface: gigabitethernet0/1" in r for r in result["actions_taken"]
        )
    assert any(
            "PS Enabled: True" in r for r in result["actions_taken"]
        )

@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
def test_live_rogue_interface(sesh): 
    context = {
        "port_security": {
            "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    "maximum": 2,
                    "violation": "restrict",
                    "sticky": False,
                    "mac_addresses": ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]
                } #removing g0/2
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

    assert any(
            "(Port Security) Drift: Rogue Interface Configured with PS" in r 
            for r in result["initial_issues"]
        )
    assert any(
            "Interface: gigabitethernet0/2" in r for r in result["initial_issues"]
        )

@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
def test_live_missing_interface(sesh):
    context = {
        "port_security": {
            "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    "maximum": 2,
                    "violation": "restrict",
                    "sticky": False,
                    "mac_addresses": ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]
                },
                 "gigabitethernet0/2": {
                    "enabled": True,
                    "maximum": 1,
                    "violation": "shutdown",
                    "sticky": True,
                    "mac_addresses": []
                },
                #adding g0/3
                "gigabitethernet0/3": {
                    "enabled": True,
                    "maximum": 1,
                    "violation": "shutdown",
                    "sticky": True,
                    "mac_addresses": []
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
    print(result)
    assert any(
            "(Port Security) Expected Interface Not Configured with Port Security" in r
            for r in result["initial_issues"]
        )
    assert any(
            "Interface: gigabitethernet0/3" in r for r in result["initial_issues"]
        )
    assert any(
            "[DRY_RUN] Would Configure Port Security" in r for r in result["actions_taken"]
        )

@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
def test_live_mismatched_maximum(sesh): 
    context = {
        "port_security": {
            "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    #changing max from 2 to 4
                    "maximum": 4,
                    "violation": "restrict",
                    "sticky": False,
                    "mac_addresses": ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]
                },
                 "gigabitethernet0/2": {
                    "enabled": True,
                    "maximum": 1,
                    "violation": "shutdown",
                    "sticky": True,
                    "mac_addresses": []
                },
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

    assert any(
            "(Port Security) Mismatched Maximum Allowed" in r 
            for r in result["initial_issues"]
        )
    assert any(
            "Expected: 4 | Actual: 2" in r for r in result["initial_issues"]
        )

@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
def test_live_mismatched_sticky(sesh):
    context = {
        "port_security": {
            "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    "maximum": 2,
                    "violation": "restrict",
                    "sticky": False,
                    "mac_addresses": ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]
                },
                 "gigabitethernet0/2": {
                    "enabled": True,
                    "maximum": 1,
                    "violation": "shutdown",
                    #inverting True
                    "sticky": False,
                    "mac_addresses": []
                },
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

    assert any(
            "(Port Security) Mismatched Sticky Configuration" in r 
            for r in result["initial_issues"]
        )
    assert any(
            "Expected: False | Actual: True" in r for r in result["initial_issues"]
        )

@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
def test_live_mismatched_violation(sesh): 
    context = {
        "port_security": {
            "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    "maximum": 2,
                    "violation": "restrict",
                    "sticky": False,
                    "mac_addresses": ["aaaa.bbbb.cccc", "aaaa.bbbb.dddd"]
                },
                 "gigabitethernet0/2": {
                    "enabled": True,
                    "maximum": 1,
                    #changing shutdown to protect
                    "violation": "protect",
                    "sticky": True,
                    "mac_addresses": []
                },
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

    assert any(
            "(Port Security) Mismatched Violation Configuration" in r
            for r in result["initial_issues"]
        )
    assert any(
            "Expected: protect | Actual: shutdown" in r for r in result["initial_issues"]
        )

@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
def test_live_extra_mac_address(sesh): 
    context = {
        "port_security": {
            "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    "maximum": 2,
                    "violation": "restrict",
                    "sticky": False,
                    #removing aaaa.bbbb.dddd
                    "mac_addresses": ["aaaa.bbbb.cccc"]
                },
                 "gigabitethernet0/2": {
                    "enabled": True,
                    "maximum": 1,
                    "violation": "protect",
                    "sticky": True,
                    "mac_addresses": []
                },
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
    assert any(
            "(Port Security) Drift: Rogue MAC Address Found" in r for r in result["initial_issues"]
        )
    assert any(
            "MAC: aaaa.bbbb.dddd" in r for r in result["initial_issues"]
        )

@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
def test_live_missing_mac_address(sesh): 
    context = {
        "port_security": {
            "interfaces": {
                "gigabitethernet0/1": {
                    "enabled": True,
                    "maximum": 2,
                    "violation": "restrict",
                    "sticky": False,
                    "mac_addresses": ["aaaa.bbbb.cccc","aaaa.bbbb.dddd"]
                },
                 "gigabitethernet0/2": {
                    "enabled": True,
                    "maximum": 1,
                    "violation": "protect",
                    "sticky": True,
                    "mac_addresses": ["aaaa.bbbb.dddd"]
                },
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
    assert any(
            "(Port Security) Missing MAC Address" in r for r in result["initial_issues"]
        )
    assert any(
            "MAC: aaaa.bbbb.dddd" in r for r in result["initial_issues"]
        )

