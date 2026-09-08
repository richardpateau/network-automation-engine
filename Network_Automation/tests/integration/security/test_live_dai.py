import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_dai
from src.compliance.security.dai.check import check_dai
from src.compliance.security.dai.compliance import compliance_dai

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


def test_live_build_dai(sesh):
    state = collect_device_state(sesh)
    actual = build_dai(state)

    assert actual
    assert actual["arp_inspection"] is True
    assert actual["enabled_vlans"] == [10, 20, 30]
    assert actual["interfaces"]["gi0/0"] == {"rate_limit": None, "trusted": True}
    assert actual["interfaces"]["gi0/2"] == {"rate_limit": 20, "trusted": False}
    assert actual["interfaces"]["gi0/3"] == {"rate_limit": 10, "trusted": False}
    assert actual["log_buffer"]["enabled"] == True
    assert actual["log_buffer"]["entries"] == 1024


def test_live_check_dai(sesh):
    expected = {
        "arp_inspection": True,
        "enabled_vlans": [10, 20, 30],
        "interfaces": {
            "gi0/0": {"rate_limit": None, "trusted": True},
            "gi0/2": {"rate_limit": 20, "trusted": False},
            "gi0/3": {"rate_limit": 10, "trusted": False}
        },
        "log_buffer": {
            "enabled": True,
            "entries": 1024
        }
    }

    state = collect_device_state(sesh)
    actual = build_dai(state)
    ok, failures = check_dai(expected, actual)
    assert ok is True
    assert failures == []


def test_live_compliance_dai(sesh):
    context = {
        "dai": {
            "arp_inspection": True,
            "enabled_vlans": [10, 20, 30],
            "interfaces": {
                "gi0/0": {"rate_limit": None, "trusted": True},
                "gi0/2": {"rate_limit": 20, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                "entries": 1024
            }
        }
    }

    state = collect_device_state(sesh)
    actual = build_dai(state)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    assert result["status"] == "SUCCESS"
    assert all(
        "DAI Configuration Already Compliant" in r for r in result["actions_taken"]
    )
    assert any(
        "Enabled VLANs: 10, 20, 30" in r for r in result["actions_taken"]
    )
    assert any(
        "Trusted Interfaces: gi0/0" in r for r in result["actions_taken"]
    )


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
def test_live_mismatched_enabled_arp(sesh):
    context = {
        "dai": {
            "arp_inspection": False,
            "enabled_vlans": [10, 20, 30],
            "interfaces": {
                "gi0/0": {"rate_limit": None, "trusted": True},
                "gi0/2": {"rate_limit": 20, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                "entries": 1024
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

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(DAI) Operational State Mismatch" in r for r in result["initial_issues"]
    )
    assert any(
        "Expected: False | Actual: True" in r for r in result["initial_issues"]
    )


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
def test_live_missing_vlans(sesh):
    context = {
        "dai": {
            "arp_inspection": False,
            # 40 added
            "enabled_vlans": [10, 20, 30, 40, 50],
            "interfaces": {
                "gi0/0": {"rate_limit": None, "trusted": True},
                "gi0/2": {"rate_limit": 20, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                "entries": 1024
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

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(DAI) Missing VLAN(s) | VLAN(s): [40, 50]" in r for r in result["initial_issues"]
    )
    assert any(
        "[DRY_RUN] Would Configure DAI" in r for r in result["actions_taken"]
    )
    assert any(
        "Enabled VLANs: 10, 20, 30, 40, 50" in r for r in result["actions_taken"]
    )


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
def test_live_extra_vlans(sesh):
    context = {
        "dai": {
            "arp_inspection": False,
            # 20 and 30 removed
            "enabled_vlans": [10],
            "interfaces": {
                "gi0/0": {"rate_limit": None, "trusted": True},
                "gi0/2": {"rate_limit": 20, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                "entries": 1024
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

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(DAI) Drift: Extra VLAN(s) Found | VLAN: [20, 30]" in r
        for r in result["initial_issues"]
    )


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
def test_live_mismatched_buffer_entry(sesh):
    context = {
        "dai": {
            "arp_inspection": False,
            "enabled_vlans": [10, 20, 30],
            "interfaces": {
                "gi0/0": {"rate_limit": None, "trusted": True},
                "gi0/2": {"rate_limit": 20, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                # entries changed from 1024
                "entries": 1025
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

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(DAI) Log Buffer Entries Mismatch" in r for r in result["initial_issues"]
    )
    assert any(
        "Expected: 1025 | Actual: 1024" in r for r in result["initial_issues"]
    )


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
def test_live_missing_interface(sesh):
    context = {
        "dai": {
            "arp_inspection": False,
            "enabled_vlans": [10, 20, 30],
            "interfaces": {
                "gi0/0": {"rate_limit": None, "trusted": True},
                "gi0/2": {"rate_limit": 20, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False},
                # added an interface
                "fastethernet0/1": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                "entries": 1024
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

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(DAI) Missing Interface during test" in r for r in result["initial_issues"]
    )
    assert any(
        "potential misconfig in SOT" in r for r in result["initial_issues"]
    )
    assert any(
        "Interface: fastethernet0/1" in r for r in result["initial_issues"]
    )


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
def test_live_mismatched_rate_limit(sesh):
    context = {
        "dai": {
            "arp_inspection": False,
            "enabled_vlans": [10, 20, 30],
            "interfaces": {
                "gi0/0": {"rate_limit": None, "trusted": True},
                # changing 20 to 30
                "gi0/2": {"rate_limit": 30, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                "entries": 1024
            }
        }
    }

    state = collect_device_state(sesh)
    actual = build_dai(state)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(DAI) Misatched Rate Limit Configuration" in r for r in result["initial_issues"]
    )
    assert any(
        "Expected: 30 | Actual: 20" in r for r in result["initial_issues"]
    )


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
def test_live_mismatched_trusted_interface(sesh):
    context = {
        "dai": {
            "arp_inspection": False,
            "enabled_vlans": [10, 20, 30],
            "interfaces": {
                # changed false to true
                "gi0/0": {"rate_limit": None, "trusted": False},
                "gi0/2": {"rate_limit": 20, "trusted": False},
                "gi0/3": {"rate_limit": 10, "trusted": False}
            },
            "log_buffer": {
                "enabled": True,
                "entries": 1024
            }
        }
    }

    state = collect_device_state(sesh)
    actual = build_dai(state)

    device_result = {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

    log = MagicMock()

    result = compliance_dai(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    assert any(
        "(DAI) Mismatched Trusted Interface Configuration" in r for r in result["initial_issues"]
    )
    assert any(
        "Expected: False | Actual: True" in r for r in result["initial_issues"]
    )
