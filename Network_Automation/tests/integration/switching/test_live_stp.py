import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_stp_global, build_stp_interfaces
from src.compliance.switching.stp.check import check_stp_global, check_stp_interfaces
from src.compliance.switching.stp.compliance import compliance_stp_global, compliance_stp_interfaces

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


def test_live_build_stp_global(sesh):
    state = collect_device_state(sesh)
    actual = build_stp_global(state)

    assert actual
    assert {
               "mode": "rapid_pvst",
               "vlan_priorities": {
                   1: 32768,
                   10: 4096,
                   20: 8192,
                   30: 12288
               }
           } == actual


def test_live_build_stp_interfaces(sesh):
    state = collect_device_state(sesh)
    actual = build_stp_interfaces(state)

    assert actual
    assert actual["gigabitethernet0/1"]["portfast"] == True
    assert actual["gigabitethernet0/1"]["bpdu_guard"] == True
    assert actual["gigabitethernet0/2"]["root_guard"] == True
    assert actual["gigabitethernet0/3"]["loop_guard"] == True
    assert actual["gigabitethernet0/3"]["bpdu_filter"] == True


def test_live_check_stp_global(sesh):
    expected = {
        "mode": "rapid_pvst",
        "vlan_priorities": {
            1: 32768,
            10: 4096,
            20: 8192,
            30: 12288
        }
    }
    state = collect_device_state(sesh)
    actual = build_stp_global(state)

    ok, failures = check_stp_global(expected, actual)
    assert ok is True
    assert failures == []

def test_live_check_stp_interfaces(sesh):
    expected = {
        "interfaces": [
            {
                "interface": "gigabitethernet0/1",
                "stp": {
                    "portfast": True,
                    "bpdu_guard": True,
                    "root_guard": False,
                    "loop_guard": False,
                    "bpdu_filter": False
                }
            },
            {
                "interface": "gigabitethernet0/2",
                "stp": {
                    "root_guard": True,
                    "portfast": False,
                    "bpdu_guard": False,
                    "loop_guard": False,
                    "bpdu_filter": False
                }
            },
            {
                "interface": "gigabitethernet0/3",
                "stp": {
                    "loop_guard": True,
                    "bpdu_filter": True,
                    "portfast": False,
                    "bpdu_guard": False,
                    "root_guard": False,

                }
            }
        ]
    }
    state = collect_device_state(sesh)
    actual = build_stp_interfaces(state)

    ok, failures = check_stp_interfaces(expected["interfaces"], actual)
    print(failures)

    assert ok is True
    assert failures == []


def test_live_compliance_stp_global(sesh):
    context = {
        "stp": {
            "mode": "rapid_pvst",
            "vlan_priorities": {
                1: 32768,
                10: 4096,
                20: 8192,
                30: 12288
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

    result = compliance_stp_global(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    print(result)
    assert result["status"] == "SUCCESS"
    assert all(
        "STP Global Configuration Already Compliant" in r for r in result["actions_taken"]
    )
    assert any(
        "Mode: rapid_pvst" in r for r in result["actions_taken"]
    )
    assert any(
        "VLAN: 10 - Priority: 4096" in r for r in result["actions_taken"]
    )


def test_live_compliance_stp_interfaces(sesh):
    context = {
        "interfaces": [
            {
                "interface": "gigabitethernet0/1",
                "stp": {
                    "portfast": True,
                    "bpdu_guard": True,
                    "root_guard": False,
                    "loop_guard": False,
                    "bpdu_filter": False
                }
            },
            {
                "interface": "gigabitethernet0/2",
                "stp": {
                    "root_guard": True,
                    "portfast": False,
                    "bpdu_guard": False,
                    "loop_guard": False,
                    "bpdu_filter": False
                }
            },
            {
                "interface": "gigabitethernet0/3",
                "stp": {
                    "loop_guard": True,
                    "bpdu_filter": True,
                    "portfast": False,
                    "bpdu_guard": False,
                    "root_guard": False,

                }
            }
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
    result = compliance_stp_interfaces(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    print(result)

    print(result["actions_taken"])
    assert result["status"] == "SUCCESS"
    assert all(
        "STP Interface Configuration Already Compliant" in r for r in result["actions_taken"]
    )
    assert any(
        "STP Interface Configuration Already Compliant | Interface: gigabitethernet0/1 | "
        f"BPDU Guard: True" in r for r in result["actions_taken"]
    )


@patch("src.compliance.switching.stp.compliance.DRY_RUN", True)
def test_live_wrong_stp_mode(sesh):
    context = {
        "stp": {
            "mode": "pvst",
            "vlan_priorities": {
                1: 32768,
                10: 4096,
                20: 8192,
                30: 12288
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

    result = compliance_stp_global(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    print(result)
    assert any(
        "Mismatched STP Mode" in r for r in result["initial_issues"]
    )
    assert any(
        "Expected: pvst | Actual: rapid_pvst" in r for r in result["initial_issues"]
    )

@patch("src.compliance.switching.stp.compliance.DRY_RUN", True)
def test_live_missing_vlans(sesh):
    context = {
        "stp": {
            "mode": "rapid_pvst",
            "vlan_priorities": {
                1: 32768,
                10: 4096,
                20: 8192,
                30: 12288,
                50: 8192
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

    result = compliance_stp_global(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    print(result)
    assert any(
        "(STP) Missing VLANs | [50]" in r for r in result["initial_issues"]
    )
    assert any(
        "[DRY_RUN] Would Configure Global STP" in r for r in result["actions_taken"]
    )

    assert any(
        "VLAN: 30 - Priority: 12288" in r for r in result["actions_taken"]
    )


@patch("src.compliance.switching.stp.compliance.DRY_RUN", True)
def test_live_rogue_vlans(sesh):
    context = {
        "stp": {
            "mode": "pvst",
            "vlan_priorities": {
                1: 32768,
                30: 12288,
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

    result = compliance_stp_global(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )

    assert any(
        "(STP) Rogue VLANs | [10, 20]" in r for r in result["initial_issues"]
    )


@patch("src.compliance.switching.stp.compliance.DRY_RUN", True)
def test_live_mismatched_priority(sesh):
    context = {
        "stp": {
            "mode": "rapid_pvst",
            "vlan_priorities": {
                1: 32768,
                10: 4096,
                20: 8192,
                30: 12281,
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

    result = compliance_stp_global(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    print(result)
    assert any(
        "(STP) Mismatched Bridge Priority | VLAN: 30"
        in r for r in result["initial_issues"]
    )
    assert any(
        "Expected: 12281 | Actual: 12288" in r for r in result["initial_issues"]
    )


def test_live_mismatched_port_fast_and_bpdu_guard(sesh):
    context = {
        "interfaces": [
            {  # bpdu guard and portfast will be inverted
                "interface": "gigabitethernet0/1",
                "stp": {
                    "portfast": False,
                    "bpdu_guard": False
                }
            },
            # root guard will be inverted
            {
                "interface": "gigabitethernet0/2",
                "stp": {
                    "root_guard": False,

                }
            },
            # loop gaurd and bpdu filter will be inverted
            {
                "interface": "gigabitethernet0/3",
                "stp": {
                    "loop_guard": True,
                    "bpdu_filter": True
                }
            }
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

    result = compliance_stp_interfaces(
        sesh,
        "192.168.255.11",
        context,
        state,
        device_result,
        log
    )
    print (result)
    assert any(
        "(STP Interface) Mismatched PortFast" in r for r in result["initial_issues"]
    )
    assert any(
        "(STP Interface) Mismatched BPDU Guard" in r for r in result["initial_issues"]
    )
    assert any(
        "(STP Interface) Mismatched Root Guard" in r for r in result["initial_issues"]
    )
    assert any(
        "(STP Interface) Mismatched Loop Guard" in r for r in result["initial_issues"]
    )
    assert any(
        "(STP Interface) Mismatched BPDU Filter" in r for r in result["initial_issues"]
    )
