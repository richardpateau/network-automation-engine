import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_snmp_netmiko
from src.compliance.services.snmp.check import check_snmp
from src.compliance.services.snmp.compliance import compliance_snmp

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

def test_live_build_snmp(sesh):
    state = collect_device_state(sesh)
    actual = build_snmp_netmiko(state)

    assert actual 
    assert {"snmp_name": "public", "permission": "ro"} in actual["communities"]
    assert {"snmp_name": "private", "permission": "rw"} in actual["communities"]
    assert actual["contact"] == "admin@example.com"
    assert actual["location"] == "network-lab" 
    assert actual["traps"] == {"snmp": True, "syslog": True}
    assert {"snmp_ip": "10.10.10.50", "snmp_verison": "2c"} in actual["hosts"]
    assert {"snmp_ip": "10.10.10.60", "snmp_verison": "2c"} in actual["hosts"]

def test_live_check_snmp(sesh):
    expected = {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
    }
    state = collect_device_state(sesh)
    actual = build_snmp_netmiko(state)
    ok, failures = check_snmp(expected, actual)

    assert ok is True 
    assert failures == []

def test_live_compliance_snmp(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert result["status"] == "SUCCESS"
    assert all(
            "SNMP Configuration Already Compliant" in r for r in result["initial_issues"]
        )
    assert any(
            "SNMP IP: 10.10.10.50 (community name = private)" in r for r in result["initial_issues"]
        )

def test_live_rogue_snmp_community(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            #{"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) Drift Detected: Rouge SNMP Community Found" in r for r in result["initial_issues"]
        )
    assert any(
            "Name: private (permission: rw)" in r for r in result["initial_issues"]
        )

def test_live_missing_community(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
            #adding extra 
            {"snmp_name": "extra_community","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) Missing SNMP Community" in r for r in result["initial_issues"]
        )
    assert any(
            "Name: extra_community" in r for r in result["initial_issues"]
        )
    assert any(
            "[DRY_RUN] Would Configure SNMP" in r for r in result["initial_issues"]
        )
    assert any(
            "Community Name: extra_community (permission = rw)" in r for r in result["initial_issues"]
        )

def test_live_mismatched_permission(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            #changing rw to ro 
            {"snmp_name": "private","permission": "ro"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )
    
    assert any(
            "(SNMP) Mismatched Community Permission" in r for r in result["initial_issues"]
        )
    assert any(
            "Name: private" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: ro | Actual: rw" in r for r in result["initial_issues"]
        )

def test_live_mismatched_contact(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        #changing example to gmail
        "contact": "admin@gmail.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) Mismatched Contact" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: admin@gmail.com | Actual: admin@example.com" in r 
            for r in result["initial_issues"]
        )

def test_live_extra_snmp_host_ip(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            },
            #adding host not on device 
            {
                "snmp_ip": "10.10.10.70",
                "snmp_version": "2c",
                "snmp_name": "voice_snmp"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) Missing SNMP Host | Name: voice_snmp" in r for r in result["initial_issues"]
        )
    assert any(
            "Host IP: 10.10.10.70" in r for r in result["initial_issues"]
        )

def test_live_mismatched_host_ip(sesh):
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            {   #changing 10.10.10.60 to .80
                "snmp_ip": "10.10.10.80",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) Mismatched SNMP Host IP" in r for r in result["initial_issues"]
        )
    assert any(
            "Name: private" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: 10.10.10.80 | Actual: 10.10.10.80" in r for r in result["initial_issues"]
        )

def test_live_mismatched_version(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            { 
                "snmp_ip": "10.10.10.60",
                #changing 2c to 3 
                "snmp_version": "3",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) Mismatched SNMP Version" in r for r in result["initial_issues"]
        )
    assert any(
            "Name: private" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: 3 | Actual: 2c" in r for r in result["initial_issues"]
        )

def test_live_mismatched_location(sesh): 
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            { 
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            "snmp": True,
            "syslog": True,
        },
        #changing location
        "location": "Network-Lab Florida",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) SNMP Location Mismatch" in r for r in result["initial_issues"]
        )
    assert any(
            "Expected: network-lab florida | Actual: network-lab" in r for r in result["initial_issues"]
        )

def test_live_mismatched_traps(sesh):
    context = {
        "snmp": {
        "communities": [
            {"snmp_name": "public","permission": "ro"},
            {"snmp_name": "private","permission": "rw"}
        ],
        "hosts": [
            {
                "snmp_ip": "10.10.10.50",
                "snmp_version": "2c",
                "snmp_name": "public"
            },
            { 
                "snmp_ip": "10.10.10.60",
                "snmp_version": "2c",
                "snmp_name": "private"
            }
        ],
        "traps": {
            #inverting all traps to false 
            "snmp": False,
            "syslog": False,
        },
        "location": "Network-Lab",
        "contact": "admin@example.com"
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

    result = compliance_snmp(
            sesh,
            "192.168.255.11",
            context,
            state,
            device_result,
            log
        )

    assert any(
            "(SNMP) Mismatched Traps | Config" in r for in result["initial_issues"]
        )
    assert any(
            "(SNMP) Mismatched Traps | SNMP" in r for r in result["initial_issues"]
        )
    