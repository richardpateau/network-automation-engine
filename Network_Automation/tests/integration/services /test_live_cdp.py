import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_cdp_netmiko
from src.compliance.services.cdp.check import check_cdp
from src.compliance.services.cdp.compliance import compliance_cdp

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

def test_live_build_cdp(sesh): 
	state = collect_device_state(sesh)
	actual = build_cdp_netmiko(state)

	assert actual 
	assert actual["enabled"] is True 
	assert actual["timer"] == 60 
	assert actual["holdtime"] == 180
	assert actual["interfaces"]["gigabitethernet0/1"]["enabled"] is True 
	assert actual["interfaces"]["gigabitethernet0/2"]["enabled"] is True 

def test_live_check_cdp(sesh): 
	state = collect_device_state(sesh)
	actual = build_cdp_netmiko(state)

	expected = {
			    "enabled": True,
			    "timer": 60,
			    "holdtime": 180,
			    "interfaces": {
			        "gigabitethernet0/1": {
			            "enabled": True
			        },
			        "gigabitethernet0/2": {
			            "enabled": True
			        }
			    }
			}

	ok, failures = check_cdp(expected, actual)

	assert ok is True 
	assert failures == []

def test_live_compliance_cdp(sesh): 
	context = {
		"cdp": {
			    "enabled": True,
			    "timer": 60,
			    "holdtime": 180,
			    "interfaces": {
			        "gigabitethernet0/1": {
			            "enabled": True
			        },
			        "gigabitethernet0/2": {
			            "enabled": True
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

    result = compliance_cdp(
    		sesh,
    		"192.168.255.11",
    		context,
    		state,
    		device_result,
    		log
    	)

    assert result["status"] == "SUCCESS"
    assert all(
    		"CDP Configuration Already Compliant" in r for r in result["actions_taken"]
    	)
    assert any(
    		"Timer: 60" in r for r in result["actions_taken"]
    	)
    assert any(
    		"HoldTime: 180" in r for r in result["actions_taken"]
    	)

@patch("src.compliance.services.cdp.compliance.DRY_RUN", True)
def test_live_global_cdp_disabled_mismatched(sesh): 
	context = {
		"cdp": {
			    "enabled": False,
			    "timer": 60,
			    "holdtime": 180,
			    "interfaces": {
			        "gigabitethernet0/1": {
			            "enabled": True
			        },
			        "gigabitethernet0/2": {
			            "enabled": True
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

    result = compliance_cdp(
    		sesh,
    		"192.168.255.11",
    		context,
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(CDP) Operational State Mismatch" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Expected: False | Actual: True" in r for r in result["initial_issues"]
    	)

@patch("src.compliance.services.cdp.compliance.DRY_RUN", True)
def test_live_mismatched_timer(sesh): 
	context = {
		"cdp": {
			    "enabled": True,
			    "timer": 65, #changing 60 to 65
			    "holdtime": 180,
			    "interfaces": {
			        "gigabitethernet0/1": {
			            "enabled": True
			        },
			        "gigabitethernet0/2": {
			            "enabled": True
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

    result = compliance_cdp(
    		sesh,
    		"192.168.255.11",
    		context,
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(CDP) Timer Mismatch" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Expected: 65 | Actual: 60" in r for r in result["initial_issues"]
    	)

@patch("src.compliance.services.cdp.compliance.DRY_RUN", True)
def test_live_mismatched_hold_timer(sesh): 
	context = {
		"cdp": {
			    "enabled": True,
			    "timer": 60, 
			    "holdtime": 120, #changing 180 to 120
			    "interfaces": {
			        "gigabitethernet0/1": {
			            "enabled": True
			        },
			        "gigabitethernet0/2": {
			            "enabled": True
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

    result = compliance_cdp(
    		sesh,
    		"192.168.255.11",
    		context,
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(CDP) HoldTime Mismatch" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Expected: 120 | Actual: 180" in r for r in result["initial_issues"]
    	)

@patch("src.compliance.services.cdp.compliance.DRY_RUN", True)
def test_live_rouge_interface(sesh): 
	context = {
		"cdp": {
			    "enabled": True,
			    "timer": 60, 
			    "holdtime": 180,
			    "interfaces": {
			        "gigabitethernet0/2": {
			            "enabled": True
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

    result = compliance_cdp(
    		sesh,
    		"192.168.255.11",
    		context,
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(CDP) Rogue Interface Configured with CDP" in r for r in result["initial_issues"]
    	)
    assert any(
    		"gigabitethernet0/1" in r for r in result["initial_issues"]
    	)

@patch("src.compliance.services.cdp.compliance.DRY_RUN", True)
def test_live_missing_interface(sesh): 
	context = {
		"cdp": {
			    "enabled": True,
			    "timer": 60, 
			    "holdtime": 180,
			    "interfaces": {
			        "gigabitethernet0/1": {
			            "enabled": True
			        },
			        "gigabitethernet0/2": {
			            "enabled": True
			        },
			        #interface not on device | SOT error caught 
			        "gigabitethernet2": {
			            "enabled": True
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

    result = compliance_cdp(
    		sesh,
    		"192.168.255.11",
    		context,
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(CDP) Missing Interface Not Configured w/ CDP" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Potential SOT Error" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Interface: gigabitethernet2" in r for r in result["initial_issues"] 
    	)
    assert any(
    		"[DRY_RUN] Would Configure CDP" in r for r in result["actions_taken"]
    	)

@patch("src.compliance.services.cdp.compliance.DRY_RUN", True)
def test_live_rogue_interface_on(sesh):
	context = {
		"cdp": {
			    "enabled": True,
			    "timer": 60, 
			    "holdtime": 180,
			    "interfaces": {
			        "gigabitethernet0/1": {
			            "enabled": True
			        },
			        #inverting g0/2 to False 
			        "gigabitethernet0/2": {
			            "enabled": False
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

    result = compliance_cdp(
    		sesh,
    		"192.168.255.11",
    		context,
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(CDP) Interface Operational State Mismatch" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Expected: False | Actual: True" in r for r in result["initial_issues"]
    	)