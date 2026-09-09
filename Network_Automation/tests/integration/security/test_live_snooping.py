import os
import pytest
from netmiko import ConnectHandler
from unittest.mock import MagicMock, patch
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_snooping
from src.compliance.security.dhcp_snooping.check import check_snooping
from src.compliance.security.dhcp_snooping.compliance import compliance_snooping

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

def test_live_build_snooping(sesh):
	state = collect_device_state(sesh)
	actual = build_snooping(state)

	assert actual 
	assert actual["enabled_vlans"] == [10, 20, 30]
	assert actual["option82"] == False
	assert actual["interfaces"]["gigabitethernet0/1"] == {"rate_limit": None, "trusted": True}
	assert actual["interfaces"]["gigabitethernet0/2"] == {"rate_limit": 10, "trusted": False}
	assert actual["interfaces"]["gigabitethernet0/3"] == {"rate_limit": 30, "trusted": False}

def test_live_check_snooping(sesh): 
	state = collect_device_state(sesh)
	actual = build_snooping(state)

	expected = {
		"enabled_vlans": [10, 20, 30],
		"interfaces": {
			"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
			"gigabitethernet0/2": {"rate_limit": 10, "trusted": False},
			"gigabitethernet0/3": {"rate_limit": 30, "trusted": False}
		},
		"option82": False
	}

	ok, failures = check_snooping(expected, actual)

	assert ok is True 
	assert failures == []

def test_live_compliance_snooping(sesh): 
	context = {
		"dhcp_snooping": {
			"enabled_vlans": [10, 20, 30],
			"interfaces": {
				"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
				"gigabitethernet0/2": {"rate_limit": 10, "trusted": False},
				"gigabitethernet0/3": {"rate_limit": 30, "trusted": False}
			},
			"option82": False
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

    assert result["status"] == "SUCCESS"
    assert all(
    		"DHCP Snooping Configuration Already Compliant" in r for r in result["actions_taken"]
    	)
    assert any(
    		"Enabled VLANs: 10, 20, 30" in r for r in result["actions_taken"]
    	)
    assert any(
    		"Trusted Interface: gigabitethernet0/1" in r for r in result["actions_taken"]
    	)

@patch("src.compliance.security.dhcp_snooping.compliance.DRY_RUN", True)
def test_live_missing_vlan(sesh): 
	context = {
		"dhcp_snooping": {
			"enabled_vlans": [10, 20, 30, 40, 50],
			"interfaces": {
				"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
				"gigabitethernet0/2": {"rate_limit": 10, "trusted": False},
				"gigabitethernet0/3": {"rate_limit": 30, "trusted": False}
			},
			"option82": False
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(DHCP Snooping) Missing VLAN(s) On Device" in r for r in result["initial_issues"]
    	)
    assert any(
    		"VLAN(s): [40, 50]" in r for r in result["initial_issues"]
    	)
    assert any(
    		"[DRY_RUN] Would Configure DHCP Snooping" in r for r in result["actions_taken"]
    	)
    assert any(
    		"Enabled VLANs: 10, 20, 30, 40, 50" in r for r in result["initial_issues"]
    	)

def test_live_rogue_vlan(sesh):
	context = {
		"dhcp_snooping": {
			"enabled_vlans": [10],
			"interfaces": {
				"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
				"gigabitethernet0/2": {"rate_limit": 10, "trusted": False},
				"gigabitethernet0/3": {"rate_limit": 30, "trusted": False}
			},
			"option82": False
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(DHCP Snooping) Drift: Rogue VLAN on Device" in r for r in result["initial_issues"]
    	)
    assert any(
    		"VLAN(s): [20, 30]" in r for r in result["initial_issues"]
    	)

def test_live_extra_mismatch(sesh): 
	context = {
		"dhcp_snooping": {
			"enabled_vlans": [10],
			"interfaces": {
				"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
				"gigabitethernet0/2": {"rate_limit": 10, "trusted": False},
			},
			"option82": False
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(DHCP Snooping) Extra Interface found | Potential SOT mismatch" in r 
    		for r in result["initial_issues"]
    	)
    assert any(
    		"Interface: gigabitethernet0/3" in r for r in result["initial_issues"]
    	)

def test_live_missing_interface(sesh): 
	context = {
		"dhcp_snooping": {
			#removing 20 and 30
			"enabled_vlans": [10],
			"interfaces": {
				"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
				"gigabitethernet0/2": {"rate_limit": 10, "trusted": False},
				"gigabitethernet0/3": {"rate_limit": 30, "trusted": False},
				"fastethernet0/1": {"rate_limit": 30, "trusted": False}
			},
			"option82": False
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

   	assert any(
   			"(DHCP Snooping) Missing Interface | Potential SOT mismatch" in r 
   			for r in result["initial_issues"]
   		)
   	assert any(
   			"Interface: fastethernet0/1" in r for r in result["initial_issues"]
   		)

def test_live_mismatched_rate_limit(sesh): 
	context = {
		"dhcp_snooping": {
			"enabled_vlans": [10],
			"interfaces": {
				"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
				#changing 10 to 20 
				"gigabitethernet0/2": {"rate_limit": 20, "trusted": False},
				"gigabitethernet0/3": {"rate_limit": 30, "trusted": False},
			},
			"option82": False
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(DCHP Snooping) Rate Limit Mismatch" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Expected: 20 | Actual: 10" in r for r in result["initial_issues"]
    	)

def test_live_mismatched_trusted_interface(sesh): 
	context = {
		"dhcp_snooping": {
			"enabled_vlans": [10],
			"interfaces": {
				#changing True to False g0/1
				"gigabitethernet0/1": {"rate_limit": None, "trusted": False},
				"gigabitethernet0/2": {"rate_limit": 20, "trusted": False},
				"gigabitethernet0/3": {"rate_limit": 30, "trusted": False},
			},
			"option82": False
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(DHCP Snooping) Trusted Interface Config Mismatched" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Interface: gigabitethernet0/1" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Expected: False | Actual: True" in r for r in result["initial_issues"]
    	)

def test_live_option_82(sesh): 
	context = {
		"dhcp_snooping": {
			"enabled_vlans": [10],
			"interfaces": {
				"gigabitethernet0/1": {"rate_limit": None, "trusted": True},
				"gigabitethernet0/2": {"rate_limit": 20, "trusted": False},
				"gigabitethernet0/3": {"rate_limit": 30, "trusted": False},
			},
			"option82": True
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

    result = compliance_snooping(
    		sesh,
    		"192.168.255.11",
    		context, 
    		state,
    		device_result,
    		log
    	)

    assert any(
    		"(DHCP Snooping) Mismatched Option 82 Configuration" in r for r in result["initial_issues"]
    	)
    assert any(
    		"Expected: True | Actual: False" in r for r in result["initial_issues"]
    	)
    
