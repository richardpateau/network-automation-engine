import pytest
from src.compliance.security.dhcp_snooping.check import check_snooping

@pytest.fixture 
def exp_snooping():
	return {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}

@pytest.fixture
def act_snooping():
	return {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}

def test_check_snooping_complaint(exp_snooping, act_snooping): 
	ok, failures = check_snooping(exp_snooping, act_snooping)
	assert ok is True 
	assert failures == []

def test_check_snooping_missing_vlans():
	expected = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	actual =  {
		"enabled_vlans": [10,20], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	ok ,failures = check_snooping(expected, actual)
	assert ok is False 
	assert any("(DHCP Snooping) Missing VLAN(s) On Device" in f for f in failures)
	assert any("VLAN(s): [30, 40, 50]" in f for f in failures)

def test_check_snooping_extra_vlans():
	expected = {
		"enabled_vlans": [10,20], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	actual =  {
		"enabled_vlans": [10,20,30,40,50,60], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	ok ,failures = check_snooping(expected, actual)
	assert ok is False 
	assert any("(DHCP Snooping) Drift: Extra VLAN on Device" in f for f in failures)
	assert any("VLAN(s): [30, 40, 50, 60]" in f for f in failures)

@pytest.mark.parametrize("interface", 
		[
			"gigabitethernet1/0", 
			"gigabitethernet1/1", 
			"gigabitethernet2", 
			"fastethernet2", 
			"fastethernet2/2"
		]
	)
def test_check_snooping_extra_interfaces(interface):
	expected = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	actual = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			},
			interface: {
				"rate_limit": 20, 
				"trusted": False 
				},
		"option82": False 
	   	}
	}

	ok, failures = check_snooping(expected, actual)
	assert ok is False 
	assert any("(DHCP Snooping) Extra Interface Configured" in f for f in failures)
	assert any(f"Interface: {interface}" in f for f in failures)

@pytest.mark.parametrize("interface", 
		[
			"gigabitethernet1/0", 
			"gigabitethernet1/1", 
			"gigabitethernet2", 
			"fastethernet2", 
			"fastethernet2/2"
		]
	)
def test_check_snooping_missing_interfaces(interface):
	expected = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			},
			interface: {
				"rate_limit": 20, 
				"trusted": False 
			},
		},
		"option82": False 
	}
	actual = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			},
		"option82": False 
	   	}
	}

	ok, failures = check_snooping(expected, actual)
	assert ok is False 
	assert any("(DHCP Snooping) Missing Interface Configured w DHCP Snooping" in f for f in failures)
	assert any(f"Interface: {interface}" in f for f in failures)
@pytest.mark.parametrize("rate_limit", [10,30,40,70,100])
def test_check_snooping_rate_limit_mismatch(rate_limit): 
	expected = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	actual = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": rate_limit, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	ok, failures = check_snooping(expected, actual)
	assert ok is False 
	assert any("(DCHP Snooping) Rate Limit Mismatch" in f for f in failures)
	assert any(f"Expected: 20 | Actual: {rate_limit}")

def test_check_snooping_trusted_mismatch():
	expected = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}
	actual = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": None, 
				"trusted": True 
			}
		},
		"option82": False 
	}

	ok, failures = check_snooping(expected, actual)
	assert ok is False 
	assert any("(DHCP Snooping) Trusted Interface Config Mismatched" in f for f in failures)
	assert any(f"Expected: False | Actual: True" in f for f in failures)

def test_check_snooping_mismatched_option82(): 
	expected = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": True 
	}
	actual = {
		"enabled_vlans": [10,20,30,40,50], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 20, 
				"trusted": False 
			}
		},
		"option82": False 
	}

	ok, failures = check_snooping(expected, actual)
	assert ok is False
	assert any("(DHCP Snooping) Mismatched Option 82 Config" in f for f in failures)
	assert any("Expected: True | Actual: False" in f for f in failures)