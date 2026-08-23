import pytest
from src.compliance.switching.etherchannel.check import check_etherchannel

@pytest.fixture 
def exp_etherchannel():
	return {
		"enabled": True, 
		"groups": {
			2: {
				"mode": "active", 
				"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
				"description": "link to R1",
				"switchport_mode": "trunk",
				"type": "lacp"
			}
		}
	}


@pytest.fixture
def act_etherchannel():
	return {
		"enabled": True, 
		"groups": {
			2: {
				"mode": "active", 
				"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
				"description": "link to R1",
				"switchport_mode": "trunk",
				"type": "lacp"
			}
		}
	}

def test_check_etherchannel_compliant(exp_etherchannel, act_etherchannel):
	ok, failures = check_etherchannel(exp_etherchannel, act_etherchannel)
	assert ok is True 
	assert failures == []

def test_check_etherchannel_mismatched_enabled():
	expected = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}
	actual = {
			"enabled": False, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Misconfigured Operational Mode" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)

def test_check_etherchannel_extra_groups(): 
	expected = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				},
				3: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				},
				4: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Drift: Rogue Port Channel(s)" in f for f in failures)
	assert any("[3, 4]" in f for f in failures)

def test_check_etherchannel_missing_groups():
	expected = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				},
				3: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				},
			}
		}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Missing Port Channel Group" in f for f in failures)
	assert any("3" in f for f in failures)

@pytest.mark.parametrize("interface", 
		[
			"gigabitethernet1/0",
			"gigabitethernet1/1/1",
			"fastethernet1",
			"fastethernet1/1"
		]
	)
def test_check_etherchannel_missing_interface(interface):
	expected = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", interface],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Missing Interface" in f for f in failures)
	assert any("2" in f for f in failures)
	assert any(f"Interface: {interface}" in f for f in failures)


@pytest.mark.parametrize("interface", 
		[
			"gigabitethernet1/0",
			"gigabitethernet1/1/1",
			"fastethernet1",
			"fastethernet1/1"
		]
	)
def test_check_etherchannel_extra_interface(interface):
	expected = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", interface],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Rogue Interface" in f for f in failures)
	assert any("2" in f for f in failures)
	assert any(f"Interface: {interface}" in f for f in failures)

def test_check_etherchannel_mode_mismatch():
	expected = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "passive", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Mode Mismatch" in f for f in failures)
	assert any("Expected: active" in f for f in failures)
	assert any("Actual: passive" in f for f in failures)

def test_check_etherchannel_type_mismatch():
	expected = {
				"enabled": True, 
				"groups": {
					2: {
						"mode": "active", 
						"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
						"description": "link to R1",
						"switchport_mode": "trunk",
						"type": "lacp"
					}
				}
			}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "trunk",
					"type": "pagp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Mismatched Etherchannel Type" in f for f in failures)
	assert any("2" in f for f in failures)
	assert any("Expected: lacp" in f for f in failures)
	assert any("Actual: pagp" in f for f in failures)

def test_check_etherchannel_switchport_mode_mismatch():
	expected = {
				"enabled": True, 
				"groups": {
					2: {
						"mode": "active", 
						"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
						"description": "link to R1",
						"switchport_mode": "trunk",
						"type": "lacp"
					}
				}
			}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R1",
					"switchport_mode": "access",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Mismatched Switchport Mode" in f for f in failures)
	assert any("2" in f for f in failures)
	assert any("Expected: trunk" in f for f in failures)
	assert any("Actual: access" in f for f in failures)

def test_check_etherchannel_description_mismatch():
	expected = {
				"enabled": True, 
				"groups": {
					2: {
						"mode": "active", 
						"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
						"description": "link to R1",
						"switchport_mode": "trunk",
						"type": "lacp"
					}
				}
			}
	actual = {
			"enabled": True, 
			"groups": {
				2: {
					"mode": "active", 
					"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
					"description": "link to R2",
					"switchport_mode": "trunk",
					"type": "lacp"
				}
			}
		}

	ok, failures = check_etherchannel(expected, actual)
	assert ok is False 
	assert any("(Etherchannel) Mismatched Description" in f for f in failures)
	assert any("2" in f for f in failures)
	assert any("Expected: link to R1" in f for f in failures)
	assert any("Actual: link to R2" in f for f in failures)
	
