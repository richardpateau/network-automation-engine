import pytest
from src.compliance.security.port_security.check import check_port_security

@pytest.fixture 
def exp_port_security():
	return {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			}
		}
	}

@pytest.fixture 
def act_port_security():
	return {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			}
		}
	}

def test_check_port_security_compliant(exp_port_security, act_port_security):
	ok, failures = check_port_security(exp_port_security, act_port_security)
	assert ok is True 
	assert failures == []

@pytest.mark.parametrize("interface", ["gigabitethernet2", "gigabitethernet3", "gigabitethernet4"])
def test_check_port_security_extra_interfaces(interface):
	expected = {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			}
		}
	}
	actual = {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			},
			interface: {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			}

		}
	}

	ok, failures = check_port_security(expected, actual)
	assert ok is False 
	assert any("(Port Security) Drift: Extra Interface Configured" in f for f in failures)
	assert any(f"Interface: {interface}" in f for f in failures)

@pytest.mark.parametrize("interface", ["gigabitethernet2", "gigabitethernet3", "gigabitethernet4"])
def test_check_port_security_missing_interfaces(interface):
	expected = {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			},
			interface: {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			}
		}
	}
	actual = {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			},

		}
	}
	
	ok, failures = check_port_security(expected, actual)
	assert ok is False
	assert any("(Port Security) Missing Interface Not Configured with Port Security"
				in f for f in failures
		)
	assert any(f"Interface: {interface}" in f for f in failures)

def test_check_port_security_enabled_mismatch():
	expected = {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			}
		}
	}
	actual = {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": False, 
				"mac_addresses": [],
				"maximum": 2, 
				"sticky": True, 
				"violation": "restrict"
			}
		}
	}

	ok, failures = check_port_security(expected, actual)
	assert ok is False
	assert any("(Port Security) Port Security Should Be Enabled Mismatch" in f for f in failures)
	assert any("Expected: True | Actual: False" in f for f in failures)

def test_check_port_security_sticky_mismatch():
	expected = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": [],
                "maximum": 2, 
                "sticky": False, 
                "violation": "restrict"
            }
        }
    }
    actual = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": [],
                "maximum": 2, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }
    ok, failures = check_port_security(expected, actual)
    assert ok is False 
    assert any("(Port Security) Mismatched Sticky Configuration" in f for f in failures)
    assert any("Expected: False | Actual: True" in f for f in failures)

@pytest.mark.parametrize("maximum", [1,3,5,6,8])
def test_check_port_security_maximum_mismatch(maximum):
	expected = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": [],
                "maximum": 2, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }
    actual = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": [],
                "maximum": maximum, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }

    ok, failures = check_port_security(expected, actual)
    assert ok is False 
    assert any("(Port Security) Mismatched Maximum Allowed" in f for f in failures)
    assert any(f"Expected: 2 | Actual: {maximum}" in f for f in failures)

def test_check_port_security_violation_mismatch():
	expected = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": [],
                "maximum": 2, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }
    actual = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": [],
                "maximum": 2, 
                "sticky": True, 
                "violation": "protect"
            }
        }
    }

    ok, failures = check_port_security(expected, actual)
    assert ok is False
    assert any("(Port Security) Mismatched Violation Configuration" in f for f in failures)
    assert any(f"Expected: restrict | Actual: protect" in f for f in failures)

def test_check_port_security_missing_mac():
	expected = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": ["02:00:00:12:34:01", "02:00:00:12:34:02"],
                "maximum": 2, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }
    actual = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": ["02:00:00:12:34:01"],
                "maximum": 2, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }

    ok, failures = check_port_security(expected, actual)
    assert ok is False 
    assert any("(Port Security) Missing MAC Address" in f for f in failures)
    assert any("02:00:00:12:34:02" in f for f in failures)

 def test_check_port_security_extra_mac():
	expected = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": ["02:00:00:12:34:01"],
                "maximum": 2, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }
    actual = {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True, 
                "mac_addresses": ["02:00:00:12:34:01", "02:00:00:12:34:06"],
                "maximum": 2, 
                "sticky": True, 
                "violation": "restrict"
            }
        }
    }

    ok, failures = check_port_security(expected, actual)
    assert ok is False 
    assert any("(Port Security) Drift: Extra MAC Address Found" in f for f in failures)
    assert any("02:00:00:12:34:06" in f for f in failures)