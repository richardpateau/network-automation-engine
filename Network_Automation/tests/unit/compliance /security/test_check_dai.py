import pytest
from src.compliance.security.dai.check import check_dai

@pytest.fixture 
def exp_dai():
	return {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
@pytest.fixture 
def act_dai():
	return {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}

def test_check_dai_compliant(exp_dai, act_dai):
	ok, failures = check_dai(exp_dai, act_dai)
	assert ok is True 
	assert failures == []

def test_check_dai_actaul_dai_false():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": False, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	ok, failures = check_dai(expected, actual)
	assert ok is False
	assert any("(DAI) Operational State Mismatch" in f for f in failures)
	assert any("Expected: True | Actual: False" in f for f in failures)

def test_check_dai_actaul_dai_missing_vlans():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Missing VLAN(s)" in f for f in failures)
	assert any("[20, 30, 40]" in f for f in failures)

def test_check_dai_actaul_dai_extra_vlans():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Drift: Extra VLAN(s) Found" in f for f in failures)
	assert any("[20, 30, 30]" in f for f in failures)

def test_check_dai_actaul_dai_log_buffer_enabled():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": False, 
			"entries": 1024
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Log Buffer State Mismatch" in f for f in failures)
	assert any(f"Expected: True | Actual: False" in f for f in failures)

def test_check_dai_actaul_dai_log_entries_mismatch():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 2048
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Log Buffer Entries Mismatch" in f for f in failures)
	assert any(f"Expected: 1024 | Actual: 2048" in f for f in failures)

def test_check_dai_actaul_dai_extra_interfaces():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			},
			"gigabitethernet2": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Drift: Extra Interface Configured with DAI" in f for f in failures)
	assert any("Interface: gigabitethernet2")

def test_check_dai_actaul_dai_missing_interface():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			},
			"gigabitethernet2": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Missing Interface Not Configured with DAI" in f for f in failures)
	assert any("Interface: gigabitethernet2")

def test_check_dai_actaul_dai_rate_limit_mismatch():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 30, 
				"trusted": False
			}
			
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Misatched Rate Limit Configuration" in f for f in failures)
	assert any("Expected: 30 | Actual: 15" in f for f in failures)

def test_check_dai_actaul_dai_trusted_interface():
	expected =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": None, 
				"trusted": True
			}
			
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}
	actual =  {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40], 
		"interfaces": {
			"gigabitethernet1": {
				"rate_limit": 15, 
				"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True, 
			"entries": 1024
		}
	}

	ok, failures = check_dai(expected, actual)
	assert ok is False 
	assert any("(DAI) Mismatched Trusted Interface Configuration" in f for f in failures)
	assert any("Expected: True | Actual: False" in f for f in failures)