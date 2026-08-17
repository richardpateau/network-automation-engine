import pytest 
from src.compliance.routing.nat import check_nat

@pytest.fixture
def exp_nat():
    return {
        "pat": {
            "acl": "10",
            "interface": "GigabitEthernet0/0",
            "overload": True
        },
        "static": [
            {"inside_ip": "10.0.0.1", "outside_ip": "203.0.113.1"},
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.2"}
        ],
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": "10",
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ],
        "interfaces": {
            "inside": ["GigabitEthernet0/1"],
            "outside": ["GigabitEthernet0/0"]
        }
    }

@pytest.fixture
def act_nat():
    return {
        "pat": {
            "acl": "10",
            "interface": "GigabitEthernet0/0",
            "overload": True
        },
        "static": [
            {"inside_ip": "10.0.0.1", "outside_ip": "203.0.113.1"},
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.2"}
        ],
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": "10",
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ],
        "interfaces": {
            "inside": ["GigabitEthernet0/1"],
            "outside": ["GigabitEthernet0/0"]
        }
    }

def test_check_nat_compliant(exp_nat, act_nat): 
	ok, failures = check_nat(exp_nat, act_nat)

	assert ok is True 
	assert failures == []

def test_check_nat_missing_pat():
	pat = {
		"pat": {
            "acl": "10",
            "interface": "GigabitEthernet0/0",
            "overload": True
		}
	}

	 
	ok, failures = check_nat(pat, {})
	assert ok is False 
	assert any("(NAT) Configuration Drift: Missing PAT" in r for r in failures)

def test_check_nat_extra_pat():
	actual = {
		"pat": {
            "acl": "10",
            "interface": "GigabitEthernet0/0",
            "overload": True
		}
	}

	ok, failures = check_nat({}, actual)

	assert ok is False 
	assert any("Unexpected PAT Configuration" in f for f in failures)

def test_check_nat_missing_static_mapping():
	expected = {
		"static": [
            {"inside_ip": "10.0.0.1", "outside_ip": "203.0.113.1"},
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.2"}
        ]
	}

	ok, failures = check_nat(expected, {})

	assert ok is False
	assert any("Missing Static Mapping" in r for r in failures)

def test_check_nat_unexpected_static_mapping():
    actual = {
        "static": [
            {"inside_ip": "10.0.0.1", "outside_ip": "203.0.113.1"},
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.2"}
        ]
    }

    ok, failures = check_nat({}, actual)
    
    assert ok is False
    assert any("Unexpected Static Configuration Found" in f for f in failures)

def test_check_nat_wrong_static_missing():
	expected = {
		"static": [
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.2"}
        ]
	}
	actual = {
		"static": [
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.3"}
        ]
	}
	
	ok, failures = check_nat(expected, actual)

	assert ok is False 
	assert any("(NAT STATIC) Missing Static Map" in f for f in failures)
	assert any("Inside Local: 10.0.0.2 | Outside Global: 203.0.113.2"
				in f for f in failures
		)

def test_check_nat_wrong_static_extra():
    expected = {
        "static": [
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.2"}
        ]
    }
    actual = {
        "static": [
            {"inside_ip": "10.0.0.2", "outside_ip": "203.0.113.2"},
            {"inside_ip": "10.0.0.1", "outside_ip": "203.0.113.2"}
        ]
    }
    
    ok, failures = check_nat(expected, actual)

    assert ok is False 
    assert any("Extra (Drift) Static Configuration" in f for f in failures)
    assert any("Inside Local: 10.0.0.1 | Outside Global: 203.0.113.2")

def test_check_nat_no_dynamic():
    expected = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": "10",
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    ok, failures = check_nat(expected, {})

    assert ok is False
    assert any("Missing Dynamic NAT Configuration" in f for f in failures)

def test_check_nat_unexpected_dynamic():
    actual = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": "10",
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    ok, failures = check_nat({}, actual)

    assert ok is False 
    assert any("Unexpected Dynamic NAT Configuration Found" in f for f in failures)

def test_check_nat_no_pool():
    expected = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            },
             {
                "pool_name": "nat",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }  
    actual = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": "10",
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    ok, failures = check_nat(expected, actual)

    assert ok is False 
    assert any("(Dynamic NAT) Expected Pool Not Found on Device" in f for f in failures)
    assert any("Expected: nat" in f for f in failures)

def test_check_nat_dynamic_acl():
    expected = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            },
        ]
    }  
    actual = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 20,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    ok, failures = check_nat(expected, actual)

    assert ok is False 
    assert any("(Dynamic NAT) ACL Mismatch" in f for f in failures)
    assert any(
             f"Expected: 10 | "
             f"Actual: 20" 
             in f for f in failures
        )

def test_check_nat_dynamic_start_ip():
    expected = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            },
        ]
    }  
    actual = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.101",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    assert ok is False 
    assert any("(Dynamic NAT) Mismatched Pool Start IP" in f for f in failures)
    assert any(
            f"Expected: 203.0.113.100 | "
            f"Actual: 203.0.113.101"
            in f for f in failures
        )

def test_check_nat_dynamic_end_ip():
    expected = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.151",
                "mask": "255.255.255.0"
            },
        ]
    }  
    actual = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    ok, failures = check_nat(expected, actual)

    assert ok is False 
    assert any("(Dynamic NAT) Mismatched End IP" in f for f in failures)
    assert any(
             f"Expected: 203.0.113.150 | "
             f"Actual: {actual.get('end_ip', '')}"
        )

def test_check_nat_dynamic_mask():
    expected = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.0.0"
            },
        ]
    }  
    actual = {
        "dynamic": [
            {
                "pool_name": "NAT_POOL",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    ok, failures = check_nat(expected, actual)

    assert ok is False
    assert any("(Dynamic NAT) Mismatched Mask" in f for f in failures)
    assert any(
            f" Expected: 255.255.0.0 | "
            f"Actual: 255.255.255.0"
            in f for f in failures
        )

def test_check_nat_dynamic_extra_pools():
    expected = {
        "dynamic": [
            {
                "pool_name": "nat_pool",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.0.0"
            },
        ]
    }  
    actual = {
        "dynamic": [
            {
                "pool_name": "nat_pool",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            },
             {
                "pool_name": "nat_pool_extra",
                "acl": 10,
                "start_ip": "203.0.113.100",
                "end_ip": "203.0.113.150",
                "mask": "255.255.255.0"
            }
        ]
    }

    ok, failures = check_nat(expected, actual)

    assert ok is False
    assert any("Unexpected Pool Found on Device | nat_pool_extra" in r for r in failures)

def test_check_nat_missing_inside():
    expected = {
        "interfaces": {
            "inside": ["gigabitethernet0/1", "gigabitethernet0/2"]
        }
    }

    ok, failures = check_nat(expected, {})

    assert ok is False 
    assert any("(NAT) Missing Inside Interface: gigabitethernet0/1, gigabitethernet0/2")

def test_check_nat_extra_inside():
    expected = {
        "interfaces": {
            "inside": ["gigabitethernet0/1", "gigabitethernet0/2"]
        }
    }
    actual = {
        "interfaces": {
            "inside": ["gigabitethernet0/1", "gigabitethernet0/2", "gigabitethernet3"]
        }
    }
    ok, failures = check_nat(expected, actual)

    assert ok is False 
    assert any("(NAT) Extra Inside Interface: gigabitethernet3")

def test_check_nat_missing_outside():
    expected = {
        "interfaces": {
            "inside": ["gigabitethernet0/1", "gigabitethernet0/2"]
        }
    }

    ok, failures = check_nat(expected, {})

    assert ok is False 
    assert any("(NAT) Missing Outside Interface: gigabitethernet0/1, gigabitethernet0/2")

def test_check_nat_extra_outside():
    expected = {
        "interfaces": {
            "inside": ["gigabitethernet0/1", "gigabitethernet0/2"]
        }
    }
    actual = {
        "interfaces": {
            "inside": ["gigabitethernet0/1", "gigabitethernet0/2", "gigabitethernet3"]
        }
    }
    ok, failures = check_nat(expected, actual)

    assert ok is False 
    assert any("(NAT) Missing Outside Interface: gigabitethernet3")