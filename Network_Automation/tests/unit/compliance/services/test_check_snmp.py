import pytest
from src.compliance.services.snmp.check import check_snmp

@pytest.fixture 
def exp_snmp():
	return {
		"communities": [{"snmp_name": "private", "permission": "rw"}, 
						{"snmp_name": "public", "permission": "ro"}],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
 
@pytest.fixture 
def act_snmp():
	return {
		"communities": [{"snmp_name": "private", "permission": "rw"}, 
						{"snmp_name": "public", "permission": "ro"}],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
 
def test_check_snmp_compliant(exp_snmp, act_snmp): 
	ok, failures = check_snmp(exp_snmp, act_snmp)
	assert ok is True 
	assert failures == []

@pytest.mark.parametrize("name", ["voice", "network", "web", "ssh"])
def test_check_snmp_extra_community(name):
	expected =  {
		"communities": [{"snmp_name": "private", "permission": "rw"}, 
						{"snmp_name": "public", "permission": "ro"}],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "rw"}, 
						{"snmp_name": "public", "permission": "ro"},
						{"snmp_name": name, "permission": "rw"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)
	assert ok is False
	assert any("(SNMP) Drift Detected: Unexpected SNMP Community Found" in f for f in failures)
	assert any(f"Name: {name} | Permission: rw" in f for f in failures)

@pytest.mark.parametrize("name", ["voice", "network", "web", "ssh"])
def test_check_snmp_missing_community(name):
	expected =  {
		"communities": [{"snmp_name": name, "permission": "rw"}],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, {})
	assert ok is False
	assert any("(SNMP) Missing SNMP Community" in f for f in failures)
	assert any(f"Name: {name}" in f for f in failures)

def test_check_snmp_permission_mismatch():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.50",
						"snmp_version": "2c" }],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "rw"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is False
	assert any("(SNMP) Mismatched Community Permission" in f for f in failures)
	assert any("Expected: ro | Actual: rw" in f for f in failures)

def test_check_snmp_contact_mismatch():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.50",
						"snmp_version": "2c" }],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@yahoo.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is False
	assert any("(SNMP) Mismatched Contact" in f for f in failures)
	assert any("Expected: network-team@example.com" in f for f in failures)
	assert any("Actual: network-team@yahoo.com")

@pytest.mark.parametrize("name, ip, version",
		[
			("voice", "10.10.10.1", "2c"), 
			("web", "203.0.113.1", "3"),
			("https", "204.0.11.6", "v1"),
			("rtp", "205.0.11.10", "v1")
		]
	)
def test_check_snmp_extra_hosts(name, ip, version):
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.50",
						"snmp_version": "2c" }],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" },
					{"snmp_name": name,
					"snmp_ip": ip,
					"snmp_version": version }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is False
	assert any("(SNMP) Extra SNMP Host Found" in f for f in failures)
	assert any(f"Name: {name}" in f for f in failures)
	assert any(f"IP: {ip} | Version: {version}" in f for f in failures)

def test_check_snmp_missing_host():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.50",
						"snmp_version": "2c" },
						{"snmp_name": "voice_traffic",
						"snmp_ip": "10.10.10.50",
						"snmp_version": "2c" 
						}],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.50",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}	
	ok, failures = check_snmp(expected, actual)
	assert ok is False
	assert any("(SNMP) Missing SNMP Host" in f for f in failures)
	assert any(f"Name: voice_traffic" in f for f in failures)

def test_check_snmp_ip_mismatch():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.50",
						"snmp_version": "2c" },
						],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.60",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is False
	assert any("(SNMP) Mismatched SNMP Host IP" in f for f in failures)
	assert any("Expected: 10.10.10.50" in f for f in failures)
	assert any("Actual: 10.10.10.60" in f for f in failures)

def test_check_snmp_version_mismatch():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.60",
						"snmp_version": "3" },
						],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.60",
					"snmp_version": "2c" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is False
	assert any("(SNMP) Mismatched SNMP Version" in f for f in failures)
	assert any("Expected: 3 | Actual: 2c" in f for f in failures)

@pytest.mark.parametrize("location", ["LA", "DC", "ATL", "TX"])
def test_check_snmp_location_mismatch(location): 
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.60",
						"snmp_version": "3" },
						],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.60",
					"snmp_version": "3" }],
		"traps": {"snmp": True, "syslog": True, "config": True},
		"location": location,
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is False
	assert any("(SNMP) SNMP Location Mismath" in f for f in failures)
	assert any("Expected: new york datacenter rack 10" in f for f in failures)
	assert any(f"Actual: {location}" in f for f in failures)

def test_check_snmp_trap_config_mismatch():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.60",
						"snmp_version": "3" },
						],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.60",
					"snmp_version": "3" }],
		"traps": {"snmp": True, "syslog": True, "config": False},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is False 
	assert any("(SNMP) Mismatched Traps | Config" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)
def test_check_snmp_trap_syslog_mismatch():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.60",
						"snmp_version": "3" },
						],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.60",
					"snmp_version": "3" }],
		"traps": {"snmp": True, "syslog": False, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)

	assert ok is True 
	assert any("(SNMP) Mismatched Traps | Syslog" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)

def test_check_snmp_trap_snmp_mismatch():
	expected =  {
			"communities": [{"snmp_name": "private", "permission": "ro"}],
			"hosts": [{"snmp_name": "private",
						"snmp_ip": "10.10.10.60",
						"snmp_version": "3" },
						],
			"traps": {"snmp": True, "syslog": True, "config": True},
			"location": "new york datacenter rack 10",
			"contact": "network-team@example.com"
		}
	actual =  {
		"communities": [{"snmp_name": "private", "permission": "ro"}
						],
		"hosts": [{"snmp_name": "private",
					"snmp_ip": "10.10.10.60",
					"snmp_version": "3" }],
		"traps": {"snmp": False, "syslog": True, "config": True},
		"location": "new york datacenter rack 10",
		"contact": "network-team@example.com"
	}
	ok, failures = check_snmp(expected, actual)
	assert ok is True 
	assert any("(SNMP) Mismatched Traps | SNMP" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)