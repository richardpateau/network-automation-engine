import pytest
from src.compliance.services.qos.check import check_qos

@pytest.fixture 
def exp_qos():
	return {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}

@pytest.fixture
def act_qos():
	return {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}

def test_check_qos_compliant(exp_qos, act_qos): 
	ok, failures = check_qos(exp_qos, act_qos)
	assert ok is True 
	assert failures == []

@pytest.mark.parametrize("policy", ["voice", "web", "https", "http"])
def test_check_qos_missing_policy(policy): 
	expected = {
		"policies": [{
			"policy_name": policy, 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	ok, failures = check_qos(expected, {})
	assert ok is False 
	assert any("Missing QOS Policy" in f for f in failures)
	assert any(policy in f for f in failures)

@pytest.mark.parametrize("policy", ["voices", "web", "https", "http"])
def test_check_qos_extra_policy(policy):
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [
		{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		  },
		  {
			"policy_name": policy, 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		  }
		]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Rogue Policy Found" in f for f in failures)
	assert any(policy in f for f in failures)

@pytest.mark.parametrize("name", ["voices", "web", "https", "http"])
def test_check_qos_extra_class_map(name):
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				},
				{
				 	"name": name,
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Extra Class Map Found" in f for f in failures)
	assert any(name in f for f in failures)

@pytest.mark.parametrize("name", ["voices", "web", "https", "http"])
def test_check_qos_missing_class_map(name):
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				},
				{
				 	"name": name,
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Missing Class Map" in f for f in failures)
	assert any(name in f for f in failures)

@pytest.mark.parametrize("name", ["voice", "https", "http"])
def test_check_qos_class_name_mismatch(name):
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": name,
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Mismatched Class Name" in f for f in failures)
	assert any("Expected: web" in f for f in failures)
	assert any(f"Actual: {name}" in f for f in failures)

def test_check_qos_match_type_mismatch():
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-all",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Mismatched Match Type Configuration" in f for f in failures)
	assert any("Expected: match-any" in f for f in failures)
	assert any("Actual: match-all" in f for f in failures)

def test_check_qos_action_type_mismatch():
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"priority",
				    "bandwidth": "5000",
				    "priority": ""

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Mismatched Action Type Configuration" in f for f in failures)
	assert any("Expected: bandwidth" in f for f in failures)
	assert any("Actual: priority" in f for f in failures)

@pytest.mark.parametrize("bandwidth", ["1000", "2000", "3000", "4000"])
def test_check_qos_bandwidth_mismatch(bandwidth):
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": bandwidth,
				    "priority": ""

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Mismatched Bandwidth Configuration" in f for f in failures)
	assert any("Expected: 5000" in f for f in failures)
	assert any(f"Actual: {bandwidth}" in f for f in failures)

@pytest.mark.parametrize("protocol", ["https", "ssh", "rtp", "dhcp"])
def test_check_qos_protocol_mismatch(protocol):
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": protocol,
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": ""

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Mismatched Protocol Configuration" in f for f in failures)
	assert any("Expected: http" in f for f in failures)
	assert any(f"Actual: {protocol}" in f for f in failures)

@pytest.mark.parametrize("priority", ["1000", "2000", "3000", "4000"])
def test_check_qos_priority_mismatch(priority): 
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "",
				    "priority": "100"

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": priority

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Mismatched Priority Configuration" in f for f in failures)
	assert any("Expected: 100" in f for f in failures)
	assert any(f"Actual: {priority}" in f for f in failures)

def test_check_qos_policy_missing_interface():
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "",
				    "priority": "100"

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"}

			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": "100"

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Policy Not Applied on Interface" in f for f in failures)
	assert any("gigabitethernet2" in f for f in failures)

def test_check_qos_policy_extra_interface():
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"}
				 
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "",
				    "priority": "100"

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}

			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": "100"

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Rogue Policy Configured On Interface" in f for f in failures)
	assert any("gigabitethernet2" in f for f in failures)

def test_check_qos_interface_direction_mismatch():
	expected = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "output"}
				 
			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "",
				    "priority": "100"

				}
			]
		}]
	}
	actual = {
		"policies": [{
			"policy_name": "voice", 
			"attachments": [
				 {"interface": "gigabitethernet1", "direction": "input"},
				 {"interface": "gigabitethernet2", "direction": "input"}

			],
			"class_maps": [
				{
				 	"name": "web",
				    "match_type": "match-any",
				    "protocol": "http",
				    "action_type":"bandwidth",
				    "bandwidth": "5000",
				    "priority": "100"

				},
	
			]
		}]
	}
	ok, failures = check_qos(expected, actual)
	assert ok is False 
	assert any("(QOS) Mismatched Direction" in f for f in failures)
	assert any("gigabitethernet2" in f for f in failures)
	assert any("Expected: output | Actual: input" in f for f in failures)