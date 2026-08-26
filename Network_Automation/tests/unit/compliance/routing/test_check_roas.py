import pytest 
from src.compliance.routing.roas.check import check_roas

@pytest.fixture
def exp_roas():
	return {
		"interface": "gigabitethernet1.10",
		"router_vlan": 10, 
		"ip": "192.168.1.10", 
		"mask": "255.255.255.0"
	}
@pytest.fixture
def act_roas():
	return {
		"gigabitethernet1.10": {
			"router_vlan": 10,
			"ip": "192.168.1.10", 
			"mask": "255.255.255.0"
		}
	}

def test_check_roas_compliant(exp_roas, act_roas):
	ok, failures = check_roas(exp_roas, act_roas)
	assert ok is True 
	assert failures == []

def test_check_roas_missing_roas():
	expected =  {
		"interface": "gigabitethernet1.10",
		"router_vlan": 10, 
		"ip": "192.168.1.10", 
		"mask": "255.255.255.0"
	}

	ok, failures = check_roas(expected, {})

	assert ok is False 
	assert any("Missing ROAS Interface on Device | Interface: gigabitethernet1.10" 
				in f for f in failures
		)
	assert any("VLAN: 10 | IP: 192.168.1.10/255.255.255.0" in f for f in failures)

def test_check_roas_mismatched_vlan():
	expected =  {
		"interface": "gigabitethernet1.10",
		"router_vlan": 10, 
		"ip": "192.168.1.10", 
		"mask": "255.255.255.0"
	}

	actual = {
		"gigabitethernet1.10": { 
		   	"router_vlan": 20,
			"ip": "192.168.1.10", 
			"mask": "255.255.255.0"
		}
	}

	ok, failures = check_roas(expected, actual)

	assert ok is False
	assert any("ROAS VLAN Mismatch | Expected: 10 | Actual: 20" in f for f in failures)

def test_check_roas_mismatched_ip():
	expected =  {
		"interface": "gigabitethernet1.10",
		"router_vlan": 10, 
		"ip": "192.168.1.10", 
		"mask": "255.255.255.0"
	}

	actual = {
		"gigabitethernet1.10": { 
		   	"router_vlan": 10,
			"ip": "192.168.1.20", 
			"mask": "255.255.255.0"
		}
	}

	ok, failures = check_roas(expected, actual)

	assert ok is False
	assert any("ROAS IP/Mask Mismatch | Interface: gigabitethernet1.10" in f for f in failures)
	assert any("Expected IP/Mask: 192.168.1.10/255.255.255.0 | Actual IP/Mask: 192.168.1.20/255.255.255.0"
				in f for f in failures
		)
def test_check_roas_mismatched_mask():
	expected =  {
		"interface": "gigabitethernet1.10",
		"router_vlan": 10, 
		"ip": "192.168.1.10", 
		"mask": "255.255.0.0"
	}

	actual = {
		"gigabitethernet1.10": { 
		   	"router_vlan": 10,
			"ip": "192.168.1.10", 
			"mask": "255.255.255.0"
		}
	}

	ok, failures = check_roas(expected, actual)

	assert ok is False
	assert any("ROAS IP/Mask Mismatch | Interface: gigabitethernet1.10" in f for f in failures)
	assert any("Expected IP/Mask: 192.168.1.10/255.255.0.0 | Actual IP/Mask: 192.168.1.10/255.255.255.0"
				in f for f in failures
		)
