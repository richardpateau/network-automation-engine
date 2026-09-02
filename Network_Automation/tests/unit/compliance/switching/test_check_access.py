import pytest
from src.compliance.switching.access.check import check_access

@pytest.fixture 
def exp_access():
	return [{
		"access_interface": "gigabitethernet1",
		"access_vlan": 10
	}]

@pytest.fixture
def act_access():
	return {
		"gigabitethernet1": {
			"access_interface": "gigabitethernet1",
			"mode": "access",
			"access_vlan": 10 
		}
	}

def test_check_access_compliant(exp_access, act_access): 
	ok, failures = check_access(exp_access, act_access)
	assert ok is True 
	assert failures == []

@pytest.mark.parametrize("interface", ["gigabitethernet3", "fastethernet1", "gigabitethernet1/0"])
def test_check_access_missing_interface(interface):
	expected = [
		{
			"access_interface": "gigabitethernet1",
			"access_vlan": 10
		},
		{
			"access_interface": interface,
			"access_vlan": 10
		}
	]
	actual = {
		"gigabitethernet1": {
			"access_interface": "gigabitethernet1",
			"mode": "access",
			"access_vlan": 10 
		}
	}
	ok, failures = check_access(expected, actual)
	assert ok is False 
	assert any("(Access) Missing Interface" in f for f in failures)
	assert any(f"{interface}" in f for f in failures)

def test_check_access_vlan_mismatch():
	expected = [
		{
			"access_interface": "gigabitethernet1",
			"access_vlan": 10
		}
	]
	actual = {
		"gigabitethernet1": {
			"access_interface": "gigabitethernet1",
			"mode": "access",
			"access_vlan": 20 
		}
	}
	ok, failures = check_access(expected, actual)
	assert ok is False 
	assert any("(Access) Mismatched VLAN" in f for f in failures)
	assert any("gigabitethernet1" in f for f in failures)
	assert any("Expected: 10" in f for f in failures)
	assert any("Actual: 20" in f for f in failures)

@pytest.mark.parametrize("interface", ["gigabitethernet3", "fastethernet1", "gigabitethernet1/0"])
def test_check_access_extra_interface(interface):
	expected = [
		{
			"access_interface": "gigabitethernet1",
			"access_vlan": 10
		}
	]
	actual = {
		"gigabitethernet1": {
			"access_interface": "gigabitethernet1",
			"mode": "access",
			"access_vlan": 20 
		},
		interface: {
			"access_interface": "gigabitethernet2",
			"mode": "access",
			"access_vlan": 20 
		}
	}
	ok, failures = check_access(expected, actual)
	assert ok is False 
	assert any("(Access) Rogue Interface Configured" in f for f in failures)
	assert any(f"Interface: {interface}" in f for f in failures)