import pytest
from src.compliance.switching.vlan.check import check_vlan


@pytest.fixture
def exp_vlan():
	return [
	{"name": "management", "vlan_id": 10},
	{"name": "users", "vlan_id": 20}
		]

@pytest.fixture
def act_vlan():
	return {
		10: {"name": "management"},
		20: {"name": "users"}
	}

def test_check_vlan(exp_vlan, act_vlan):
	ok, failures = check_vlan(exp_vlan, act_vlan)
	assert ok is True 
	assert failures == []

def test_check_missing_vlan():
	expected = [
			{"name": "management", "vlan_id": 10},
			{"name": "users", "vlan_id": 20}
		]
	actual = {
		10: {"name": "management"},
	}

	ok, failures = check_vlan(expected, actual)
	assert ok is False 
	assert any("Missing VLAN 20" in f for f in failures)
	assert any("users" in f for f in failures)

def test_check_name_mismatch():
	expected = [
			{"name": "management", "vlan_id": 10}
		]
	actual = {
		10: {"name": "users"}
	}

	ok, failures = check_vlan(expected, actual)
	assert ok is False 
	assert any("VLAN Name Mismatch" in f for f in failures)
	assert any("Expected: management" in f for f in failures)
	assert any("Actual: users" in f for f in failures)

@pytest.mark.parametrize("vlan", [20,30,40,50,60,70])
def test_check_vlan_extra_vlan(vlan):
	expected = [
			{"name": "management", "vlan_id": 10}
		]
	actual = {
		10: {"name": "users"},
		vlan: {"name": "management"}
	}

	ok, failures = check_vlan(expected, actual)
	assert ok is False 
	assert any("Rogue VLAN Detected" in f for f in failures)
	assert any(f"ID: {vlan}" in f for f in failures)
	assert any("management" in f for f in failures)