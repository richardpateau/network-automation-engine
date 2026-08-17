import pytest
from src.compliance.switching.trunk.check import check_trunk

@pytest.fixture
def exp_trunk():
	return [{
		"trunk_interface": "gigabitethernet1",
		"mode": "trunk", 
		"allowed_vlans": "10,20,30,40,50"
	}]

@pytest.fixture
def act_trunk():
	return {
		"gigabitethernet1": {
			"trunk_interface": "gigabitethernet1",
			"allowed_vlans": "10,20,30,40,50",
			"mode": "trunk"
		}
	}

def test_check_trunk_complaint(exp_trunk, act_trunk): 
	ok, failures = check_trunk(exp_trunk, act_trunk)
	assert ok is True 
	assert failures == []

@pytest.mark.parametrize("interface", 
		[
			"gigabitethernet1/0",
			"gigabitethernet1/1",
			"gigabitethernet2",
			"fastethernet2"
		]
	)
def test_check_trunk_missing_interface(interface):
	expected = [
	{
		"trunk_interface": "gigabitethernet1",
		"mode": "trunk", 
		"allowed_vlans": "10,20,30,40,50"
	},
	{
		"trunk_interface": interface,
		"mode": "trunk", 
		"allowed_vlans": "10,20,30,40,50"
	}

	]


	actual = {
		"gigabitethernet1": {
			"trunk_interface": "gigabitethernet1",
			"allowed_vlans": "10,20,30,40,50",
			"mode": "trunk"
		}
	}
	ok, failures = check_trunk(expected, actual)
	assert ok is False 
	assert any("(Trunk) Missing Interface" in f for f in failures)
	assert any("gigabitethernet2" in f for f in failures)

@pytest.mark.parametrize("interface", 
		[
			"gigabitethernet1/0",
			"gigabitethernet1/1",
			"gigabitethernet2",
			"fastethernet2"
		]
	)
def test_check_trunk_extra_interface(interface):
	expected = [
			{
				"trunk_interface": "gigabitethernet1",
				"mode": "trunk", 
				"allowed_vlans": "10,20,30,40,50"
			}
		]


	actual = {
		"gigabitethernet1": {
			"trunk_interface": "gigabitethernet1",
			"allowed_vlans": "10,20,30,40,50",
			"mode": "trunk"
		},
		interface: {
			"trunk_interface": interface,
			"mode": "trunk", 
			"allowed_vlans": "10,20,30,40,50"
		}
	}
	ok, failures = check_trunk(expected, actual)
	assert ok is False 
	assert any("(Trunk) Rogue Interface Configured in Trunk Mode" in f for f in failures)
	assert any(f"{interface}" in f for f in failures)

def test_check_trunk_mode_mismatch():
	expected = [{
		"trunk_interface": "gigabitethernet1",
		"mode": "trunk", 
		"allowed_vlans": "10,20,30,40,50"
	}]

	actual = {
		"gigabitethernet1": {
			"trunk_interface": "gigabitethernet1",
			"allowed_vlans": "10,20,30,40,50",
			"mode": "access"
		}
	}
	ok, failures = check_trunk(expected, actual)
	assert ok is False
	assert any("(Trunk) Mismatched Operational Mode" in f for f in failures)
	assert any("Expected: trunk" in f for f in failures)
	assert any("Actual: access" in f for f in failures)

@pytest.mark.parametrize("allowed", 
		[
			"40,50,60,70",
			"10,20,50,60,90",
			"5,10,15,20,25,40",
			"1,2,3,4,5,6,7"
		]
	)
def test_check_trunk_complaint	