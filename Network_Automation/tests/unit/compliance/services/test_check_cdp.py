import pytest
from src.compliance.services.cdp.check import check_cdp

@pytest.fixture
def exp_cdp():
	return {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}

@pytest.fixture
def act_cdp():
	return {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}

def test_check_cdp_compliant(exp_cdp, act_cdp): 
	ok, failures = check_cdp(exp_cdp, act_cdp)
	assert ok is True 
	assert failures == []

def test_check_cdp_enabled_mismatch():
	expected = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}
	actual = {
		"enabled": False, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}

	ok,failures = check_cdp(expected, actual)
	assert ok is False
	assert any("(CDP) Operational State Mismatch" in f for f in failures)
	assert any("Expected: True | Actual: False" in f for f in failures)

@pytest.mark.parametrize("timer", [10,40,50,80,100])
def test_check_cdp_timer_mismatch(timer):
	expected = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}
	actual = {
		"enabled": True, 
		"timer": timer, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}

	ok,failures = check_cdp(expected, actual)
	assert ok is False
	assert any("(CDP) Timer Mismatch" in f for f in failures)
	assert any(f"Expected: 60 | Actual: {timer}" in f for f in failures)

@pytest.mark.parametrize("holdtime", [100, 120, 200, 204, 240])
def test_check_cdp_holdtime_mismatch(holdtime):
	expected = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}
	actual =  {
		"enabled": True, 
		"timer": 60, 
		"holdtime": holdtime,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}

	ok, failures = check_cdp(expected, actual)
	assert ok is False 
	assert any("(CDP) HoldTime Mismatch" in f for f in failures)
	assert any(f"Expected: 180 | Actual: {holdtime}" in f for f in failures)

def test_check_cdp_extra_interfaces():
	expected = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}
	actual = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False},
			"gigabitethernet3": {"enabled": True}, 
			"gigabitethernet4": {"enabled": False}
		}
	}

	ok, failures = check_cdp(expected, actual)
	assert ok is False
	assert any("(CDP) Rogue Interface Configured with CDP" in f for f in failures)
	assert any("gigabitethernet3" in f for f in failures)
	assert any("gigabitethernet4" in f for f in failures)
	
def test_check_cdp_missing_interfaces():
	expected = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False},
			"gigabitethernet3": {"enabled": True}, 
		}
	}
	actual = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False},
		}
	}

	ok, failures = check_cdp(expected, actual)
	assert ok is False
	assert any("(CDP) Missing Interface Not Configured w/ CDP" in f for f in failures)
	assert any("gigabitethernet3" in f for f in failures)

def test_check_cdp_enabled_interface_mismatch():
	expected = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": False}
		}
	}
	actual = {
		"enabled": True, 
		"timer": 60, 
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True}, 
			"gigabitethernet2": {"enabled": True}
		}
	}

	ok, failures = check_cdp(expected, actual)
	assert ok is False
	assert any("(CDP) Interface Operational State Mismatch" in f for f in failures)
	assert any("Expected: False | Actual: True" in f for f in failures)
	assert any("gigabitethernet2" in f for f in failures)