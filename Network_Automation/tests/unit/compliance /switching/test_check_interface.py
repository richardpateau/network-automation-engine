import pytest
from src.compliance.switching.interface.check import check_interface

@pytest.fixture 
def exp_interface():
	return [
		{
			"interface": "gigabitethernet1",
			"should_be_up": True
		},
		{
			"interface": "gigabitethernet2",
			"should_be_up": False
		}
	]

@pytest.fixture 
def act_interface():
	return {
		"gigabitethernet1": {"is_up": True},
		"gigabitethernet2": {"is_up": False}
	}

def test_check_interface_compliant(exp_interface, act_interface): 
	ok, failures = check_interface(exp_interface, act_interface)
	assert ok is True 
	assert failures == []

def test_check_interface_mismatched_operational_state(): 
	expected = [
		{
			"interface": "gigabitethernet1",
			"should_be_up": True
		},
		{
			"interface": "gigabitethernet2",
			"should_be_up": True
		}
	]
	actual = {
		"gigabitethernet1": {"is_up": True},
		"gigabitethernet2": {"is_up": False}
	}

	ok, failures = check_interface(expected, actual)
	assert ok is False  
	assert any("Mismatched Interface Operational State" in f for f in failures)
	assert any("gigabitethernet2" in f for f in failures)
	assert any("Expected Should Be Up/Up: True" in f for f in failures)
	assert any("Actual Should be Up/Up: False" in f for f in failures)