import pytest 
from src.compliance.routing.static.check import check_static

@pytest.fixture
def exp_static():
	return [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]

@pytest.fixture
def act_static():
	return [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]

def test_check_roas_compliant(exp_static, act_static):
	ok, failures = check_static(exp_static, act_static)
	assert ok is True 
	assert failures == []

def test_check_roas_extra_routes():
	expected =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	actual =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		},
		{
			"AD": 10,
			"network_address": "192.168.2.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]

	ok, failures = check_static(expected, actual)

	assert ok is False 
	assert any("(Static Routing) Drift: Unexpected Static IP" in f for f in failures)
	assert any("IP: 192.168.2.10 | Mask: 255.255.255.0" in f for f in failures)

def test_check_roas_missing_routes():
	expected =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		},
		{
			"AD": 10,
			"network_address": "192.168.2.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	actual =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]

	ok, failures = check_static(expected, actual)
	assert ok is False
	assert any("(Static Routing) Missing Static Route" in f for f in failures)
	assert any("IP: 192.168.2.10 | Mask: 255.255.255.0" in f for f in failures)

def test_check_roas_wrong_ad():
	expected =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	actual =  [
		{
			"AD": 11,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]

	ok, failures = check_static(expected, actual)
	assert ok is False
	assert any("(Static Routing) AD Mismatch" in f for f in failures)
	assert any("Expected: 10 | Actual: 11" in f for f in failures)

def test_check_roas_wrong_exit_interface():
	expected =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	actual =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet2",
			"name": "voice"
		}

	]

	ok, failures = check_static(expected, actual)
	assert ok is False
	assert any("(Static Routing) Exit Interface Mismatch" in f for f in failures)
	assert any("Expected: gigabitethernet1 | Actual: gigabitethernet2" in f for f in failures)

def test_check_roas_wrong_missing_next_hop():
	expected =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20", "192.168.40.1", "192.168.40.10"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	actual =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	ok, failures = check_static(expected, actual)
	assert ok is False 
	assert any("(Static Routing) Missing Next Hop" in f for f in failures)
	assert any("Missing: 192.168.40.1, 192.168.40.10" in f for f in failures)

def test_check_roas_wrong_extra_next_hop():
	expected =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	actual =  [
		{
			"AD": 10,
			"network_address": "192.168.1.10",
			"mask": "255.255.255.0",
			"next_hop": ["192.168.1.20", "192.168.40.1", "192.168.40.10"],
			"exit_interface": "gigabitethernet1",
			"name": "voice"
		}

	]
	ok, failures = check_static(expected, actual)
	assert ok is False 
	assert any("(Static Routing) Drift: Unexpected Next Hop" in f for f in failures)
	assert any("Extra: 192.168.40.1, 192.168.40.10" in f for f in failures)