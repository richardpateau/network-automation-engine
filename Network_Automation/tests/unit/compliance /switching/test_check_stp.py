import pytest
from src.compliance.switching.stp.check import check_stp_global, check_stp_interfaces

@pytest.fixture
def exp_stp_global():
	return {
		"mode": "rapid-pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576

		}
	}

@pytest.fixture
def act_stp_global():
	return {
		"mode": "rapid-pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576

		}
	}
@pytest.fixture
def exp_stp_interface():
	return [{
		"interface": "gigabitethernet1",
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}]
@pytest.fixture
def act_stp_interface():
	return  {
		"gigabitethernet1": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}
def test_check_stp_global_compliant(exp_stp_global, act_stp_global):
	ok, failures = check_stp_global(exp_stp_global, act_stp_global)
	assert ok is True
	assert failures == []

def test_check_stp_global_wrong_mode():
	expected =  {
		"mode": "rapid-pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576

		}
	}

	actual = {
		"mode": "pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576

		}
	}
	ok, failures = check_stp_global(expected, actual)
	assert ok is False 
	assert any("Mismatched STP Mode" in f for f in failures)
	assert any("Expected: rapid-pvst" in f for f in failures)
	assert any("Actual: pvst" in f for f in failures)

def test_check_stp_global_missing_vlans():
	expected =  {
		"mode": "rapid-pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576,
			50: 32768,
			60:4096,
			70:4096

		}
	}


	actual = {
		"mode": "pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576,


		}
	}
	ok, failures = check_stp_global(expected, actual)
	assert ok is False 
	assert any("(STP) Missing VLANs" in f for f in failures)
	assert any("[50, 60, 70]" in f for f in failures)

def test_check_stp_global_extra_vlans():
	expected =  {
		"mode": "rapid-pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576

		}
	}


	actual = {
		"mode": "pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576,
			50:32768,
			60:4096,
			70:4096


		}
	}
	ok, failures = check_stp_global(expected, actual)
	assert ok is False 
	assert any("(STP) Rogue VLANs" in f for f in failures)
	assert any("[50, 60, 70]" in f for f in failures)

@pytest.mark.parametrize("priority", [1000, 2000, 3000, 4000, 6000])
def test_check_stp_global_priority_mismatch(priority):
	expected =  {
		"mode": "rapid-pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:24576

		}
	}


	actual = {
		"mode": "pvst",
		"vlan_priorities": {
			10:32768,
			20:4096,
			30:28672,
			40:priority,
		}
	}
	ok, failures = check_stp_global(expected, actual)
	assert ok is False 
	assert any("(STP) Mismatched Bridge Priority" in f for f in failures)
	assert any("VLAN: 40" in f for f in failures)
	assert any("Expected: 24576" in f for f in failures)
	assert any(f"Actual: {priority}" in f for f in failures)

def test_check_stp_interfaces_complaint(exp_stp_interface, act_stp_interface): 
	ok, failures = check_stp_interfaces(exp_stp_interface, act_stp_interface)
	assert ok is True
	assert failures == []

@pytest.mark.parametrize("interface", ["gigabitethernet1/0", "gigabitethernet1/1", "fastethernet1"])
def test_check_stp_inteface_missing(interface): 
	expected = [
	{
		"interface": "gigabitethernet1",
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	},
	{
		"interface": interface,
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}
	]
	actual =  {
		"gigabitethernet1": {
			"portfast": True ,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}
	ok, failures = check_stp_interfaces(expected, actual)
	assert ok is False 
	assert any("(STP) Missing Interface" in f for f in failures)
	assert any(f"{interface}" in f for f in failures)

def test_check_stp_interfaces_portfast_mismatch():
	expected = [{
		"interface": "gigabitethernet1",
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}]
	actual =  {
		"gigabitethernet1": {
			"portfast": False,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}
	ok, failures = check_stp_interfaces(expected, actual)
	assert ok is False 
	assert any("(STP Interface) Mismatched PortFast" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)

def test_check_stp_interfaces_bpdu_guard_mismatch():
	expected = [{
		"interface": "gigabitethernet1",
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}]
	actual =  {
		"gigabitethernet1": {
			"portfast": True,
			"bpdu_guard": False, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}
	ok, failures = check_stp_interfaces(expected, actual)
	assert ok is False 
	assert any("(STP Interface) Mismatched BPDU Guard" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)

def test_check_stp_interfaces_root_guard_mismatch():
	expected = [{
		"interface": "gigabitethernet1",
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}]
	actual =  {
		"gigabitethernet1": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": False, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}
	ok, failures = check_stp_interfaces(expected, actual)
	assert ok is False 
	assert any("(STP Interface) Mismatched Root Guard" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)

def test_check_stp_interfaces_loop_guard_mismatch():
	expected = [{
		"interface": "gigabitethernet1",
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}]
	actual =  {
		"gigabitethernet1": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": True,
			"bpdu_filter": False 
		}
	}
	ok, failures = check_stp_interfaces(expected, actual)
	assert ok is False 
	assert any("(STP Interface) Mismatched Loop Guard" in f for f in failures)
	assert any("Expected: False" in f for f in failures)
	assert any("Actual: True" in f for f in failures)

def test_check_stp_interfaces_bpdu_filter_mismatch():
	expected = [{
		"interface": "gigabitethernet1",
		"stp": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": False 
		}
	}]
	actual =  {
		"gigabitethernet1": {
			"portfast": True,
			"bpdu_guard": True, 
			"root_guard": True, 
			"loop_guard": False,
			"bpdu_filter": True 
		}
	}
	ok, failures = check_stp_interfaces(expected, actual)
	assert ok is False 
	assert any("(STP Interface) Mismatched BPDU Filter" in f for f in failures)
	assert any("Expected: False" in f for f in failures)
	assert any("Actual: True" in f for f in failures)