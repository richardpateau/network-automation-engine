import pytest
from src.compliance.services.syslog.check import check_syslog

@pytest.fixture 
def exp_syslog():
	return {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}

@pytest.fixture 
def act_syslog():
	return {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}

def test_check_syslog_compliant(exp_syslog, act_syslog): 
	ok, failures = check_syslog(exp_syslog, act_syslog, "NETMIKO")
	assert ok is True 
	assert failures == []

def test_check_syslog_missing_hosts():
	expected = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}
	actual = {
		"hosts": ["192.168.10.10"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}

	ok, failures = check_syslog(expected, actual, "NETMIKO")
	assert ok is False
	assert any("(Syslog) Missing Host" in f for f in failures)
	assert any("192.168.20.20" in f for f in failures)

def test_check_syslog_extra_hosts():
	expected = {
		"hosts": ["192.168.10.10"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}
	actual = {
		"hosts": ["192.168.10.10", "192.168.20.25"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}

	ok, failures = check_syslog(expected, actual, "NETMIKO")
	assert ok is False
	assert any("(Syslog) Drift: Rogue Host" in f for f in failures)
	assert any("192.168.20.25" in f for f in failures)

def test_check_syslog_interface_mismatch():
	expected = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}
	actual = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "gigabitethernet1/0",
		"timestamps": True,
	}

	ok, failures = check_syslog(expected, actual, "NETMIKO")
	assert ok is False
	assert any("(Syslog) Mismatched Source Interface" in f for f in failures)
	assert any("Expected: loopback0" in f for f in failures)
	assert any("Actual: gigabitethernet1/0" in f for f in failures)

def test_check_syslog_timestamps_mismatch():
	expected = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}
	actual = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": False,
	}

	ok, failures = check_syslog(expected, actual, "NETMIKO")
	assert ok is False
	assert any("(Syslog) Mismatched Timestamps Configuration" in f for f in failures)
	assert any("Expected: True" in f for f in failures)
	assert any("Actual: False" in f for f in failures)
	assert any("service timestamps log datetime msec" in f for f in failures)
def test_check_syslog_trap_level():
	expected = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True,
	}
	actual = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "informational",
		"source_interface": "loopback0",
		"timestamps": True,
	}

	ok, failures = check_syslog(expected, actual, "NETMIKO")
	assert ok is False
	assert any("(Syslog) Mismatched Trap Level" in f for f in failures)
	assert any("Expected: warnings" in f for f in failures)
	assert any("Actual: informational" in f for f in failures)

def test_check_syslog_facility_mismatch():
	expected = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "informational",
		"source_interface": "loopback0",
		"timestamps": True,
	}
	actual = {
		"hosts": ["192.168.10.10", "192.168.20.20"],
		"facility": "local7",
		"trap_level": "informational",
		"source_interface": "loopback0",
		"timestamps": True,
	}

	ok, failures = check_syslog(expected, actual, "NETCONF")
	assert ok is False
	assert any("(Syslog) Mismatched Facility" in f for f in failures)
	assert any("Expected: local6" in f for f in failures)
	assert any("Actual: local7" in f for f in failures)