import pytest
from src.compliance.services.ntp.check import check_ntp

@pytest.fixture 
def exp_ntp():
	return {
		"keys": [{"id": 2, "trusted": True}],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}

@pytest.fixture 
def act_ntp():
	return {
		"keys": [{"id": 2, "trusted": True}],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}

def test_check_ntp_compliant(exp_ntp, act_ntp): 
	ok, failures = check_ntp(exp_ntp, act_ntp)
	assert ok is True 
	assert failures == []

@pytest.mark.parametrize("id_num", [1,3,4,5,6])
def test_check_ntp_mismatched_id(id_num):
	expected = {
		"keys": [{"id": id_num, "trusted": True},],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}

	actual = {
		"keys": [{"id": 2, "trusted": True}],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}

	ok, failures = check_ntp(expected, actual)
	assert ok is False 
	assert any("Missing Key ID" in f for f in failures)
	assert any(f"Key ID(s): {id_num}" in f for f in failures)

def test_check_ntp_trusted_mismatch(): 
	expected = {
		"keys": [{"id": 2, "trusted": True},],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}

	actual = {
		"keys": [{"id": 2, "trusted": False}],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}
	ok, failures = check_ntp(expected, actual)
	assert ok is False
	assert any("NTP Trusted (Bool) Key Mismatch" in f for f in failures)
	assert any("Key: 2" in f for f in failures)
	assert any("Expected: True | Actual: False" in f for f in failures)

@pytest.mark.parametrize("id_num", [1,3,4,5,6])
def test_check_ntp_extra_key_id(id_num):
	expected = {
		"keys": [{"id": 2, "trusted": True},
		],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}

	actual = {
		"keys": [{"id": 2, "trusted": True},
				 {"id": id_num, "trusted": True}
				],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}
	ok, failures = check_ntp(expected, actual)
	assert ok is False
	assert any("(NTP) Rogue Key ID" in f for f in failures)
	assert any(f"Key ID: {id_num}" in f for f in failures)

@pytest.mark.parametrize("ip", 
		[
			("192.168.1.11"),
			("172.15.1.1"), 
			("203.0.113.1"),
			("205.10.10.1")
		]
	)
def test_check_ntp_missing_server(ip): 
	expected = {
		"keys": [{"id": 2, "trusted": True},
		],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2},
					{"server_ip": ip, "server_id": 2}

		]
	}

	actual = {
		"keys": [{"id": 2, "trusted": True}],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}
	ok, failures = check_ntp(expected, actual)
	assert ok is False
	assert any("Missing NTP Server on Device" in f for f in failures)
	assert any(f"Expected IP: {ip}" in f for f in failures)

@pytest.mark.parametrize("id_num", [1,3,4,5,6])
def test_check_ntp_wrong_server_id(id_num):
	expected = {
		"keys": [{"id": 2, "trusted": True},
		],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2}]
	}

	actual = {
		"keys": [{"id": 2, "trusted": True}],
		"servers": [{"server_ip": "192.168.1.1", "server_id": id_num}]
	}
	ok, failures = check_ntp(expected, actual)
	assert ok is False
	assert any("(NTP) Mismatched Server Key ID" in f for f in failures)
	assert any("192.168.1.1" in f for f in failures)
	assert any(f"Expected ID: 2 | Actual ID: {id_num}" in f for f in failures)

@pytest.mark.parametrize("ip", 
		[
			("192.168.1.11"),
			("172.15.1.1"), 
			("203.0.113.1"),
			("205.10.10.1")
		]
	)
def test_check_ntp_extra_server_ip(ip): 
	expected = {
		"keys": [{"id": 2, "trusted": True},
		],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2},
					

		]
	}

	actual = {
		"keys": [{"id": 2, "trusted": True}],
		"servers": [{"server_ip": "192.168.1.1", "server_id": 2},
					{"server_ip": ip, "server_id": 2}
					]
	}
	ok, failures = check_ntp(expected, actual)
	assert ok is False
	assert any("(NTP) Rogue NTP Server IP" in f for f in failures)
	assert any(f"IP: {ip}" in f for f in failures)