import pytest
from src.compliance.services.dhcp.check import check_dhcp

@pytest.fixture
def exp_dhcp():
	return {
		"excluded_addresses": [{"start_ip": "192.168.1.1", "end_ip": "192.168.1.10"}], 
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}],
		"helper": {"helper_ip": "10.10.10.5" , "interface_name": "gigabitethernet2"}
	}

@pytest.fixture
def act_dhcp():
	return {
		"excluded_addresses": [{"start_ip": "192.168.1.1", "end_ip": "192.168.1.10"}], 
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}],
		"helper": {"helper_ip": "10.10.10.5" , "interface_name": "gigabitethernet2"}
	}

def test_check_dhcp_compliant(exp_dhcp, act_dhcp): 
	ok, failures = check_dhcp(exp_dhcp, act_dhcp)
	assert ok is True 
	assert failures == []

def test_check_dhcp_rogue_pool():
	expected = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}
	actual = {
		"pools": [
			{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
			}, 
			{
				"pool_name": "voice",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
			}
		]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False 
	assert any("(DHCP) Rogue DHCP Pool | Name: voice" in f for f in failures)

def test_check_dhcp_missing_pool():
	expected = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
			}, 
			{
				"pool_name": "voice",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
			}
		]
	}
	actual = {
		"pools": [
			{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
			}
		]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False 
	assert any("(DHCP) Missing DHCP Pool | Name: voice" in f for f in failures)
	assert len(failures) == 1

@pytest.mark.parametrize("gateway", ["204.0.113.1", "204.0.113.2", "204.0.113.3"])
def test_check_dhcp_gateway_mismatch(gateway): 
	expected = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}
	actual = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": gateway,
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False 
	assert any("(DHCP) Default Gateway Mismatch" in f for f in failures)
	assert any("Pool: users" in f for f in failures)
	assert any(f"Expected: 192.168.10.1 | Actual: {gateway}" in f for f in failures)

@pytest.mark.parametrize("dns", 
		[
			["4.4.4.4"],
			["5.5.5.5", "6.6.6.6", "9.9.9.9"], 
			["192.168.1.1", "8.8.8.8", "203.0.113.1", "172.16.1.1"]
	 	]
	)
def test_check_dhcp_dns_mismatch(dns):
	expected = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}
	actual = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": dns,
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False
	assert any("(DHCP) DNS Server IP Mismatch" in f for f in failures)
	assert any(f'Expected: ["4.4.4.4", "8.8.8.8"] | Actual: {dns}' in f for f in failures)

@pytest.mark.parametrize("days, hours, minutes", 
		[
			(7, 12, 30), 
			(12, 12, 30), 
			(7, 12, 50), 
			(6, 4, 30), 
			(8, 24, 0)
		]
	)
def test_check_dhcp_wrong_hours_days_minutes():
	expected = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}
	actual = {
		"pools": [{
				"pool_name": "users",
				"lease_days": days,
				"lease_hours": hours,
				"lease_minutes": minutes,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False 
	assert any("(DHCP) Mismatched Lease Duration" in f for f in failures)
	assert any("users" for f in failures)
	assert any("Expected(Days/Hours/Min): 7/12/30" in f for f in failures)
	assert any(f"Actual (Days/Hours/Min): {days}/{hours}/{minutes}")

@pytest.mark.parametrize("ip, mask", [
			("192.168.10.1", "255.255.0.0"), 
			("192.168.20.1", "255.255.255.0"),
			("203.0.113.1", "255.255.255.0"),
			("172.16.1.1", "255.0.0.0")
		]
    )
def test_check_dhcp_ip_mask(ip, mask): 
	expected = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}
	actual = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": ip,
				"pool_mask": mask
		}]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False 
	assert any("(DHCP) Mismatched IP or Mask" in f for f in failures)
	assert any("users" in f for f in failures)
	assert any("Expected: 192.168.10.0/255.255.255.0" in f for f in failures)
	assert any(f"Actual: {ip}/{mask}" in f for f in failures)

@pytest.mark.parametrize("domain", 
		[
			("corp.local"),
			("network.local"),
			("voice.local")
		]
	)
def test_check_dhcp_dns(domain): 
	expected = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}
	actual = {
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": domain,
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False 
	assert any("(DHCP) Mismatched Domain Name" in f for f in failures)
	assert any("users" in f for f in failures)
	assert any(f"Expected: company.local | Actual: {domain}")

@pytest.mark.parametrize("start, end", 
					[
						("203.0.113.1", "203.0.113.10"), 
						("172.16.1.1", "172.16.1.10"), 
						("205.0.113.1", "205.0.113.5"),
						("192.168.70.1", "192.168.70.20")
					]
	)

def test_check_dhcp_missing_excluded(start, end):
	expected = {
		"excluded_addresses": [{"start_ip": "192.168.1.1", "end_ip": "192.168.1.10"},
							   {"start_ip": ip, "end_ip": mask}
							  ]
	}

	actual = {
		"excluded_addresses": [{"start_ip": "192.168.1.1", "end_ip": "192.168.1.10"}
							  ]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False
	assert any(f"(DHCP) Missing Excluded IP {ip} - {mask}" 
				in f for f in failures
		)
def test_check_dhcp_missing_excluded(start, end):
	expected = {
		"excluded_addresses": [{"start_ip": "192.168.1.1", "end_ip": "192.168.1.10"},
							   {"start_ip": ip, "end_ip": mask}
							  ]
	}

	actual = {
		"excluded_addresses": [{"start_ip": "192.168.1.1", "end_ip": "192.168.1.10"}
							  ]
	}

	ok, failures = check_dhcp(expected, actual)
	assert ok is False