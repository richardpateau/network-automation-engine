import pytest 
from src.compliance.routing.ospf import check_ospf

@pytest.fixture 
def exp_ospf():
	return {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }

@pytest.fixture
def act_ospf():
	return {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }

def test_check_ospf_compliant(exp_ospf, act_ospf):
	ok, failures = check_ospf(exp_ospf, act_ospf)
	
	assert ok is True
	assert failures == [] 

def test_check_ospf_missing_process(exp_ospf): 
	ok, failures = check_ospf(exp_ospf, {})
	
	assert ok is False 
	assert any("Missing Process ID (OSPF)" in f for f in failures)
	assert any("ID: 1" in f for f in failures)

def test_check_ospf_wrong_rid():
	expected = {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    
	actual = {
	        1: {
	             "process_id": 1,
	             "router_id": "2.2.2.2",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }
	
	ok, failures = check_ospf(expected, actual)

	assert ok is False 
	assert any("(OSPF) Mismatched Router ID" in f for f in failures)
	assert any("Expected RID: 1.1.1.1 | Actual RID: 2.2.2.2"
				in f for f in failures
		)
	assert len(failures) == 1 
def test_check_ospf_wrong_expected_network_not_found():
	expected = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }
	actual = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [],
	        }
	    }
	
	ok, failures = check_ospf(expected, {})

	assert ok is False 
	assert any("(OSPF) Expected Network Not Found on Device" in f for f in failures)
	assert any("Expected: 192.168.10.0 | Wildcard: 0.0.0.255 | Area: 0"
				in f for f in failures
			)
def test_check_ospf_mismatched_area():
	 expected = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 1,
	                }
	            ],
	        }
	    }
	actual = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }
	
	ok, failures = check_ospf(expected, actual)

	assert ok is False 
	assert any("(OSPF) Area Mismatch | Network: 192.168.10.0" in f for f in failures)
	assert any("Expected: 1 | Actual: 0" in f for f in failures)

def test_check_ospf_mismatched_wildcard():
	 expected = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.255.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }
	actual = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }
	
	ok, failures = check_ospf(expected, actual)

	assert ok is False 
	assert any("(OSPF) Mismatched Wildcard | Network: 192.168.10.0" in f for f in failures)
	assert any("Expected: 0.0.255.255 | Actual: 0.0.0.255" in f for f in failures)

def test_check_ospf_extra_network():
	 expected = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.10.0",
	                    "wildcard": "0.0.255.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }
	actual = {
	        1: {
	             "process_id": 1,
	             "router_id": "1.1.1.1",
	             "network_list": [
	                {
	                    "subnet": "192.168.20.0",
	                    "wildcard": "0.0.0.255",
	                    "area": 0,
	                }
	            ],
	        }
	    }
	
	ok, failures = check_ospf(expected, actual)
	assert any("(OSPF) Rogue Network Found | Network: 192.168.20.0" in f for f in failures)
	assert any("Wildcard: 0.0.0.255 | Area: 0" in f for f in failures)