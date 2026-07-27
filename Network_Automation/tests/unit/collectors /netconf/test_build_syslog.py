from src.collectors.netconf.builders import build_syslog_netconf 

def test_build_syslog_valid(syslog_netconf): 
	result = build_syslog_netconf(syslog_netconf)

	assert result["hosts"] == ["192.168.10.10", "192.168.20.20"]
	assert result["facility"] == "local6"
	assert result["trap_level"] == "warnings"
	assert result["source_interface"] == "loopback0"
	assert result["timestamps"] == True 

def test_build_syslog_empty():
	assert build_syslog_netconf({}) == {
        "hosts": [],
        "facility": "",
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }
    assert build_syslog_netconf(None) == {
        "hosts": [],
        "facility": "",
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }
    assert build_syslog_netconf({"not_netconf": {}}) == {
        "hosts": [],
        "facility": "",
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }
    assert build_syslog_netconf({"netconf_state": {}}) == {
        "hosts": [],
        "facility": "",
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }

@pytest.mark.parametrize("ip", 
		[
			("200.10.10.10"),
			("192.168.20.1"),
			("203.0.113.4"),
			("172.32.10.10")
		]
	)
def test_build_syslog_hosts(ip):
	data = {
		"native_netconf":{
			"logging": {
				"host": {
			        "ipv4-host-list": [
			          {
			            "ipv4-host": ip
			          }
			        ]  
				}
			}
		  }	
		}

	result = build_syslog_netconf(data)

	assert ip in result["hosts"]

@pytest.mark.parametrize("facility",
		[
			"local1",
			"local2",
			"local3",
			"local7",
			"local6"
		]
	)
def test_build_syslog_facility(facility): 
	data = {
		"native_netconf": {
			"logging": {
				"facility": facility
			}
		}
	}

	result = build_syslog_netconf(data)

	assert result["facility"] == facility

@pytest.mark.parametrize("trap_level"
		[
			"emergency",
			"alert",
			"critical",
			"error",
			"warning",
			"notification",
			"informational",
			"debugging"
		]
	)
def test_build_syslog_trap_level(trap_level):
	data = {
		"native_netconf": {
			"logging": {
				"trap": {
			        "severity": trap_level			      

			    }
			}
		}
	}	

	result = build_syslog_netconf(data)

	assert result["trap_level"] == trap_level

@pytest.mark.parametrize("source_interface", 
		[
			"loopback0",
			"GigabitEthernet1",
			"GigabitEthernet1/0",
			"FastEthernet1",
			"FastEthernet1/0"
		]
	)

def test_build_syslog_source_interface(source_interface): 
	data = {
		"native_netconf": {
			"logging": {
				"source-interface": {
			        "interface-name": source_interface
			      }
			}
		}
	}

	result = build_syslog_netconf(data)

	assert result["source_interface"] == source_interface

def test_build_syslog_no_timestamps():
	data = {
		"native_netconf": {
			"service": {
				"timestamps": {
					"log": {
						"datetime": {}
					}
				}
			}
		}
	}

	result = build_syslog_netconf(data)

	assert result["timestamps"] is False 

def test_build_syslog_no_hosts():
	data = {
		"native_netconf":{
			"logging": {
				"host": {
			        "ipv4-host-list": []  
				}
			}
		  }	
		}

	result = build_syslog_netconf(data)

	assert result["hosts"] == []

def test_build_syslog_no_facility():
	data = {
		"native_netconf": {
			"logging": {}
		}
	}

	result = build_syslog_netconf(data) 

	assert result["facility"] == ""

def test_build_syslog_no_trap_level():
	data = {
		"native_netconf": {
			"logging": {
				"trap": {}
			}
		}
	}

	result = build_syslog_netconf(data)

	assert result["trap_level"] == ""

def test_build_syslog_no_source_interface(): 
	data = {
		"native_netconf": {
			"logging": {
				"source-interface": {}			
			}
		}
	}

	result = build_syslog_netconf(data)

	assert result["source_interface"] == ""