from src.collectors.netconf.builders import build_snmp_netconf

def test_build_snmp_valid(snmp_netconf):
	result = build_snmp_netconf(snmp_netconf)

	assert {"snmp_name": "private", "permission": "rw"} in result["communities"]
	assert {"snmp_name": "public", "permission": "ro"} in result["communities"]
	assert result["contact"] == "network-team@example.com"
	assert result["location"] == "new york datacenter rack 10"
	assert result["traps"] == {"snmp": True, "syslog": True, "config": True}
	assert {
			"community_name": "private",
			"snmp_ip": "10.10.10.50",
			"snmp_version": "2c" 
		   } in result["hosts"]
    assert {
			"community_name": "public" ,
			"snmp_ip": "10.10.10.60",
			"snmp_version": "2c"
		   } in result["hosts"]

def test_build_snmp_empty():
	assert build_snmp_netconf({}) == {
        "communities": [],
        "hosts": [],
        "traps": {},
        "location": "",
        "contact": "",
    }
    assert build_snmp_netconf(None) ==
    {
        "communities": [],
        "hosts": [],
        "traps": {},
        "location": "",
        "contact": "",
    }
     assert build_snmp_netconf({"not_netconf": {}}) ==
    {
        "communities": [],
        "hosts": [],
        "traps": {},
        "location": "",
        "contact": "",
    }
    assert build_snmp_netconf({"native_netconf": {}}) ==
    {
        "communities": [],
        "hosts": [],
        "traps": {},
        "location": "",
        "contact": "",
    }

@pytest.mark.parametrize(
		"name, permission", 
		[("routers","rw"), 
		 ("switches", "ro"), 
		 ("APs", "rw"), 
		 ("core_switches", "ro")
		]
	)
def test_build_snmp_communities(name, permission): 
	data = {
		"native_netconf":{
			"snmp-server": {
				"community-config": [
					{"name": name, "permission": permission}
				]
			}
		}
	}

	result = build_snmp_netconf(data)

	assert {"snmp_name": name, "permission": permission} in result["communities"]

@pytest.mark.parametrize(
		"contact, location", 
		[
			("network@yahoo.com", "NYC Data Center"),
			("team@gmail.com", "LA Data Center"),
			("cisco@gmail.com", "Denver Data Center")
		]
	)
def test_build_snmp_contact_location(contact, location):
	data = {
		"native_netconf": {
			"snmp-server": {
				"contact": {
		            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-snmp",
		            "#text": contact
		          },
		          "location": {
		            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-snmp",
		            "#text": location
		          }
			}
		}
	}

	result = build_snmp_netconf(data)

	assert result["contact"] == contact
	assert result["location"] == location

@pytest.mark.parametrize(
	  "name, ip, version", [
	  	("access_switches", "192.168.10.1", "1"), 
	  	("core_switches", "192.168.20.1", "2c"),
	  	("wan_routers", "192.168.30.1", "3")
	  ]
	)
def test_build_snmp_hosts(name, ip, version):
	data = {
		"native_netconf": {
			"snmp-server": {
				"host-config": {
					"ip-community": [
						{
			                "ip-address": ip,
			                "community-or-user": name,
			                "version": version
			            }
					]	
				}
			}
		}
	}

	result = build_snmp_netconf(data)

	assert {"community_name": name, "snmp_ip": ip, "snmp_version": version} in result["hosts"]

def test_build_snmp_traps():
	data = {
		"native_netconf": {
			"snmp-server": {
				"enable": {
					"enable-choice": {
						"traps": {
							"snmp": None,
						}
					}
				}			
			}
		}
	}

	result = build_snmp_netconf(data)

	assert result["traps"]["snmp"] is True 
	assert result["traps"]["syslog"] is False 
	assert result["traps"]["config"] is True 

def test_build_snmp_no_traps():
	data = {
		"native_netconf": {
			"snmp-server": {
				"enable": {
					"enable-choice": {
						"traps": {
							
						}
					}
				}			
			}
		}
	}

	result = build_snmp_netconf(data)

	assert result["traps"] == {}

def test_build_snmp_no_contact_location():
	data = {
		"native_netconf": {
			"snmp-server": {
				"contact": {},
		          "location": {}
			}
		}
	}

	result = build_snmp_netconf(data)

	assert result["contact"] == ""
	assert result["location"] == ""

def test_build_snmp_no_hosts
():
	data = {
		"native_netconf": {
			"snmp-server": {
				"host-config": {
					"ip-community": [
						
					]	
				}
			}
		}
	}

	result = build_snmp_netconf(data)

	assert result["hosts"] == []

def test_build_snmp_communities(name, permission): 
	data = {
		"native_netconf":{
			"snmp-server": {
				"community-config": []
			}
		}
	}

	result = build_snmp_netconf(data)

	assert result["communities"] == []
	