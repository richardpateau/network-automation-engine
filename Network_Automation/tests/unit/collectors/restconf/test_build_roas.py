from src.collectors.restconf.builders import build_roas 
import pytest 

def test_build_roas_valid(roas_restconf): 
	result = build_roas(roas_restconf)

	assert result["gigabitethernet2.10"] == {
											"interface": "gigabitethernet2.10",
											"router_vlan": 20,
											"ip": "192.168.20.1",
											"mask": "255.255.255.0"
										}

	assert result["gigabitethernet1.30"] == {
											"interface": "gigabitethernet1.30",
											"router_vlan": 30,
											"ip": "192.168.30.1",
											"mask": "255.255.255.0"
										}

@pytest.mark.parametrize("data", [
		{}, None, {"not_restconf": {}}, {"interface_restconf": {}}
	])	
def test_build_roas_empty(data): 
	assert build_roas(data) == {}

@pytest.mark.parametrize("int_type, int_num, vlan, ip, mask",
	  [
	  	("GigabitEthernet", "2.30", 50, "203.0.113.10", "255.255.255.0"),
	  	("GigabitEthernet", "2.50", 100, "192.168.1.0", "255.255.255.0"),
	  	("FastEthernet", "5.10", 40, "200.0.112.12", "255.255.0.0"),
	  	("FastEthernet", "3.20", 30, "205.12.13.14", "255.0.0.0")
	  ]
	)
def test_build_roas_valid_parameters(int_type, int_num, vlan, ip, mask): 
	data = {
		"interface_restconf": {
			"Cisco-IOS-XE-native:interface": {
				int_type: [
			        {
			          "name": int_num,
			          "encapsulation": {
			            "dot1Q": {
			              "vlan-id": vlan
			            }
			          },
			          "ip": {
			            "address": {
			              "primary": {
			                "address": ip,
			                "mask": mask
					               		}
					            	}
					          	}
					        }
					    ]
					}
				}
			}
	result = build_roas(data)

	assert result[f"{int_type}{int_num}".lower()] == {
														"interface": f"{int_type}{int_num}".lower(),
														"router_vlan": vlan,
														"ip": ip, 
														"mask": mask
													}

def test_build_roas_continue(): 
	data = {
		"interface_restconf": {
			"Cisco-IOS-XE-native:interface": {
				"GigabitEthernet": [
			        {
			          "name": "2",
			          "encapsulation": {
			            "dot1Q": {
			              "vlan-id": 30
			            }
			          },
			          "ip": {
			            "address": {
			              "primary": {
			                "address": "192.168.1.1",
			                "mask": "255.255.255.0"
					               		}
					            	}
					          	}
					        }
					    ]
					}
				}
			}
	result = build_roas(data)

	assert "gigabitethernet2" not in result 
	assert "GigabitEthernet2" not in result 

def test_build_roas_no_roas(): 
	data = {
		"interface_restconf": {
			"Cisco-IOS-XE-native:interface": {
				"GigabitEthernet": [
			        {
			          "name": "2",
			         
					        }
					    ]
					}
				}
			}
	assert build_roas(data) == {} 

def test_build_roas_no_ip():
	data = {
			"interface_restconf": {
				"Cisco-IOS-XE-native:interface": {
					"GigabitEthernet": [
						{
							"name": "2",
							"encapsulation": {
								"dot1Q": {
									"vlan-id": 30
								}
							},
							"ip": {}
						}
					]
				}
			}
		}

	assert build_roas(data) == {}

def test_build_roas_no_vlan(): 
	data = {
		"interface_restconf": {
			"Cisco-IOS-XE-native:interface": {
				"GigabitEthernet": [
			        {
			          "name": "2",
			          "encapsulation": {
			            "dot1Q": {}
			          },
			          "ip": {
			            "address": {
			              "primary": {
			                "address": "192.168.1.1",
			                "mask": "255.255.255.0"
					               		}
					            	}
					          	}
					        }
					    ]
					}
				}
			}
	assert build_roas(data) == {}

def test_build_roas_no_mask(): 
	data = {
		"interface_restconf": {
			"Cisco-IOS-XE-native:interface": {
				"GigabitEthernet": [
			        {
			          "name": "2",
			          "encapsulation": {
			            "dot1Q": {}
			          },
			          "ip": {
			            "address": {
			              "primary": {
			                "address": "192.168.1.1",
					               		}
					            	}
					          	}
					        }
					    ]
					}
				}
			}
	assert build_roas(data) == {}