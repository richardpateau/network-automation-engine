from src.collectors.netconf.builders import build_qos 

def test_build_qos_valid(qos_netconf): 
	result = build_qos(qos_netconf)

	assert len(result["policies"]) == 1 
	assert result["policies"][0]["policy_name"] == "wan-qos"
	assert result["policies"][0]["class_maps"][0] == {
												    "name": "voice",
												    "match_type": "match-any",
												    "protocol": "rtp audio",
												    "action_type":"priority",
												    "bandwidth": "",
												    "priority": "1000"
												  }
	assert result["policies"][1]["class_maps"] == {
												    "name": "web",
												    "match_type": "match-any",
												    "protocol": "http",
												    "action_type":"bandwidth",
												    "bandwidth": "5000",
												    "priority": ""
												  }
	assert result["policies"][0]["attachments"][0] == {
													  "interface": "gigabitethernet1", 
													  "direction": "output"
													}
def test_build_qos_empty():
	assert build_qos({}) == {"policies": []}
	assert build_qos(None) == {"policies": []}
	assert build_qos({"not_netconf": {}}) == {"policies": []}
	assert build_qos({"native_netconf": {}}) == {"policies": []}

def test_build_qos_no_service_policy(): 

	data = {
		"native_netconf":{
			"policy": {
		      "class-map": [
		        {
		          "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
		          "name": "VOICE",
		          "prematch": "match-any",
		          "match": {
		            "protocol": {
		              "protocols-list": {
		                "protocols": "rtp audio"
		              }
		            }
		          }
		        }],"policy-map": {
			        "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			        "name": "WAN-QOS",
			        "class": [
			          {
			            "name": "VOICE",
			            "action-list": {
			              "action-type": "priority",
			              "priority": {
			                "kilo-bits": "1000"
			              }
			            }
			          }
			        ]
			       },
				"interface": {
		      "GigabitEthernet": [
		        {"name": "1",},
			    ]
			  }
			}
	      } 
	    }
	   

	result = build_qos(data)

	assert result["attachments"] == []
	assert result["policies"]["policy_name"] == "wan-qos"
def test_build_qos_no_service_policy(): 

	data = {
		"native_netconf":{
			"policy": {
		      "class-map": [
		        {
		          "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
		          "name": "VOICE",
		          "prematch": "match-any",
		          "match": {
		            "protocol": {
		              "protocols-list": {
		                "protocols": "rtp audio"
		              }
		            }
		          }
		        }],"policy-map": {
			        "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			        "name": "WAN-QOS",
			        "class": [
			          {
			            "name": "VOICE",
			            "action-list": {
			              "action-type": "priority",
			              "priority": {
			                "kilo-bits": "1000"
			              }
			            }
			          }
			        ]
			       },
				"interface": {
		      "GigabitEthernet": [
		        {"name": "1",
		         "service-policy": {
			            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			            "output": "WAN-QOS"
			          }
		        },
		        {"name": "2",
		         "service-policy": {
			            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			            "input": "WAN-QOS"
			          }
		        }, 
		        {"name": "3",
		         "service-policy": {
			            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			            "input": "WAN-QOS"
			          }
			    }

			    ]
			  
			}
	      } 
	    }
	   }


	result = build_qos(data)
	assert len(result["policies"]["attachments"]) == 3
	assert result["policies"][0]["attachments"] == {"interface": "gigabitethernet1", "direction": "output"}
	assert result["policies"][1]["attachments"] == {"interface": "gigabitethernet2", "direction": "input"}
	assert result["policies"][2]["attachments"] == {"interface": "gigabitethernet3", "direction": "input"}

def test_build_qos_no_attachments_or_class(): 

	data = {
		"native_netconf":{
			"policy": {
		      "policy-map": {
			        "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			        "name": "WAN-QOS",
			        "class": [
			          {
			            "name": "VOICE",
			            "action-list": {
			              "action-type": "priority",
			              "priority": {
			                "kilo-bits": "1000"
			              }
			            }
			          }
			        ],
			}
	      } 
	    }
	   }

	result = build_qos(data)

	assert result["policies"] == []

def test_build_qos_no_attachments_or_class(): 

	data = {
		"native_netconf":{
			"policy": {
		      "class-map": [],
		      "policy-map": {
			        "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			        "name": "WAN-QOS",
			        "class": [
			          {
			            "name": "VOICE",
			            "action-list": {
			              "action-type": "priority",
			              "priority": {
			                "kilo-bits": "1000"
			              }
			            }
			          }
			        ],
			  	},
			 "interface": {
		      "GigabitEthernet": [
		        {"name": "1",},
			    ]
			}
	      } 
	    }
	   }

	result = build_qos(data)

	assert result["policies"]["class_maps"][0]["class_name"] == "VOICE"
	assert result["policies"]["class_maps"][0]["match_type"] == ""
	assert result["policies"]["class_maps"][0]["protocol"] == ""

def test_build_qos_no_multiple_policies(): 

	data = {
		"native_netconf":{
			"policy": {
		      "class-map": [],
		      "policy-map": [
			        {"@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			        "name": "WAN-QOS",
			        "class": [
			          {
			            "name": "VOICE",
			            "action-list": {
			              "action-type": "priority",
			              "priority": {
			                "kilo-bits": "1000"
			              }
			            }
			          }
			        ]
			       }
			       {"@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			        "name": "LAN-QOS",
			        "class": [
			          {
			            "name": "VOICE",
			            "action-list": {
			              "action-type": "priority",
			              "priority": {
			                "kilo-bits": "1000"
			              }
			            }
			          }
			        ]
			       },
			       {"@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			        "name": "LAN",
			        "class": [
			          {
			            "name": "VOICE",
			            "action-list": {
			              "action-type": "priority",
			              "priority": {
			                "kilo-bits": "1000"
			              }
			            }
			          }
			        ]
			       }
			  	],
			  "interface": {
		      "GigabitEthernet": [
		        {"name": "1",},
		       ]
			}
	      } 
	    }
	   }

	result = build_qos(data)
	assert len(result["policies"]) == 3 
	assert result["policies"][0]["policy_name"] == "wan-qos"
	assert result["policies"][1]["policy_name"] == "lan-qos"
	assert result["policies"][2]["policy_name"] == "lan"