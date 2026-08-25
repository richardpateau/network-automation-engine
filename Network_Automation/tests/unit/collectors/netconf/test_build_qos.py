from src.collectors.netconf.builders import build_qos 

def test_build_qos_valid(qos_netconf): 
	result = build_qos(qos_netconf)

	assert len(result["policies"]) == 1 
	assert result["policies"][0]["policy_name"] == "wan-qos"
	class_maps = result["policies"][0]["class_maps"]

	assert {
		    "class_name": "voice",
		    "match_type": "match-any",
		    "protocol": "rtp audio",
		    "action_type":"priority",
		    "bandwidth": "",
		    "priority": "1000"
		  } in class_maps
	assert {
			    "class_name": "web",
			    "match_type": "match-all",
			    "protocol": "http",
			    "action_type":"bandwidth",
			    "bandwidth": "5000",
			    "priority": ""
			  } in class_maps
	assert result["policies"][0]["attachments"][0] == {
													  "interface": "gigabitethernet1", 
													  "direction": "output"
													}
def test_build_qos_empty():
	assert build_qos({}) == {"policies": []}
	assert build_qos(None) == {"policies": []}
	assert build_qos({"not_netconf": {}}) == {"policies": []}
	assert build_qos({"native_netconf": {}}) == {"policies": []}

def test_build_qos_no_attachments_interfaces(): 

	data = {
		  "native_netconf": {
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
		        }
		      ],
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
		        ]
		      }
		    },
		    "interface": {
		      "GigabitEthernet": [
		        {
		          "name": "1"
		        }
		      ]
		    }
		  }
		}
   

	result = build_qos(data)

	assert result["policies"][0]["attachments"] == []
	assert result["policies"][0]["policy_name"] == "wan-qos"
def test_build_qos_multiple_attachments(): 

	data = {
    "native_netconf": {
        "policy": {
            "class-map": [{
                "name": "VOICE",
                "prematch": "match-any",
                "match": {"protocol": {"protocols-list": {"protocols": "rtp audio"}}},
            }],
            "policy-map": {
                "name": "WAN-QOS",
                "class": [{
                    "name": "VOICE",
                    "action-list": {
                        "action-type": "priority",
                        "priority": {"kilo-bits": "1000"},
                    },
                }],
            },
        },
        "interface": {
            "GigabitEthernet": [
                {"name": "1", "service-policy": {"output": "WAN-QOS"}},
                {"name": "2", "service-policy": {"input": "WAN-QOS"}},
                {"name": "3", "service-policy": {"input": "WAN-QOS"}},
            ]
        },
    }
}
	

	result = build_qos(data)
	assert len(result["policies"][0]["attachments"]) == 3
	attachments = result["policies"][0]["attachments"]
	assert {"interface": "gigabitethernet1", "direction": "output"} in attachments
	assert {"interface": "gigabitethernet2", "direction": "input"} in attachments
	assert {"interface": "gigabitethernet3", "direction": "input"} in attachments

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

	assert result["policies"][0]["policy_name"] == "wan-qos"
	assert result["policies"][0]["attachments"] == []

def test_build_qos_no_match_type_no_protocol(): 

	data = {
		"native_netconf":{
			"policy": {
		      "class-map": [
					      	{
			          "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-policy",
			          "name": "VOICE",
			          "match": {
			            "protocol": {
			              "protocols-list": {
			              }
			            }
			          }
			        }
		      ],
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

	assert result["policies"][0]["class_maps"][0]["class_name"] == "voice"
	assert result["policies"][0]["class_maps"][0]["match_type"] == ""
	assert result["policies"][0]["class_maps"][0]["protocol"] == ""

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
			       },
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