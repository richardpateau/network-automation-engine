from src.collectors.cli.builders import build_stp_global 

def test_build_stp_global_valid(stp_global_genie_output):
	result = build_stp_global(stp_global_genie_output)


	assert result["mode"] == "pvst"
	assert len(result["vlan_priorities"]) == 7
	assert result["vlan_priorities"][10] == 24586
	assert result["vlan_priorities"][20] == 28692
	assert result["vlan_priorities"][30] == 12318
	assert result["vlan_priorities"][40] == 16424

def test_build_stp_global_empty(): 
	assert build_stp_global(None) == {}
	assert build_stp_global({}) == {}
	assert build_stp_global({"not_stp": {}}) == {}
	assert build_stp_global({"stp": None}) == {"mode": "","vlan_priorities": {},}

def test_build_stp_global_unknown(): 
	data = {
		"stp": {}

				}
	result = build_stp_global(data)

	assert result["mode"] == "unknown"
	assert result["vlan_priorities"] == {}

def test_build_stp_global_missing_priority():
	data = {
			 "pvst": {
		        "vlans": {
		            "20": {}
					}
				}
			}
	
	result = build_stp_global(data)
	assert result["vlan_priorities"][20] == 32768

def test_build_stp_global_invalid_vlan():
	data = { 
	"stp": {
		"pvst": {
        "vlans": {
            "20": {
                "bridge": {
                    "configured_bridge_priority": 28692,
                    	}
								},
			"abc": {
               "bridge": {
                    "configured_bridge_priority": 32768,
            	  				},
           	 				}
           				}
           			}
          		}
          	}




    result = build_stp_global(data)

    assert len(result["vlan_priorities"]) == 1 
   	assert "abc" not in result["vlan_priorities"]
   	assert result["vlan_priorities"][20] == 28692

