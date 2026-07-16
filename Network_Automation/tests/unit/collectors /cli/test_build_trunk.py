from src.collectors.cli.builders import build_trunk 

def test_build_trunk_valid(access_trunk_genie_output): 
	result = build_trunk(access_trunk_genie_output)

	assert len(result) == 2 
	assert "gigabitethernet0/3" in result 
	assert "gigabitethernet1/0" in result
	assert result["gigabitethernet0/3"]["trunk_vlans"] == "10,20,30,40,50"
	assert result["gigabitethernet1/0"]["trunk_vlans"] == "10,20,30,40"

def test_build_no_trunks():
	data = {
		"switchports": {
		    "GigabitEthernet0/0": {
		      "operational_mode": "static access",
		    },
		    "GigabitEthernet0/1": {

		      "operational_mode": "static access",
		      
		    	}
			}
		}

	result = build_trunk(data)

	assert result = {}

def test_build_trunk_empty_input():
	assert build_trunk({}) == {}
	assert build_trunk(None) == {}
	assert build_trunk({"not_switchport": {}}) == {}

def test_build_trunk_default():
	assert 