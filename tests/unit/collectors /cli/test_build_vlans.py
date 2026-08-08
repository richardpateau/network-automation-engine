from src.collectors.cli.builders import build_vlan

def test_build_vlan_valid_path(vlan_genie_output):
	result = build_vlan(vlan_genie_output)

	assert result["10"]["name"] == "USERS"
	assert result["20"]["name"] == "VOICE"
	assert result["30"]["name"] == "SERVERS"

def test_build_vlan_empty():
	assert build_vlan({}) == {}
	assert build_vlan(None) == {}

def test_build_vlan_none():
	result = build_vlan(None)

	assert result == {}

def test_build_vlan_missing_name():

	data = "vlans": {{"10": {},}}

    result = build_vlan(data)

    assert result["10"]["name"] == ""

def test_build_vlan_invalid_vlan_id():
	data = {
	    "vlans": {
	        "not_valid": {"name": "USERS"},
	        "20": {"name": "VOICE"}
	    	}

		}

	result = build_vlan(data)

	assert "not_valid" not in result
	assert "20" in result 
	assert result["20"]["name"] == "VOICE"