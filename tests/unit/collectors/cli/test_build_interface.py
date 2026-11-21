from src.collectors.cli.builders import build_interface

def test_build_interface_valid(interface_genie_output): 
	result = build_interface(interface_genie_output)

	assert "gigabitethernet0/0" in result
	assert result["gigabitethernet0/0"]["interface"] == "gigabitethernet0/0"
	assert result["gigabitethernet0/0"]["status"] == "up"
	assert result["gigabitethernet0/0"]["protocol"] == "up"
	assert result["gigabitethernet0/0"] ["is_up"] == True 

	assert result["gigabitethernet1/3"]["interface"] == "gigabitethernet1/3"
	assert result["gigabitethernet1/3"]["status"] == "down"
	assert result["gigabitethernet1/3"]["protocol"] == "down"
	assert result["gigabitethernet1/3"]["is_up"] == False  


def test_build_interface_empty(): 
	assert build_interface(None) == {}
	assert build_interface({}) == {}
	assert build_interface({"not_interface": {}}) == {}
	assert build_interface({"interface": None}) == {}

def test_build_interface_is_down():
	data = {
			"interface": {
		        "GigabitEthernet0/0": {
		            "status": "up",
		            "protocol": "down"
		            }   
		        }, 
		        "GigabitEthernet0/1": {
		            "status": "down",
		            "protocol": "up"
		            },
		        "GigabitEthernet0/2": {
		            "status": "up",
		            "protocol": "up"
		            }     
		    }
    
    result = build_interface(data)
    assert result["gigabitethernet0/0"]["is_up"] == False 
    assert result["gigabitethernet0/1"]["is_up"] == False 
    assert result["gigabitethernet0/2"]["is_up"] == True 

def test_build_interface_lowercase(interface_genie_output):
	result = build_interface(interface_genie_output)

	assert "GigabitEthernet0/0" not in result
	assert "GigabitEthernet0/1" not in result
	assert "gigabitethernet0/0" in result
	assert "gigabitethernet0/1" in result

def test_build_interface_non_dictionary(): 
	data = {
			"interface": {
		        "GigabitEthernet0/0": None    
		        }, 
		        "GigabitEthernet0/1": {
		            "status": "down",
		            "protocol": "up"
		            },
		        "GigabitEthernet0/2": "not_dictionary"   
		    }

    result = build_interface(data)

    assert len(result) == 1 
    assert "gigabitethernet0/0" not in result
    assert "gigabitethernet0/2" not in result
    assert "gigabitethernet0/1" in result

def test_build_interface_missing_fields():
	data = {
			"interface": {
		        "GigabitEthernet0/0": {}    
		        }
		    }

    result = build_interface(data)

    assert result["gigabitethernet0/0"]["status"] == ""
    assert result["gigabitethernet0/0"]["protocol"] == ""
    assert result["gigabitethernet0/0"]["is_up"] == False 