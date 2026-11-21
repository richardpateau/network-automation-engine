from src.collectors.cli.builders import build_cdp_netmiko


def test_build_cdp_valid(cdp_running_config):
    result = build_cdp_netmiko(cdp_running_config)

    assert result["timer"] == 60
    assert result["holdtime"] == 180
    assert result["enabled"] is True
    assert result["interfaces"]["gigabitethernet0/1"]["enabled"] is True
    assert result["interfaces"]["gigabitethernet0/2"]["enabled"] is True


def test_build_cdp_empty():
    assert build_cdp_netmiko({}) == {
        "enabled": False,
        "timer": None,
        "holdtime": None,
        "interfaces": {},
    }
    assert build_cdp_netmiko(None) == {
        "enabled": False,
        "timer": None,
        "holdtime": None,
        "interfaces": {},
    }
    assert build_cdp_netmiko({"not_cdp": {}}) == {
        "enabled": False,
        "timer": None,
        "holdtime": None,
        "interfaces": {},
    }
    assert build_cdp_netmiko({"cdp": None}) == {
        "enabled": False,
        "timer": None,
        "holdtime": None,
        "interfaces": {},
    }


def test_build_cdp_no_enabled():
    data = {
        "cdp": """
		Global CDP information:
		  Sending CDP packets every 70 seconds
		  Sending a holdtime value of 190 seconds
  		"""
    }
    result = build_cdp_netmiko(data)
    assert result["enabled"] is False
    assert result["timer"] == 70
    assert result["holdtime"] == 190


def test_build_cdp_no_interfaces():
    data = {
        "cdp": """
		Global CDP information:
		  Sending CDP packets every 60 seconds
		  Sending a holdtime value of 180 seconds
  		""",
        "cdp_interface": "",
    }
    result = build_cdp_netmiko(data)

    assert result["interfaces"] == {}


def test_build_no_cdp_global():
    data = {
        "cdp": "",
    }
    result = build_cdp_netmiko(data)
    assert result["timer"] == None
    assert result["holdtime"] == None
    assert result["enabled"] == None


def test_build_cdp_no_invalid_timer():
    data = {
        "cdp": """
		Global CDP information:
		  Sending CDP packets every abc seconds
		  Sending a holdtime value of abc seconds
  		""",
        "cdp_interface": "",
    }
    result = build_cdp_netmiko(data)

    assert result["timer"] is None
    assert result["holdtime"] is None


def test_build_cdp_invalid_interface():
    data = {
        "cdp": "",
        "cdp_interface": """
		Global CDP information:
		  Sending CDP packets every 60 seconds
		  Sending a holdtime value of 180 seconds
		  Sending CDPv2 advertisements is enabled
		""",
    }
    result = build_cdp_netmiko(data)

    assert result["interfaces"] == {}
