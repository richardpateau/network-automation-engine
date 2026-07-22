from src.collectors.cli.builders import build_dai


def test_build_dai_valid(dai_running_config):
    result = build_dai(dai_running_config)

    assert result["arp_inspection"] is True
    assert result["enabled_vlans"] == [10, 20, 30]
    assert result["log_buffer"]["enabled"] is True
    assert result["log_buffer"]["entries"] == 100
    assert result["interfaces"]["gi0/1"]["trusted"] is True
    assert result["interfaces"]["gi0/2"]["rate_limit"] == 15


def test_build_dai_empty():
    assert build_dai({}) == {
        "arp_inspection": "",
        "enabled_vlans": [],
        "interfaces": {},
        "log_buffer": {},
    }
    assert build_dai(None) == {
        "arp_inspection": "",
        "enabled_vlans": [],
        "interfaces": {},
        "log_buffer": {},
    }
    assert build_dai({"not_dai"}) == {
        "arp_inspection": "",
        "enabled_vlans": [],
        "interfaces": {},
        "log_buffer": {},
    }
    assert build_dai({"running_config": {}}) == {
        "arp_inspection": "",
        "enabled_vlans": [],
        "interfaces": {},
        "log_buffer": {},
    }


def test_build_dai_no_buffer():
    data = {
        "running_config": """
	 	ip arp inspection vlan 10,20,30
	 	"""
    }

    result = build_dai(data)

    assert ["log_buffer"] == {}


def test_build_dai_rate_and_trust():
    data = {
        "dai_interfaces": """
		"\n Interface        Trust State     Rate (pps)    
		Burst Interval\n ---------------  -----------     ----------    --------------\n 
		Gi0/0            Untrusted               15                 1\n Gi0/1            
		Trusted               None               N/A\n

		"""
    }

    result = build_dai(data)

    assert result["interfaces"]["gi0/0"]["rate_limit"] == 15
    assert result["interfaces"]["gi0/0"]["trusted"] is False


def test_build_dai_no_buffer():
    data = {
        "running_config": """
	 	ip arp inspection vlan 10,20,30, abc, richard 
	 	"""
    }

    result = build_dai(data)

    assert result["enabled_vlans"] == [10, 20, 30]
    assert "richard" not in result["enabled_vlans"]
    assert "abc" not in result["enabled_vlans"]


def test_build_dai_no_config():
    data = {
        "running_config": """
		interface GigabitEthernet0/1
		 ip dhcp snooping limit rate 20 
		 ip dhcp snooping trust

		""",
        "dai_interfaces": "",
    }

    result = build_dai(data)

    assert result["arp_inspection"] is False
    assert result["enabled_vlans"] == []
    assert result["interfaces"] == {}
    assert result["log_buffer"] == {}


@pytest.mark.parametrize("rate", [10, 40, 50, 60, 100])
def test_build_dai_rate(rate):
    data = {
        "dai_interfaces": f"""
		"\n Interface        Trust State     Rate (pps)    
		Burst Interval\n ---------------  -----------     ----------    --------------\n 
		Gi0/0            Untrusted               {rate}                 1\n Gi0/1            
		Trusted               None               N/A\n
		"""
    }

    result = build_dai(data)

    assert result["interfaces"]["gi0/0"]["rate_limit"] == rate
