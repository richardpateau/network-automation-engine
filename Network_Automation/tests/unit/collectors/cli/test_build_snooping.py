from src.collectors.cli.builders import build_snooping

def test_build_snooping_valid(snooping_running_config):
    result = build_snooping(snooping_running_config)

    assert result["enabled_vlans"] == [10, 20, 30]
    assert result["option82"] is False
    assert len(result["interfaces"]) == 8
    assert result["interfaces"]["gigabitethernet0/2"]["rate_limit"] == 15
    assert result["interfaces"]["gigabitethernet0/1"]["trusted"] is True


def test_build_snooping_snooping_interfaces(snooping_running_config,):
    result = build_snooping(snooping_running_config)

    assert "gigabitethernet0/3" in result["interfaces"]
    assert "gigabitethernet1/0" in result["interfaces"]
    assert "gigabitethernet1/1" in result["interfaces"]

def test_build_snooping_empty():
    assert build_snooping({}) == {
        "enabled_vlans": [],
        "interfaces": {},
        "option82": True,
    }
    assert build_snooping(None) == {
        "enabled_vlans": [],
        "interfaces": {},
        "option82": True,
    }
    assert build_snooping({"not_snooping": {}}) == {
        "enabled_vlans": [],
        "interfaces": {},
        "option82": True,
    }
    assert build_snooping({"running_config": {}}) == {
        "enabled_vlans": [],
        "interfaces": {},
        "option82": True,
    }


def test_build_snooping_option_82():
    data = {
"running_config": """
ip dhcp snooping vlan 10,20,30
"""
    }

    result = build_snooping(data)
    assert result["option82"] is True


def test_build_snooping_trusted_interface():
    data = {
"running_config": """
interface GigabitEthernet0/1
 ip dhcp snooping trust
"""
    }

    result = build_snooping(data)

    assert result["interfaces"]["gigabitethernet0/1"]["trusted"] is True
    assert result["interfaces"]["gigabitethernet0/1"]["rate_limit"] == None


def test_build_snooping_rate_limit_only():
    data = {
"running_config": """
interface GigabitEthernet0/1
 ip dhcp snooping limit rate 20 
"""
    }

    result = build_snooping(data)

    assert result["interfaces"]["gigabitethernet0/1"]["trusted"] is False
    assert result["interfaces"]["gigabitethernet0/1"]["rate_limit"] == 20


def test_build_snooping_both_rate_and_trust():
    data = {
"running_config":
"""
interface GigabitEthernet0/1
 ip dhcp snooping limit rate 20 
 ip dhcp snooping trust
"""
    }

    result = build_snooping(data)
    assert result["interfaces"]["gigabitethernet0/1"]["trusted"] is True
    assert result["interfaces"]["gigabitethernet0/1"]["rate_limit"] == 20


def test_build_snooping_invalid_vlan():
    data = {
        "running_config": """
ip dhcp snooping vlan 10,20,30, abc, richard
ip dhcp snooping
"""
    }

    result = build_snooping(data)

    assert "abc" not in result["enabled_vlans"]
    assert "richard" not in result["enabled_vlans"]
