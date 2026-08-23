from src.collectors.cli.builders import build_port_security
import pytest


def test_build_port_security_first_valid(port_security_running_config):
    result = build_port_security(port_security_running_config)

    assert len(result["interfaces"]) == 9
    assert result["interfaces"]["gigabitethernet0/1"]["enabled"] is True
    assert result["interfaces"]["gigabitethernet0/1"]["maximum"] == 2
    assert result["interfaces"]["gigabitethernet0/1"]["violation"] == "restrict"
    assert result["interfaces"]["gigabitethernet0/1"]["sticky"] is True
    assert result["interfaces"]["gigabitethernet0/1"]["mac_addresses"] == []


def test_build_port_security_second_valid(port_security_running_config):
    result = build_port_security(port_security_running_config)

    assert result["interfaces"]["gigabitethernet0/2"]["enabled"] is True
    assert result["interfaces"]["gigabitethernet0/2"]["maximum"] == 3
    assert result["interfaces"]["gigabitethernet0/2"]["violation"] == "shutdown"
    assert result["interfaces"]["gigabitethernet0/2"]["sticky"] is False
    assert len(result["interfaces"]["gigabitethernet0/2"]["mac_addresses"]) == 2
    assert result["interfaces"]["gigabitethernet0/2"]["mac_addresses"] == [
        "0050.56aa.aaaa",
        "0050.56aa.bbcc",
    ]


def test_build_port_security_no_configuration(port_security_running_config):
    result = build_port_security(port_security_running_config)

    assert result["interfaces"]["gigabitethernet0/0"]["enabled"] is False
    assert result["interfaces"]["gigabitethernet0/0"]["maximum"] == None
    assert result["interfaces"]["gigabitethernet0/0"]["violation"] == None
    assert result["interfaces"]["gigabitethernet0/0"]["sticky"] is False
    assert result["interfaces"]["gigabitethernet0/0"]["mac_addresses"] == []


def test_build_port_security_empty():
    assert build_port_security({}) == {"interfaces": {}}
    assert build_port_security(None) == {"interfaces": {}}
    assert build_port_security({"not_port": {}}) == {"interfaces": {}}
    assert build_port_security({"running_config": None}) == {"interfaces": {}}


def test_build_port_security_no_interfaces():
    data = {
        "running_config": """
switchport access vlan 98
switchport mode access
negotiation auto
"""
    }
    result = build_port_security(data)

    assert result["interfaces"] == {}


@pytest.mark.parametrize("violation", ["restrict", "shutdown", "protect"])
def test_build_port_security_violation(violation):
    data = {
        "running_config": f"""
interface GigabitEthernet0/1
 switchport access vlan 10
 switchport mode access
 switchport port-security maximum 2
 switchport port-security violation {violation}
 switchport port-security mac-address sticky
 switchport port-security
 negotiation auto
 """
    }

    result = build_port_security(data)
    assert result["interfaces"]["gigabitethernet0/1"]["violation"] == violation


@pytest.mark.parametrize("maximum", [1, 3, 5, 8, 10])
def test_build_port_security_maximum(maximum):
    data = {
        "running_config": f"""
interface GigabitEthernet0/1
 switchport access vlan 10
 switchport mode access
 switchport port-security maximum {maximum}
 switchport port-security violation restrict
 switchport port-security mac-address sticky
 switchport port-security
 negotiation auto
 """
    }

    result = build_port_security(data)
    assert result["interfaces"]["gigabitethernet0/1"]["maximum"] == maximum


def test_build_port_security_no_port_security_command():
    data = {
        "running_config": """
interface GigabitEthernet0/1
 switchport access vlan 10
 switchport mode access
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
 negotiation auto
 """
    }

    result = build_port_security(data)

    assert result["interfaces"]["gigabitethernet0/1"]["enabled"] is False
