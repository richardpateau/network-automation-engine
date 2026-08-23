from src.collectors.cli.builders import build_snmp_netmiko


def test_build_snmp_valid(snmp_running_config):
    result = build_snmp_netmiko(snmp_running_config)

    assert len(result["communities"]) == 2
    assert {"snmp_name": "network_ro", "permission": "ro"} in result["communities"]
    assert {"snmp_name": "network_rw", "permission": "rw"} in result["communities"]
    assert result["location"] == "NYC Data Center Rack 12"
    assert result["contact"] == "Network Team admin@example.com"
    assert result["traps"]["snmp"] is True
    assert result["traps"]["syslog"] is True
    assert len(result["hosts"]) == 1
    assert {
           "snmp_ip": "192.168.100.50",
           "snmp_version": "2c",
           "snmp_name": "NETWORK_RO",
           } in result["hosts"]


def test_build_snmp_empty():
    assert build_snmp_netmiko({}) == {}
    assert build_snmp_netmiko(None) == {}
    assert build_snmp_netmiko({"not_run": None}) == {}


def test_build_snmp_no_config():
    data = {
        "running_config": """
interface GigabitEthernet0/0
 switchport access vlan 98
 switchport mode access
 negotiation auto
"""
    }
    result = build_snmp_netmiko(data)

    assert result["communities"] == []
    assert result["hosts"] == []
    assert result["traps"] == {}
    assert result["location"] == ""
    assert result["contact"] == ""


def test_build_snmp_lowercase(snmp_running_config):
    result = build_snmp_netmiko(snmp_running_config)

    assert result["communities"][0]["permission"] == "ro"
    assert result["communities"][1]["permission"] == "rw"


def test_build_snmp_invalid_host():
    data = {
        "running_config": """
snmp-server host 192.168.100.50 version 2c 
"""
    }
    result = build_snmp_netmiko(data)

    assert result["hosts"] == []


def test_build_snmp_multiple_hosts():
    data = {
        "running_config": """
snmp-server host 192.168.100.50 version 2c NETWORK_RO
snmp-server host 192.168.100.51 version 2c NETWORK_RO
snmp-server host 192.168.100.52 version 2c NETWORK_RO
"""
    }


    result = build_snmp_netmiko(data)

    assert len(result["hosts"]) == 3


def test_build_snmp_partial_config():
    data = {
        "running_config": """
snmp-server community NETWORK_RO RO
snmp-server community NETWORK_RW RW
snmp-server host 192.168.100.50 version 2c NETWORK_RO
"""
    }
    result = build_snmp_netmiko(data)

    assert result["traps"] == {}
    assert result["location"] == ""
    assert result["contact"] == ""
    assert {
               "snmp_ip": "192.168.100.50",
               "snmp_version": "2c",
               "snmp_name": "NETWORK_RO",
           } in result["hosts"]
    assert {"snmp_name": "network_ro", "permission": "ro"} in result["communities"]
    assert {"snmp_name": "network_rw", "permission": "rw"} in result["communities"]
