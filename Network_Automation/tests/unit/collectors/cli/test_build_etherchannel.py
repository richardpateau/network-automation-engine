from src.collectors.cli.builders import build_etherchannel
import pytest


def test_build_etherchannel_valid_lacp(etherchannel_running_config):
    result = build_etherchannel(etherchannel_running_config)

    assert result["enabled"] is True
    assert len(result["groups"]) == 3
    assert result["groups"][1]["mode"] == "active"
    assert result["groups"][1]["interfaces"] == [
        "gigabitethernet0/1",
        "gigabitethernet0/2",
    ]
    assert result["groups"][1]["type"] == "lacp"
    assert result["groups"][1]["description"] == "uplink to core"
    assert result["groups"][1]["switchport_mode"] == "trunk"


def test_build_etherchannel_valid_pagp(etherchannel_running_config):
    result = build_etherchannel(etherchannel_running_config)

    assert result["enabled"] is True
    assert result["groups"][2]["mode"] == "desirable"
    assert result["groups"][2]["interfaces"] == [
        "gigabitethernet0/3",
        "gigabitethernet1/0",
    ]
    assert result["groups"][2]["type"] == "pagp"
    assert result["groups"][2]["description"] == "server farm"
    assert result["groups"][2]["switchport_mode"] == "access"


def test_build_etherchannel_empty():
    assert build_etherchannel({}) == {"enabled": False, "groups": {}}
    assert build_etherchannel(None) == {"enabled": False, "groups": {}}
    assert build_etherchannel({"not_run": {}}) == {"enabled": False, "groups": {}}
    assert build_etherchannel({"running_config": {}}) == {
        "enabled": False,
        "groups": {},
    }


@pytest.mark.parametrize(
    "mode, expected_type",
    [
        ("active", "lacp"),
        ("passive", "lacp"),
        ("desirable", "pagp"),
        ("auto", "pagp"),
        ("on", "static"),
    ],
)
def test_build_etherchannel_types(mode, expected_type):
    data = {
"running_config": f"""
interface GigabitEthernet0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 ip arp inspection trust
 negotiation auto
 channel-group 1 mode {mode}
 """
    }

    result = build_etherchannel(data)

    assert result["groups"][1]["type"] == expected_type


@pytest.mark.parametrize("group", [1, 10, 20, 100])
def test_build_etherchannel_group(group):
    data = {
"running_config": f"""
interface GigabitEthernet0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 ip arp inspection trust
 negotiation auto
 channel-group {group} mode active
 """
    }
    result = build_etherchannel(data)

    assert group in result["groups"]


@pytest.mark.parametrize(
    "description",
    [
        "etherchannel bundle",
        "richard's etherchannel",
        "server farm ether",
        "portchannel uplink",
    ],
)
def test_build_etherchannel_description(description):
    data = {
"running_config": f"""
interface GigabitEthernet0/1
 channel-group 1 mode active
interface Port-channel1
 description {description}
 switchport trunk encapsulation dot1q
 switchport mode trunk
"""
    }

    result = build_etherchannel(data)

    assert result["groups"][1]["description"] == description


def test_build_etherchannel_no_group():
    data = {
"running_config": """
interface Port-channel1
 description uplink to core
 switchport trunk encapsulation dot1q
 switchport mode trunk
"""
    }

    result = build_etherchannel(data)

    assert result == {"enabled": False, "groups": {}}


def test_build_etherchannel_no_switchport_no_description():
    data = {
"running_config":
"""
interface GigabitEthernet0/1
 channel-group 1 mode active
interface Port-channel1
"""
    }

    result = build_etherchannel(data)

    assert result["groups"][1]["description"] is None
    assert result["groups"][1]["switchport_mode"] is None


def test_build_etherchannel_no_config():
    data = {
        "running_config": """
		interface GigabitEthernet0/0
		 switchport access vlan 98
		 switchport mode access
		 negotiation auto
		interface GigabitEthernet0/1
		 switchport trunk encapsulation dot1q
		 switchport mode trunk
		 ip arp inspection trust
		 negotiation auto
		"""
    }

    result = build_etherchannel(data)

    assert result["enabled"] is False
    assert result["groups"] == {}
