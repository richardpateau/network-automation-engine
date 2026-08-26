from src.collectors.netconf.builders import build_static
import pytest
from src.utils.helpers import safe_int


def test_build_static_valid(static_netconf):
    result = build_static(static_netconf)

    assert {
        "AD": 1,
        "network_address": "10.10.10.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": None,
        "name": None,
    } in result
    assert {
        "AD": 5,
        "network_address": "20.20.20.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": None,
        "name": None,
    } in result
    assert {
        "AD": 1,
        "network_address": "40.40.40.0",
        "mask": "255.255.255.0",
        "next_hop": [],
        "exit_interface": "gigabitethernet1",
        "name": None,
    } in result
    assert {
        "AD": 1,
        "network_address": "60.60.60.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": "gigabitethernet1",
        "name": None,
    } in result
    assert {
        "AD": 20,
        "network_address": "70.70.70.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": "gigabitethernet1",
        "name": None,
    } in result
    assert {
        "AD": 1,
        "network_address": "80.80.80.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": "gigabitethernet1",
        "name": "backup",
    } in result
    assert {
        "AD": 1,
        "network_address": "30.30.40.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": None,
        "name": "wan",
    } in result

    assert {
        "AD": 1,
        "network_address": "30.30.30.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": None,
        "name": "users",
    } in result


@pytest.mark.parametrize(
    "data", [{}, None, {"not_netconf": {}}, {"native_netconf": {}}]
)
def test_build_static_empty(data):
    assert build_static(data) == []


@pytest.mark.parametrize(
    "ad, network, mask, exit_interface, name",
    [
        ("20", "192.168.20.1", "255.255.255.0", "gigabitethernet1", ""),
        ("100", "203.118.20.1", "255.255.255.0", "gigabitethernet1/0", "wan"),
        ("2", "200.168.20.1", "255.255.255.0", "fastethernet5/0", None),
        ("45", "176.168.20.1", "255.255.255.0", "fastethernet9/1", "router"),
        ("86", "19.168.20.1", "255.255.255.0", "gigabitethernet3/1", "users"),
    ],
)
def test_build_static_only_exit_interface_only(ad, network, mask, exit_interface, name):
    data = {
        "native_netconf": {
            "ip": {
                "route": {
                    "ip-route-interface-forwarding-list": [
                        {
                            "prefix": network,
                            "mask": mask,
                            "fwd-list": {
                                "fwd": exit_interface,
                                "metric": ad,
                                "name": name,
                            },
                        }
                    ]
                }
            }
        }
    }

    result = build_static(data)

    assert {
        "AD": safe_int(ad),
        "network_address": network,
        "mask": mask,
        "next_hop": [],
        "exit_interface": exit_interface,
        "name": name,
    } in result


@pytest.mark.parametrize(
    "network, mask, exit_interface",
    [
        (
            "192.168.20.1",
            "255.255.255.0",
            "gigabitethernet1",
        ),
        ("203.118.20.1", "255.255.255.0", "gigabitrthernet1/0"),
        ("200.168.20.1", "255.255.255.0", "fastethernet5/0"),
        ("176.168.20.1", "255.255.255.0", "fastethernet9/1"),
        ("19.168.20.1", "255.255.255.0", "gigabitethernet3/1"),
    ],
)
def test_build_static_exit_interface(network, mask, exit_interface):
    data = {
        "native_netconf": {
            "ip": {
                "route": {
                    "ip-route-interface-forwarding-list": [
                        {
                            "prefix": network,
                            "mask": mask,
                            "fwd-list": {
                                "fwd": exit_interface,
                            },
                        }
                    ]
                }
            }
        }
    }

    result = build_static(data)
    assert {
        "AD": 1,
        "network_address": network,
        "mask": mask,
        "next_hop": [],
        "exit_interface": exit_interface,
        "name": None,
    } in result


@pytest.mark.parametrize(
    "network, mask, next_hop, ad, name",
    [
        ("192.168.20.1", "255.255.255.0", "192.168.1.2", "20", "voice"),
        ("203.118.20.1", "255.255.255.0", "192.168.20.1", "111", ""),
        ("200.168.20.1", "255.255.255.0", "201.113.1.1", "190", None),
        ("176.168.20.1", "255.255.255.0", "205.0.11.3", "95", "wan"),
        ("19.168.20.1", "255.255.255.0", "192.168.39.1", "2", "cisco"),
    ],
)
def test_build_static_only_next_hop(network, mask, next_hop, ad, name):
    data = {
        "native_netconf": {
            "ip": {
                "route": {
                    "ip-route-interface-forwarding-list": [
                        {
                            "prefix": network,
                            "mask": mask,
                            "fwd-list": {"fwd": next_hop, "metric": ad, "name": name},
                        }
                    ]
                }
            }
        }
    }

    result = build_static(data)
    assert {
        "AD": safe_int(ad) or 1,
        "network_address": network,
        "mask": mask,
        "next_hop": [next_hop],
        "exit_interface": None,
        "name": name,
    } in result


@pytest.mark.parametrize(
    "network, mask, exit_interface, next_hop, ad, name",
    [
        (
            "192.168.20.1",
            "255.255.255.0",
            "gigabitethernet1",
            "192.168.1.2",
            "20",
            "voice",
        ),
        (
            "203.118.20.1",
            "255.255.255.0",
            "gigabitethernet1/0",
            "192.168.20.1",
            "111",
            "",
        ),
        ("200.168.20.1", "255.255.255.0", "fastethernet5", "201.113.1.1", "190", "voice"),
        ("176.168.20.1", "255.255.255.0", "fastethernet9", "205.0.11.3", "95", "wan"),
        (
            "19.168.20.1",
            "255.255.255.0",
            "gigabitethernet5/1",
            "192.168.39.1",
            "2",
            "cisco",
        ),
    ],
)
def test_build_static_fully_specified(
    network, mask, exit_interface, next_hop, ad, name):
    data = {
        "native_netconf": {
            "ip": {
                "route": {
                    "ip-route-interface-forwarding-list": [
                        {
                            "prefix": network,
                            "mask": mask,
                            "fwd-list": {
                                "fwd": exit_interface,
                                "interface-next-hop": {
                                    "ip-address": next_hop,
                                    "name": name,
                                    "metric": ad,
                                },
                            },
                        }
                    ]
                }
            }
        }
    }

    result = build_static(data)
    assert {
        "AD": safe_int(ad) or 1,
        "network_address": network,
        "mask": mask,
        "next_hop": [next_hop],
        "exit_interface": exit_interface,
        "name": name,
    } in result


def test_build_static_multiple_next_hops():
    data = {
        "native_netconf": {
            "ip": {
                "route": {
                    "ip-route-interface-forwarding-list": [
                        {
                            "prefix": "192.168.255.1",
                            "mask": "255.255.255.0",
                            "fwd-list": [
                                {"fwd": "192.168.1.2"},
                                {"fwd": "192.168.1.3"},
                            ],
                        }
                    ]
                }
            }
        }
    }

    result = build_static(data)

    assert result[0]["next_hop"] == ["192.168.1.2", "192.168.1.3"]
    assert result[0]["AD"] == 1
