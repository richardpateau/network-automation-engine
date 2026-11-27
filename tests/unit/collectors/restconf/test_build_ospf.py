from src.collectors.restconf.builders import build_ospf
import pytest


def test_build_ospf_valid(ospf_restconf):
    result = build_ospf(ospf_restconf)

    assert result == {
        1: {
            "process_id": 1,
            "router_id": "1.1.1.1",
            "network_list": [
                {
                    "subnet": "192.168.10.0",
                    "wildcard": "0.0.0.255",
                    "area": 0,
                }
            ],
        },
        2: {
            "process_id": 2,
            "router_id": "2.2.2.2",
            "network_list": [
                {
                    "subnet": "192.168.20.0",
                    "wildcard": "0.0.0.255",
                    "area": 1,
                }
            ],
        },
    }


@pytest.mark.parametrize(
    "data", [{}, None, {"not_restconf": {}}, {"restconf_state": {}}]
)
def test_build_ospf_empty(data):
    assert build_ospf(data) == {}


@pytest.mark.parametrize(
    "proc_id, rid, subnet, wildcard, area",
    [
        (1, "4.4.4.4", "192.170.2.0", "0.0.255.255", 3),
        (3, "192.168.5.1", "200.0.112.0", "0.0.0.255", 10),
        (5, "203.0.112.1", "156.24.13.0", "0.0.7.255", 15),
        (10, "200.20.1.1", "160.50.20.0", "0.0.31.255", 20),
    ],
)
def test_build_ospf_parameters(proc_id, rid, subnet, wildcard, area):
    data = {
        "ospf_restconf": {
            "Cisco-IOS-XE-native:router": {
                "Cisco-IOS-XE-ospf:router-ospf": {
                    "ospf": {
                        "process-id": [
                            {
                                "id": proc_id,
                                "network": [
                                    {"ip": subnet, "wildcard": wildcard, "area": area}
                                ],
                                "router-id": rid,
                            }
                        ]
                    }
                }
            }
        }
    }

    result = build_ospf(data)

    assert result == {
        proc_id: {
            "process_id": proc_id,
            "router_id": rid,
            "network_list": [
                {
                    "subnet": subnet,
                    "wildcard": wildcard,
                    "area": area,
                }
            ],
        }
    }


def test_build_ospf_no_proc_id():
    data = {
        "ospf_restconf": {
            "Cisco-IOS-XE-native:router": {
                "Cisco-IOS-XE-ospf:router-ospf": {
                    "ospf": {
                        "process-id": [
                            {
                                "network": [
                                    {
                                        "ip": "192.168.20.1",
                                        "wildcard": "0.0.0.255",
                                        "area": 0,
                                    }
                                ],
                                "router-id": "1.1.1.1",
                            }
                        ]
                    }
                }
            }
        }
    }

    result = build_ospf(data)

    assert result == {}


def test_build_ospf_no_rid():
    data = {
        "ospf_restconf": {
            "Cisco-IOS-XE-native:router": {
                "Cisco-IOS-XE-ospf:router-ospf": {
                    "ospf": {
                        "process-id": [
                            {
                                "id": 1,
                                "network": [
                                    {
                                        "ip": "192.168.20.1",
                                        "wildcard": "0.0.0.255",
                                        "area": 0,
                                    }
                                ],
                            }
                        ]
                    }
                }
            }
        }
    }

    result = build_ospf(data)

    assert result[1]["router_id"] == ""


def test_build_ospf_no_networks():
    data = {
        "ospf_restconf": {
            "Cisco-IOS-XE-native:router": {
                "Cisco-IOS-XE-ospf:router-ospf": {
                    "ospf": {
                        "process-id": [{"id": 1, "network": [], "router-id": "1.1.1.1"}]
                    }
                }
            }
        }
    }

    result = build_ospf(data)

    assert result[1]["network_list"] == []


def test_build_ospf_no_ip():
    data = {
        "ospf_restconf": {
            "Cisco-IOS-XE-native:router": {
                "Cisco-IOS-XE-ospf:router-ospf": {
                    "ospf": {
                        "process-id": [
                            {
                                "id": 1,
                                "network": [{"wildcard": "0.0.0.255", "area": 0}],
                                "router-id": "1.1.1.1",
                            }
                        ]
                    }
                }
            }
        }
    }

    result = build_ospf(data)

    assert result[1]["network_list"][0]["subnet"] == ""


def test_build_ospf_no_area():
    data = {
        "ospf_restconf": {
            "Cisco-IOS-XE-native:router": {
                "Cisco-IOS-XE-ospf:router-ospf": {
                    "ospf": {
                        "process-id": [
                            {
                                "id": 1,
                                "network": [
                                    {
                                        "ip": "192.168.20.1",
                                        "wildcard": "0.0.0.255",
                                    }
                                ],
                                "router-id": "1.1.1.1",
                            }
                        ]
                    }
                }
            }
        }
    }

    result = build_ospf(data)

    assert result[1]["network_list"][0]["area"] is None


def test_build_ospf_no_mask():
    data = {
        "ospf_restconf": {
            "Cisco-IOS-XE-native:router": {
                "Cisco-IOS-XE-ospf:router-ospf": {
                    "ospf": {
                        "process-id": [
                            {
                                "id": 1,
                                "network": [{"ip": "192.168.20.1", "area": 0}],
                                "router-id": "1.1.1.1",
                            }
                        ]
                    }
                }
            }
        }
    }

    result = build_ospf(data)

    assert result[1]["network_list"][0]["wildcard"] == ""
