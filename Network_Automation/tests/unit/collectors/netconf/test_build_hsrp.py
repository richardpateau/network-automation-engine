from src.collectors.netconf.builders import build_hsrp


def test_build_hsrp_valid(hsrp_netconf):
    result = build_hsrp(hsrp_netconf)

    assert result[0]["interface"] == "gigabitethernet1.50"
    assert result[0]["version"] == 2
    assert result[0]["group"] == 10
    assert result[0]["vip"] == "192.168.10.1"
    assert result[0]["preempt"] == True
    assert result[0]["priority"] == 110
    assert result[0]["router_vlan"] == 10


def test_build_hsrp_empty():
    assert build_hsrp({}) == []
    assert build_hsrp(None) == []
    assert build_hsrp({"not_netconf": {}}) == []
    assert build_hsrp({"native_netconf": {}}) == []


def test_build_no_standby():
    data = {
        "native_netconf": {
            "interface": {
                "GigabitEthernet": [
                    {
                        "name": "1",
                    }
                ]
            }
        }
    }


    result = build_hsrp(data)

    assert result == []


def test_build_hsrp_no_interface():
    data = {
        "native_netconf": {
            "interfaces": {
                "GigabitEthernet": [
                    {
                        "name": "1",
                    }
                ]
            }
        }
    }


    result = build_hsrp(data)

    assert result == []


def test_build_hsrp_default():
    data = {
        "native_netconf": {
            "interface": {
                "GigabitEthernet": [
                    {
                        "name": "1.50",
                        "encapsulation": {
                            "dot1Q": {
                            }
                        },
                        "standby": {
                            "standby-list": {
                                "ip": {},
                            }
                        }
                    }
                ]
            }
        }
    }

    result = build_hsrp(data)

    assert result[0]["interface"] == "gigabitethernet1.50"
    assert result[0]["version"] is None
    assert result[0]["group"] is None
    assert result[0]["vip"] == ""
    assert result[0]["preempt"] is False
    assert result[0]["router_vlan"] is None


def test_build_hsrp_multiple_interfaces():
    data = {
        "native_netconf": {
            "interface": {
                "GigabitEthernet": [
                    {
                        "name": "1.50",
                        "encapsulation": {
                            "dot1Q": {
                            }
                        },
                        "standby": {
                            "version": "2",
                            "standby-list": {
                                "group-number": "10",
                                "ip": {
                                    "address": "192.168.10.1"
                                },
                                "preempt": None,
                                "priority": "110"
                            }
                        }
                    },
                ],
                "FastEthernet": [
                    {
                        "name": "1.60",
                        "encapsulation": {
                            "dot1Q": {
                            }
                        },
                        "standby": {
                            "version": "1",
                            "standby-list": {
                                "group-number": "10",
                                "ip": {
                                    "address": "192.168.20.1"
                                },
                                "preempt": None,
                                "priority": "110"
                            }
                        }
                    },
                    {
                        "name": "1.70",
                        "encapsulation": {
                            "dot1Q": {
                            }
                        },
                        "standby": {
                            "version": "1",
                            "standby-list": {
                                "group-number": "10",
                                "ip": {
                                    "address": "192.168.30.1"
                                },
                                "preempt": None,
                                "priority": "110"
                            }
                        }
                    },

                ]
            }
        }
    }

    result = build_hsrp(data)

    assert len(result) == 3
    interfaces = {e["interface"] for e in result}
    assert "gigabitethernet1.50" in interfaces
    assert "fastethernet1.60" in interfaces
    assert "fastethernet1.70" in interfaces
