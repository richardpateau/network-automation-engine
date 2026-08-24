from src.collectors.netconf.builders import build_dhcp
import pytest


def test_build_dhcp_valid(dhcp_netconf):
    result = build_dhcp(dhcp_netconf)

    assert {"start_ip": "192.168.10.1", "end_ip": "192.168.10.20"} in result["excluded_addresses"]
    assert {"start_ip": "192.168.20.1", "end_ip": "192.168.20.10"} in result["excluded_addresses"]
    assert {
               "pool_name": "users",
               "lease_days": 7,
               "lease_hours": 12,
               "lease_minutes": 30,
               "default_gateway": "192.168.10.1",
               "dns_ip": ["4.4.4.4", "8.8.8.8"],
               "domain_name": "company.local",
               "pool_ip": "192.168.10.0",
               "pool_mask": "255.255.255.0"
           } in result["pools"]


    assert {"helper_ip": "10.10.10.5", "interface": "gigabitethernet2"} in result["helper"]["interfaces"]
    assert {"helper_ip": "10.10.10.6", "interface": "gigabitethernet2"} in result["helper"]["interfaces"]


def test_build_dhcp_empty():
    assert build_dhcp({}) == {"excluded_addresses": [], "pools": [], "helper": {"interfaces": []}}
    assert build_dhcp(None) == {"excluded_addresses": [], "pools": [], "helper": {"interfaces": []}}
    assert build_dhcp({"not_netconf": {}}) == {"excluded_addresses": [], "pools": [], "helper": {"interfaces": []}}
    assert build_dhcp({"native_netconf": {}}) == {"excluded_addresses": [], "pools": [], "helper": {"interfaces": []}}


@pytest.mark.parametrize("days,hours,minutes",
                           [
                               (1, 2, 3),
                               (2, 5, 30),
                               (3, 10, 20),
                               (1, 20, 10)
                           ]
                           )
def test_build_dhcp_lease_times(days, hours, minutes):
    data = {
        "native_netconf": {
            "ip": {
                "dhcp": {
                    "pool": [
                        {
                            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-dhcp",
                            "id": "USERS",
                            "lease": {
                                "lease-value": {
                                    "days": days,
                                    "hours": hours,
                                    "minutes": minutes
                                }
                            }
                        }
                    ]
                }
            }
        }
    }

    result = build_dhcp(data)

    assert result["pools"][0]["pool_name"] == "users"
    assert result["pools"][0]["lease_days"] == days
    assert result["pools"][0]["lease_hours"] == hours
    assert result["pools"][0]["lease_minutes"] == minutes


def test_build_dhcp_no_helper(dhcp_netconf):
    data = {
        "native_netconf": {
            "interface": {
                "GigabitEthernet": [
                    {"name": "1", }
                ]
            }
        }
    }
    result = build_dhcp(data)
    assert result["helper"]["interfaces"] == []


def test_build_dhcp_multiple_pools():
    data = {
        "native_netconf": {
            "ip": {
                "dhcp": {
                    "pool": [
                        {
                            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-dhcp",
                            "id": "USERS",
                            "lease": {
                                "lease-value": {
                                    "days": "7",
                                    "hours": "12",
                                    "minutes": "30"
                                }
                            },
                            "default-router": {
                                "default-router-list": "192.168.10.1"
                            },
                            "dns-server": {
                                "dns-server-list": [
                                    "4.4.4.4",
                                    "8.8.8.8"
                                ]
                            },
                            "domain-name": "company.local",
                            "network": {
                                "primary-network": {
                                    "number": "192.168.10.0",
                                    "mask": "255.255.255.0"
                                }
                            }
                        },
                        {
                            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-dhcp",
                            "id": "voice",
                            "lease": {
                                "lease-value": {
                                    "days": "7",
                                    "hours": "12",
                                    "minutes": "30"
                                }
                            },
                            "default-router": {
                                "default-router-list": "192.168.10.1"
                            },
                            "dns-server": {
                                "dns-server-list": [
                                    "4.4.4.4",
                                    "8.8.8.8"
                                ]
                            },
                            "domain-name": "company.local",
                            "network": {
                                "primary-network": {
                                    "number": "192.168.10.0",
                                    "mask": "255.255.255.0"
                                }
                            }
                        }
                    ]
                }
            }
        }
    }
   

    result = build_dhcp(data)
    pool_names = [p["pool_name"] for p in result["pools"]]
    assert len(result["pools"]) == 2
    assert pool_names == ["users", "voice"]


@pytest.mark.parametrize("int_type, int_num, helper_ip",
             [
                 ("gigabitethernet", "3", "192.168.30.1"),
                 ("fastethernet", "2", "200.10.10.1"),
                 ("ethernet", "1", "192.168.1.1")
             ]
             )
def test_build_dhcp_multiple_helpers(int_type, int_num, helper_ip):
    data = {
        "native_netconf": {
            "interface": {
                f"{int_type}": [
                    {
                        "name": f"{int_num}",
                        "ip": {
                            "address": {
                                "primary": {
                                    "address": "192.168.30.1",
                                    "mask": "255.255.255.0"
                                }
                            },
                            "helper-address": [
                                {
                                    "address": helper_ip
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }

    result = build_dhcp(data)

    assert {"helper_ip": helper_ip, "interface": f"{int_type}{int_num}"} in result["helper"]["interfaces"]


def test_build_dhcp_multiple_pool_defaults():
    data = {
        "native_netconf": {
            "ip": {
                "dhcp": {
                    "pool": [
                        {
                            "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-dhcp",
                            "id": "USERS",
                        }
                    ]
                }
            }
        }
    }

    result = build_dhcp(data)

    assert {
               "pool_name": "users",
               "lease_days": None,
               "lease_hours": None,
               "lease_minutes": None,
               "default_gateway": "",
               "dns_ip": [],
               "domain_name": "",
               "pool_ip": "",
               "pool_mask": ""
           } in result["pools"]
