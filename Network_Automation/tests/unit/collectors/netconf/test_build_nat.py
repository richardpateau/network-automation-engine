from src.collectors.netconf.builders import build_nat


def test_build_nat_pat(pat_netconf):
    result = build_nat(pat_netconf)

    assert result["pat"]["acl"] == 1
    assert result["pat"]["interface"] == "gigabitethernet1"
    assert result["pat"]["overload"] is True


def test_build_nat_static(pat_netconf):
    result = build_nat(pat_netconf)

    static = {(s["inside_local"], s["inside_global"]) for s in result["static"]}

    assert ("192.168.10.10", "200.1.1.10") in static
    assert ("192.168.10.20", "200.1.1.20") in static


def test_build_nat_dynamic(dynamic_nat_netconf):
    result = build_nat(dynamic_nat_netconf)

    assert len(result["dynamic"]) == 2

    assert {
               "acl": 10,
               "pool_name": "backup_pool",
               "start_ip": "210.1.1.100",
               "end_ip": "210.1.1.110",
               "mask": "255.255.255.0"
           } in result["dynamic"]
    assert {
               "acl": 10,
               "pool_name": "internet_pool",
               "start_ip": "200.1.1.100",
               "end_ip": "200.1.1.110",
               "mask": "255.255.255.0"
           } in result["dynamic"]


def test_build_nat_interfaces(pat_netconf):
    result = build_nat(pat_netconf)

    assert result["interfaces"]["inside"] == ["gigabitethernet3"]
    assert result["interfaces"]["outside"] == ["gigabitethernet1", "gigabitethernet2"]


def test_build_nat_empty():
    assert build_nat({}) == {
            "pat": {}, 
            "static": [],
            "dynamic": [],
            "interfaces": {"inside": [], "outside": []}
        }
    assert build_nat(None) == {
            "pat": {}, 
            "static": [],
            "dynamic": [],
            "interfaces": {"inside": [], "outside": []}
        }
    assert build_nat({"not_netconf": {}}) == {
            "pat": {}, 
            "static": [],
            "dynamic": [],
            "interfaces": {"inside": [], "outside": []}
        }
    assert build_nat({"native_netconf": {}}) == {
            "pat": {}, 
            "static": [],
            "dynamic": [],
            "interfaces": {"inside": [], "outside": []}
        }


def test_build_nat_no_nat_interface():
    data = {
        "native_netconf": {
            "interface": {
                "GigabitEthernet": [
                    {
                        "name": "1",
                        "ip": {
                            "nat": {}
                        }
                    }
                ]
            }
        }
    }


    result = build_nat(data)
    assert result["interfaces"]["inside"] == []
    assert result["interfaces"]["outside"] == []


def test_build_nat_no_static(dynamic_nat_netconf):
    result = build_nat(dynamic_nat_netconf)
    static = [n for n in result if "inside_local" in n]
    assert static == []


def test_build_nat_no_pat(dynamic_nat_netconf):
    result = build_nat(dynamic_nat_netconf)
    pat = [p for p in result if "overload" in p]

    assert pat == []


def test_build_nat_no_dynamic(pat_netconf):
    result = build_nat(pat_netconf)
    dynamic = [d for d in result if "pool_name" in d]

    assert dynamic == []


def test_build_nat_dynamic_defaults():
    data = {
        "native_netconf": {
            "ip": {
                "nat": {
                    "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XE-nat",
                    "pool": [
                        {
                            "id": "BACKUP_POOL"
                        },
                        {
                            "id": "INTERNET_POOL"
                        }
                    ],
                    "inside": {
                        "source": {
                            "list": {
                            	"id": "",
                            "pool-with-vrf": {
                                "pool": {
                                    "name": "INTERNET_POOL"
                                }
                            }
                          }
                       } 
                    }
                }
            }
        }
    }

    result = build_nat(data)

    assert {
               "acl": None,
               "pool_name": "internet_pool",
               "start_ip": "",
               "end_ip": "",
               "mask": ""
           } in result["dynamic"]


def test_build_nat_static_default():
    data = {
        "native_netconf": {
            "ip": {
                "nat": {
                    "inside": {
                        "source": {
                            "static": {
                                "nat-static-transport-list": [
                                    {
                                        "not_ip": None
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }
    }


    result = build_nat(data)
    static = {(s["inside_local"], s["inside_global"]) for s in result["static"]}

    assert static == {("", "")}
