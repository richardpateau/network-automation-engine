from src.collectors.netconf.builders import build_ntp


def test_build_ntp_valid(ntp_netconf):
    result = build_ntp(ntp_netconf)

    assert len(result["servers"]) == 2
    assert {"server_ip": "192.168.100.10", "server_id": 1} in result["servers"]
    assert {"server_ip": "192.168.100.11", "server_id": 1} in result["servers"]
    assert {"id": 1, "trusted": True} in result["keys"]
    assert len(result["keys"]) == 1


def test_build_ntp_empty():
    assert build_ntp({}) == {"keys": [], "servers": []}
    assert build_ntp(None) == {"keys": [], "servers": []}
    assert build_ntp({"not_native": {}}) == {"keys": [], "servers": []}
    assert build_ntp({"native_netconf": {}}) == {"keys": [], "servers": []}


def test_build_ntp_not_trusted():
    data = {
        "native_netconf": {
            "ntp": {
                "authentication-key": {
                    "number": "1",
                },
                "trusted-key": {"number": "2"},
            }
        }
    }

    result = build_ntp(data)

    assert result["keys"][0]["id"] == 1
    assert result["keys"][0]["trusted"] is False


def test_build_ntp_no_servers():
    data = {
        "native_netconf": {
            "ntp": {
                "server": {},
            }
        }
    }

    result = build_ntp(data)

    assert result["servers"] == []


def test_build_ntp_no_keys():
    data = {"native_netconf": {"ntp": {"authentication-key": {}, "trusted-key": {}}}}

    result = build_ntp(data)

    assert result["keys"] == []


def test_build_ntp_no_server_id():
    data = {
        "native_netconf": {
            "ntp": {
                "server": {
                    "server-list": [
                        {"ip-address": "192.168.100.10"},
                    ],
                }
            }
        }
    }
    result = build_ntp(data)

    assert result["servers"][0]["server_ip"] == "192.168.100.10"
    assert result["servers"][0]["server_id"] is None


def test_build_ntp_no_server_ip():
    data = {
        "native_netconf": {
            "ntp": {
                "server": {
                    "server-list": [
                        {"key": "1"},
                    ],
                }
            }
        }
    }
    result = build_ntp(data)

    assert result["servers"][0]["server_ip"] == ""
    assert result["servers"][0]["server_id"] == 1
