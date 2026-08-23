from src.collectors.cli.builders import build_syslog_netmiko


def test_build_syslog_valid(syslog_genie_output):
    result = build_syslog_netmiko(syslog_genie_output)
    assert result["hosts"] == (["192.168.100.60", "192.168.100.61"])
    assert result["trap_level"] == "informational"
    assert result["source_interface"] == "loopback0"
    assert result["timestamps"] is True


def test_build_syslog_no_timestamps():
    data = {
        "running_config":"""
service timestamps debug datetime msec
service timestamps datetime msec
no service password-encryption
"""
    }
    result = build_syslog_netmiko(data)

    assert result["timestamps"] is False


def test_build_syslog_empty():
    assert build_syslog_netmiko({}) == {
        "hosts": [],
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }
    assert build_syslog_netmiko(None) == {
        "hosts": [],
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }
    assert build_syslog_netmiko({"not_syslog": {}}) == {
        "hosts": [],
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }
    assert build_syslog_netmiko({"syslog": {}}) == {
        "hosts": [],
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }


def test_build_syslog_no_logging():
    data = {"syslog": {"logging": None}}

    assert build_syslog_netmiko(data) == {
        "hosts": [],
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }


def test_build_syslog_defaults():
    data = {
        "syslog": {
            "logging": {
                "trap": {
                    "message_lines_logged": 58,
                    "logging_to": {
                        "192.168.100.60": {
                            "protocol": "udp",
                            "port": 514,
                            "audit": "disabled",
                            "link": "up",
                            "message_lines_logged": 14,
                            "message_lines_rate_limited": 0,
                            "message_lines_dropped_by_md": 0,
                            "xml": "disabled",
                            "sequence_number": "disabled",
                            "filtering": "disabled",
                        }
                    },
                }
            }
        }
    }

    result = build_syslog_netmiko(data)

    assert result["hosts"] == ["192.168.100.60"]
    assert result["trap_level"] == ""
    assert result["source_interface"] == ""
    assert result["timestamps"] is False


def test_build_syslog_source_interface():
    data = {

        "syslog": {
            "logging": {
                "trap": {
                    "logging_source_interface": {
                        "Loopback0": {},
                    }
                }
            }
        }
    }


    result = build_syslog_netmiko(data)

    assert result["source_interface"] == "loopback0"
