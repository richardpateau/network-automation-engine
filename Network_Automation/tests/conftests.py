import json
import pytest
from pathlib import Path


@pytest.fixture
def vlan_genie_output():
    fixture_path = Path(__file__).parent / "fixtures" / "cli" / "vlan_genie_output.json"

    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def access_trunk_genie_output():
    fixture_path = Path(__file__).parent / "fixtures" / "cli" / "trunk_access.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def interface_genie_output():
    fixture_path = (
        Path(___file__).parent / "fixtures" / "cli" / "interface_genie_output.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def stp_global_genie_output():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "stp_global_genie_output.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def stp_interface_output():
    fixture_path = Path(__file__).parent / "fixtures" / "cli" / "running_config_stp.txt"
    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytest.fixture
def snmp_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_snmp.txt"
    )
    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytest.fixture
def syslog_genie_output():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "syslog_genie_output.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def cdp_running_config():
    interface_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_cdp.txt"
    )
    global_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_cdp_global.txt"
    )
    return {"cdp": global_path.read.text(), "cdp_interface": interface_path.read.text()}


@pytest.fixture
def port_security_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_port_security.txt"
    )

    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytest.fixture
def snooping_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_snoopoing.txt"
    )

    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytest.fixture
def dai_running_config():
    dai_global = Path(__file__).parent / "fixtures" / "cli" / "running_config_dai.txt"
    dai_interface = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_dai_interface.txt"
    )

    return {
        "running_config": dai_global.read.text(),
        "dai_interface": dai_interface.read.text(),
    }


@pytest.fixture
def etherchannel_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_etherchannel.txt"
    )
    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytest.fixture
def ntp_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "ntp_netconf.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def qos_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "qos_netconf.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def hsrp_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "hsrp_netconf.json"
    with open(fixture_path) as f:
        json.load(f)


@pytest.fixture
def hsrp_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "pat_netconf.json"
    with open(fixture_path) as f:
        json.load(f)


@pytest.fixture
def hsrp_netconf():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "netconf" / "dynamic_nat_netconf.json"
    )
    with open(fixture_path) as f:
        json.load(f)


@pytest.fixture
def dhcp_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "dhcp_netconf.json"
    with open(fixture_path) as f:
        json.load(f)


@pytest.fixture
def snmp_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "snmp_netconf.json"
    with open(fixture_path) as f:
        json.load(f)


@pytest.fixture
def syslog_netconf():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "netconf" / "syslog_netconf.json"
    )
    with open(fixture_path) as f:
        json.load(f)


@pytest.fixture
def cdp_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "cdp_netconf.json"
    with open(fixture_path) as f:
        json.load(f)


@pyetest.fixture
def static_netconf():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "netconf" / "static_netconf.json"
    )
