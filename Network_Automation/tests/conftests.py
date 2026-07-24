import json
import pytests
from pathlib import Path


@pytests.fixture
def vlan_genie_output():
    fixture_path = Path(__file__).parent / "fixtures" / "cli" / "vlan_genie_output.json"

    with open(fixture_path) as f:
        return json.load(f)


@pytests.fixture
def access_trunk_genie_output():
    fixture_path = Path(__file__).parent / "fixtures" / "cli" / "trunk_access.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytests.fixture
def interface_genie_output():
    fixture_path = (
        Path(___file__).parent / "fixtures" / "cli" / "interface_genie_output.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytests.fixture
def stp_global_genie_output():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "stp_global_genie_output.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytests.fixture
def stp_interface_output():
    fixture_path = Path(__file__).parent / "fixtures" / "cli" / "running_config_stp.txt"
    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytests.fixture
def snmp_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_snmp.txt"
    )
    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytests.fixture
def syslog_genie_output():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "syslog_genie_output.json"
    )
    with open(fixture_path) as f:
        return json.load(f)


@pytests.fixture
def cdp_running_config():
    interface_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_cdp.txt"
    )
    global_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_cdp_global.txt"
    )
    return {"cdp": global_path.read.text(), "cdp_interface": interface_path.read.text()}


@pytests.fixture
def port_security_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_port_security.txt"
    )

    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytests.fixture
def snooping_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_snoopoing.txt"
    )

    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytests.fixture
def dai_running_config():
    dai_global = Path(__file__).parent / "fixtures" / "cli" / "running_config_dai.txt"
    dai_interface = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_dai_interface.txt"
    )

    return {
        "running_config": dai_global.read.text(),
        "dai_interface": dai_interface.read.text(),
    }


@pytests.fixture
def etherchannel_running_config():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "cli" / "running_config_etherchannel.txt"
    )
    with open(fixture_path) as f:
        return {"running_config": f.read}


@pytests.fixture
def ntp_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "ntp_netconf.json"
    with open(fixture_path) as f:
        return json.load(f)


def qos_netconf():
    fixture_path = Path(__file__).parent / "fixtures" / "netconf" / "qos_netconf.json"
    with open(fixture_path) as f:
        return json.load(f)
