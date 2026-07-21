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
