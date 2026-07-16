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
