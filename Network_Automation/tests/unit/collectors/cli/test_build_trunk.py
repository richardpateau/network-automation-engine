from src.collectors.cli.builders import build_trunk

def test_build_trunk_valid(access_trunk_genie_output):
    result = build_trunk(access_trunk_genie_output)

    assert len(result) == 2
    assert "gigabitethernet0/3" in result
    assert "gigabitethernet1/0" in result
    assert result["gigabitethernet0/3"]["allowed_vlans"] == "10,20,30,40,50"
    assert result["gigabitethernet1/0"]["allowed_vlans"] == "10,20,30,40"

    assert "gigabitethernet0/0" not in result
    assert "gigabitethernet0/1" not in result


def test_build_trunk_lowercase():
    data = {"switchports": {
        "Gigabitethernet0/0": {
            "operational_mode": "trunk"
        },
        "Gigabitethernet0/1": {
            "operational_mode": "trunk"
        }
    }
    }

    result = build_trunk(data)

    assert "GigabitEthernet0/0" not in result
    assert "GigabitEthernet0/1" not in result

    assert "gigabitethernet0/0" in result
    assert "gigabitethernet0/1" in result


def test_build_no_trunks():
    data = {
        "switchports": {
            "gigabitethernet0/0": {
                "operational_mode": "static access",
            },
            "gigabitethernet0/1": {

                "operational_mode": "static access",

            }
        }
    }

    result = build_trunk(data)

    assert result == {}


def test_build_trunk_missing_vlans():
    data = {
        "switchports": {
            "Gigabitethernet0/0": {
                "operational_mode": "trunk",
            },
        }
    }
    result = build_trunk(data)
    assert result["gigabitethernet0/0"]["allowed_vlans"] == ""


def test_build_trunk_missing_operational_mode():
    data = {
        "switchports": {
            "Gigabitethernet0/0": {
            },
        }
    }
    result = build_trunk(data)

    assert result == {}


def test_build_trunk_empty_input():
    assert build_trunk({}) == {}
    assert build_trunk({"not_switchport": {}}) == {}
    assert build_trunk(None) == {}
    assert build_trunk({"switchports": None}) == {}
