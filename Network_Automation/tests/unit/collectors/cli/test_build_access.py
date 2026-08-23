from src.collectors.cli.builders import build_access

def test_build_access_valid_path(access_trunk_genie_output):
    result = build_access(access_trunk_genie_output)

    assert "gigabitethernet0/0" in result
    assert result["gigabitethernet0/0"]["access_vlan"] == 98
    assert result["gigabitethernet0/0"]["operational_mode"] == "static access"
    assert "gigabitethernet0/1" in result
    assert result["gigabitethernet0/1"]["operational_mode"] == "static access"
    assert result["gigabitethernet0/1"]["access_vlan"] == 20


def test_build_access_ingore_trunk():
    data = {"gigabitethernet0/3": {
        "operational_mode": "trunk",
        "access_vlan": 10
    }
    }

    result = build_access(data)

    assert result == {}


def test_build_access_mixed():
    data = {
        "switchports": {
            "gigabitethernet0/3": {
                "operational_mode": "trunk",
                "access_vlan": "1"
            },
            "gigabitethernet1/0": {
                "operational_mode": "static access",
                "access_vlan": "10",

            }
        }
    }

    result = build_access(data)

    assert len(result) == 1
    assert "gigabitethernet1/0" in result
    assert "gigabitethernet0/3" not in result


def test_build_access_no_vlan():
    data = data = {
    "switchports": {
        "gigabitethernet0/3": {
            "operational_mode": "trunk",
        },
        "gigabitethernet1/0": {
            "operational_mode": "static access",
        }
    }
}
    result = build_access(data)
    assert result["gigabitethernet1/0"]["access_vlan"] == None


def test_build_access_empty():
    result = build_access({})

    assert result == {}


def test_build_access_no_dict():
    result = build_access({"not_switchport": {}})

    assert result == {}
