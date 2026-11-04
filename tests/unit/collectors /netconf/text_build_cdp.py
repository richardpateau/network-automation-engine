from src.collectors.netconf.builders import build_cdp_netconf
import pytest


def test_build_cdp_valid(cdp_netconf):
    result = build_cdp_netconf(cdp_netconf)

    assert result["enabled"] is True
    assert result["timer"] == 60
    assert result["holdtime"] == 180
    assert result["interfaces"]["gigabitethernet1"]["enabled"] is True
    assert result["interfaces"]["gigabitethernet2"]["enabled"] is False
    assert result["interfaces"]["gigabitethernet3"]["enabled"] is True
    assert result["interfaces"]["gigabitethernet4"]["enabled"] is False


@pytest.mark.parametrize(
    "data",
    [
        {},
        None,
        {"not_netconf": {}},
        {"netconf_state": {}},
    ],
)
def test_build_cdp_empty(data):
    assert build_cdp_netconf(data) == {
        "enabled": False,
        "timer": None,
        "holdtime": None,
        "interfaces": {},
    }


@pytest.mark.parametrize(
    "timer, holdtime", [(60, 180), (30, 100), (100, 300), (45, 150), (90, 300)]
)
def test_build_cdp_timer_holdtime(timer, holdtime):
    data = {
        "native_netconf": {
            "cdp": {"holdtime": {"#text": holdtime}, "timer": {"#text": timer}}
        }
    }

    result = build_cdp_netconf(data)

    assert result["timer"] == timer
    assert result["holdtime"] == holdtime


@pytest.mark.parametrize(
    "int_type, int_num",
    [
        ("gigabitethernet", "1"),
        ("gigabitethernet", "2"),
        ("fastethernet", "1/0"),
        ("fastethernet", "2/0"),
    ],
)
def test_build_cdp_interfaces(int_type, int_num):
    data = {
        "native_netconf": {
            "interface": {int_type: [{"name": int_num, "cdp": {"enable": "true"}}]}
        }
    }

    result = build_cdp_netconf(data)
    assert result["interfaces"][f"{int_type}{int_num}".lower()]["enabled"] is True


def test_build_cdp_interfaces_disabled(int_type, int_num):
    data = {
        "native_netconf": {
            "interface": {int_type: [{"name": int_num, "cdp": {"enable": "false"}}]}
        }
    }

    result = build_cdp_netconf(data)
    assert result["interfaces"][f"{int_type}{int_num}".lower()]["enabled"] is False


def test_build_cdp_not_enabled():
    data = {"native_netconf": {"cdp": {"run-enable": {}}}}

    result = build_cdp_netconf(data)

    assert result["enabled"] is False


def test_build_cdp_no_timer_holdtime():
    data = {"native_netconf": {"cdp": {"holdtime": {}, "timer": {}}}}

    result = build_cdp_netconf(data)

    assert resul["timer"] is None
    assert result["holdtime"] is None


def test_build_cdp_no_interfaces():
    data = {"native_netconf": {"interface": {}}}

    result = build_cdp_netconf(data)

    assert result["interfaces"] == {}
