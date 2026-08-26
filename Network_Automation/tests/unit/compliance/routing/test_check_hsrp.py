import pytest
from src.compliance.routing.hsrp.check import check_hsrp


@pytest.fixture
def expected_hsrp():
    return [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.10.1",
            "priority": 110,
            "preempt": True,
            "version": 2
        }
    ]


@pytest.fixture
def actual_hsrp():
    return [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.10.1",
            "priority": 110,
            "preempt": True,
            "version": 2
        }
    ]


def test_check_hsrp_compliant(expected_hsrp, actual_hsrp):
    ok, failures = check_hsrp(expected_hsrp, actual_hsrp)

    assert ok is True
    assert failures == []


def test_check_hsrp_missing(expected_hsrp):
    ok, failures = check_hsrp(expected_hsrp, [])

    assert ok is False
    assert any("(HSRP) Missing Configuration" in r for r in failures)
    assert any("gigabitethernet1" in r for r in failures)


def test_check_hsrp_extra(expected_hsrp):
    actual = [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.10.1",
            "priority": 110,
            "preempt": True,
            "version": 2
        },
        {
            "interface": "gigabitethernet2",
            "router_vlan": 20,
            "group": 20,
            "vip": "192.168.20.1",
            "priority": 100,
            "preempt": False,
            "version": 2
        }
    ]


    ok, failures = check_hsrp(expected_hsrp, actual)

    assert ok is False
    assert any("(HSRP) Unexpected Configuration" in r for r in failures)
    assert any("gigabitethernet2" in r for r in failures)


def test_check_hsrp_wrong_priority(expected_hsrp):
    actual = [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.10.1",
            "priority": 90,
            "preempt": True,
            "version": 2
        }
    ]

    ok, failures = check_hsrp(expected_hsrp, actual)

    assert ok is False
    assert any("(HSRP) Mismatched Priority" in r for r in failures)
    assert any("Expected: 110 | Actual: 90" in r for r in failures)


def test_check_hsrp_wrong_vip(expected_hsrp):
    actual = [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.20.1",
            "priority": 110,
            "preempt": True,
            "version": 2
        }
    ]

    ok, failures = check_hsrp(expected_hsrp, actual)

    assert ok is False
    assert any("(HSRP) Mismatched Virtual IP" in r for r in failures)
    assert any("Expected: 192.168.10.1 | Actual: 192.168.20.1" in r for r in failures)


def test_check_hsrp_wrong_preempt(expected_hsrp):
    actual = [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.10.1",
            "priority": 110,
            "preempt": False,
            "version": 2
        }
    ]

    ok, failures = check_hsrp(expected_hsrp, actual)

    assert ok is False
    assert any("(HSRP) Mismatched Preempt" in r for r in failures)
    assert any("Expected: True | Actual: False" in r for r in failures)


def test_check_hsrp_wrong_version(expected_hsrp):
    actual = [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.10.1",
            "priority": 110,
            "preempt": True,
            "version": 1
        }
    ]

    ok, failures = check_hsrp(expected_hsrp, actual)

    assert ok is False
    assert any("(HSRP) Mismatched Version" in r for r in failures)
    assert any("Expected: 2 | Actual: 1" in r for r in failures)


def test_check_hsrp_multiple_failures(expected_hsrp):
    actual = [
        {
            "interface": "gigabitethernet1",
            "router_vlan": 10,
            "group": 10,
            "vip": "192.168.20.1",
            "priority": 210,
            "preempt": False,
            "version": 1
        }
    ]
    ok, failures = check_hsrp(expected_hsrp, actual)

    assert ok is False
    assert len(failures) == 4
    assert any("(HSRP) Mismatched Virtual IP" in r for r in failures)
    assert any("(HSRP) Mismatched Priority" in r for r in failures)
    assert any("(HSRP) Mismatched Preempt" in r for r in failures)
    assert any("(HSRP) Mismatched Version" in r for r in failures)
