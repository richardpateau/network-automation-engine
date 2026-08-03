import pytest
from unittest.mock import MagicMock, patch
from src.compliance.routing.nat.compliance import compliance_nat
from src.core.enums import OperationalStatus


@pytest.fixture
def mock_sesh():
    sesh = MagicMock()
    sesh.transport = "NETCONF"
    sesh.device_ip = "192.168.1.1"
    return sesh


@pytest.fixture
def mock_log():
    return MagicMock()


@pytest.fixture
def mock_device_result():
    return {
        "actions_taken": [],
        "critical_issues": [],
        "initial_issues": [],
        "status": "SUCCESS",
    }


@pytest.fixture
def exp_nat():
    return {
        "pat": {"acl": 10, "interface": "gigabitethernet2", "overload": True},
        "dynamic": [
            {
                "pool_name": "corporate",
                "start_ip": "203.0.113.2",
                "end_ip": "203.0.113.10",
                "acl": 20,
                "mask": "255.255.255.0",
            },
            {
                "pool_name": "voice",
                "start_ip": "100.0.1.10",
                "end_ip": "100.0.1.20",
                "acl": 40,
                "mask": "255.255.255.0",
            },
        ],
        "static": [{"inside_local": "192.168.10.25", "inside_global": "203.0.113.25"}],
        "interfaces": {
            "inside": ["gigabitethernet2", "gigabitethernet1/0"],
            "outside": ["fastethernet1/0"],
        },
    }


@pytest.fixture
def mock_context(exp_nat):
    return {"nat": exp_nat}


@patch("src.compliance.routing.nat.compliance.build_nat")
@patch("src.compliance.routing.nat.compliance.check_nat")
def test_compliance_nat_already_compliant(
    mock_check_nat,
    mock_build_nat,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_nat.return_value = {}
    mock_check_nat.return_value = (True, [])

    result = compliance_nat(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert result["initial_issues"] == []
    assert any(
        "NAT Configuration Already Compliant" in r for r in result["actions_taken"]
    )


@patch("src.compliance.routing.nat.compliance.configure_nat")
@patch("src.compliance.routing.nat.compliance.build_nat")
@patch("src.compliance.routing.nat.compliance.check_nat")
def test_compliance_nat_non_compliant_config_successful(
    mock_configure_nat,
    mock_check_nat,
    mock_build_nat,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_nat.return_value = {}
    mock_check_nat.return_value = (False, ["(NAT STATIC) Missing Static Configuration"])
    mock_configure_nat.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "(NAT) Static Mapping Configuration Successful",
    }

    result = compliance_nat(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_configure_nat.assert_called_once()
    mock_log.warning.assert_called_once()
    assert any(
        "(NAT STATIC) Missing Static Configuration" in r
        for r in result["initial_issues"]
    )
    assert any(
        "(NAT) Static Mapping Configuration Successful" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.routing.nat.compliance.configure_nat")
@patch("src.compliance.routing.nat.compliance.build_nat")
@patch("src.compliance.routing.nat.compliance.check_nat")
def test_compliance_nat_config_failed(
    mock_configure_nat,
    mock_check_nat,
    mock_build_nat,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_nat.return_value = {}
    mock_check_nat.return_value = (False, ["(NAT STATIC) Missing Static Configuration"])
    mock_configure_nat.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "(NAT STATIC) Failed To Configure Static NAT",
    }

    result = compliance_nat(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any(
        "(NAT STATIC) Missing Static Configuration" in r
        for r in result["initial_issues"]
    )
    assert any(
        "(NAT STATIC) Failed To Configure Static NAT" in r
        for r in result["actions_taken"]
    )
    assert any("Failed To Remediate NAT" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.routing.nat.compliance.DRY_RUN", True)
@patch("src.compliance.routing.nat.compliance.configure_nat")
@patch("src.compliance.routing.nat.compliance.build_nat")
@patch("src.compliance.routing.nat.compliance.check_nat")
def test_compliance_nat_dry_run(
    mock_configure_nat,
    mock_build_nat,
    mock_check_nat,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_nat.return_value = {}
    mock_check_nat.return_value = (False, ["(NAT STATIC) Missing Static Configuration"])
    mock_configure_nat.return_value = {}

    result = compliance_nat(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_configure_nat.assert_not_called()
    mock_log.warning.assert_called_once()
    assert any(
        "(NAT STATIC) Missing Static Configuration" in r
        for r in result["initial_issues"]
    )
    assert any("[DRY_RUN] Would Configure NAT" in r for r in result["actions_taken"])


@patch("src.compliance.routing.nat.compliance.collect_netconf_state")
@patch("src.compliance.routing.nat.compliance.configure_nat")
@patch("src.compliance.routing.nat.compliance.build_nat")
@patch("src.compliance.routing.nat.compliance.check_nat")
def test_compliance_nat_post_validation_successful(
    mock_collect_netconf_state,
    mock_configure_nat,
    mock_build_nat,
    mock_check_nat,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_nat.return_value = {}
    mock_check_nat.side_effect = [
        (False, ["(NAT STATIC) Missing Static Configuration"]),
        (True, []),
    ]
    mock_configure_nat.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "(NAT STATIC) Static Mapping Configuration Successful",
    }
    mock_collect_netconf_state.return_value = {}

    result = compliance_nat(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_log.error.assert_not_called()
    mock_collect_netconf_state.assert_called_once()
    assert any(
        "(NAT STATIC) Missing Static Configuration" in r
        for r in result["initial_issues"]
    )
    assert any(
        "(NAT STATIC) Static Mapping Configuration Successful" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value
    assert any("NAT Post Validation Successful" in r for r in result["actions_taken"])


@patch("src.compliance.routing.nat.compliance.collect_netconf_state")
@patch("src.compliance.routing.nat.compliance.configure_nat")
@patch("src.compliance.routing.nat.compliance.build_nat")
@patch("src.compliance.routing.nat.compliance.check_nat")
def test_compliance_nat_post_validation_failed(
    mock_collect_netconf_state,
    mock_configure_nat,
    mock_build_nat,
    mock_check_nat,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_nat.return_value = {}
    mock_check_nat.side_effect = [
        (False, ["(NAT STATIC) Missing Static Configuration"]),
        (False, ["(NAT STATIC) Missing Static Configuration"]),
    ]
    mock_configure_nat.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "(NAT STATIC) Static Mapping Configuration Successful",
    }
    mock_collect_netconf_state.return_value = {}

    result = compliance_nat(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.error.assert_called_once()
    mock_log.warning.assert_called_once()
    mock_log.info.assert_not_called()
    mock_collect_netconf_state.assert_called_once()
    assert any(
        "(NAT STATIC) Missing Static Configuration" in r
        for r in result["initial_issues"]
    )
    assert any(
        "(NAT STATIC) Static Mapping Configuration Successful" in r
        for r in result["actions_taken"]
    )
    assert any(
        "(NAT STATIC) Missing Static Configuration" in r
        for r in result["critical_issues"]
    )
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_nat_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_nat(
        mock_sesh, "192.168.1.1", {"nat": {}}, {}, mock_device_result, mock_log
    )

    assert result["actions_taken"] == []
    assert result["initial_issues"] == []
