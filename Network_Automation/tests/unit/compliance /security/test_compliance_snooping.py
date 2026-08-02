import pytest
from unittest.mock import MagicMock, patch
from src.compliance.security.dhcp_snooping import compliance_snooping
from src.core.enums import OperationalStatus


@pytest.fixture
def mock_sesh():
    sesh = MagicMock()
    sesh.transport = "NETMIKO"
    sesh.device_ip = "192.168.1.1"
    return sesh


@pytest.fixture
def mock_log():
    return MagicMock()


@pytest.fixture
def mock_device_result():
    return {
        "initial_issues": [],
        "actions_taken": [],
        "critical_issues": [],
        "status": "SUCCESS",
    }


@pytest.fixture
def exp_snooping():
    return {
        "enabled_vlans": [10, 20, 30, 40, 50],
        "interfaces": {
            "gigabitethernet1": {"rate_limit": 20, "trusted": False},
            "gigabitethernet2": {"rate_limit": 50, "trusted": True},
        },
        "option82": True,
    }


@pytest.fixture
def mock_context(exp_snooping):
    return {"dhcp_snooping": exp_snooping}


@patch("src.compliance.security.dhcp_snooping.compliance.build_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.check_snooping")
def test_compliance_snooping_already_compliant(
    mock_check_snooping,
    mock_build_snooping,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_snooping.return_value = {}
    mock_check_snooping.return_value = (True, [])

    result = compliance_snooping(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert result["initial_issues"] == []
    assert any(
        "DHCP Snooping Configuration Already Compliant" in r
        for r in result["actions_taken"]
    )


@patch("src.compliance.security.dhcp_snooping.compliance.configure_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.build_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.check_snooping")
def test_compliance_snooping_non_compliant_and_configuration_successful(
    mock_configure_snooping,
    mock_check_snooping,
    mock_build_snooping,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_snooping.return_value = {}
    mock_check_snooping.return_value = (
        False,
        ["(DHCP Snooping) Missing VLAN(s) On Device"],
    )
    mock_configure_snooping.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DHCP Snooping Successfully Configured",
    }

    result = compliance_snooping(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_snooping.assert_called_once()
    assert any(
        "(DHCP Snooping) Missing VLAN(s) On Device" in r
        for r in result["initial_issues"]
    )
    assert any(
        "DHCP Snooping Successfully Configured" in r for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.security.dhcp_snooping.compliance.configure_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.build_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.check_snooping")
def test_compliance_snooping_non_compliant_and_configuration_failed(
    mock_configure_snooping,
    mock_check_snooping,
    mock_build_snooping,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_snooping.return_value = {}
    mock_check_snooping.return_value = (
        False,
        ["(DHCP Snooping) Missing VLAN(s) On Device"],
    )
    mock_configure_snooping.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed to Configure DHCP Snooping",
    }

    result = compliance_snooping(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_snooping.assert_called_once()
    assert any(
        "(DHCP Snooping) Missing VLAN(s) On Device" in r
        for r in result["initial_issues"]
    )
    assert any(
        "DHCP Snooping Configuration Remediation Failed" in r
        for r in result["critical_issues"]
    )
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.security.dhcp_snooping.compliance.DRY_RUN", True)
@patch("src.compliance.security.dhcp_snooping.compliance.configure_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.build_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.check_snooping")
def test_compliance_snooping_dry_run(
    mock_configure_snooping,
    mock_check_snooping,
    mock_build_snooping,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_snooping.return_value = {}
    mock_check_snooping.return_value = (
        False,
        ["(DHCP Snooping) Missing VLAN(s) On Device"],
    )
    mock_configure_snooping.return_value = {}

    result = compliance_snooping(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_snooping.assert_not_called()
    assert any(
        "(DHCP Snooping) Missing VLAN(s) On Device" in r
        for r in result["initial_issues"]
    )
    assert any(
        "[DRY_RUN] Would Configure DHCP Snooping" in r for r in result["actions_taken"]
    )


@patch("src.compliance.security.dhcp_snooping.compliance.collect_device_state")
@patch("src.compliance.security.dhcp_snooping.compliance.configure_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.build_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.check_snooping")
def test_compliance_snooping_post_validation_success(
    mock_collect_device_state,
    mock_configure_snooping,
    mock_check_snooping,
    mock_build_snooping,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_snooping.return_value = {}
    mock_check_snooping.side_effect = [
        (False, ["(DHCP Snooping) Missing VLAN(s) On Device"]),
        (True, []),
    ]
    mock_configure_snooping.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DHCP Snooping Successfully Configured",
    }
    mock_collect_device_state.return_value = {}

    result = compliance_snooping(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_snooping.assert_called_once()
    mock_collect_device_state.assert_called_once()
    assert any(
        "(DHCP Snooping) Missing VLAN(s) On Device" in r
        for r in result["initial_issues"]
    )
    assert any(
        "DHCP Snooping Successfully Configured" in r for r in result["actions_taken"]
    )
    assert any(
        "DHCP Snooping Configuration Post Validation Successful" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.security.dhcp_snooping.compliance.collect_device_state")
@patch("src.compliance.security.dhcp_snooping.compliance.configure_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.build_snooping")
@patch("src.compliance.security.dhcp_snooping.compliance.check_snooping")
def test_compliance_snooping_post_validation_failed(
    mock_collect_device_state,
    mock_configure_snooping,
    mock_check_snooping,
    mock_build_snooping,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_snooping.return_value = {}
    mock_check_snooping.side_effect = [
        (False, ["(DHCP Snooping) Missing VLAN(s) On Device"]),
        (False, ["(DHCP Snooping) Missing VLAN(s) On Device"]),
    ]
    mock_configure_snooping.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DHCP Snooping Successfully Configured",
    }
    mock_collect_device_state.return_value = {}

    result = compliance_snooping(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_snooping.assert_called_once()
    mock_collect_device_state.assert_called_once()
    assert any(
        "(DHCP Snooping) Missing VLAN(s) On Device" in r
        for r in result["initial_issues"]
    )
    assert any(
        "DHCP Snooping Successfully Configured" in r for r in result["actions_taken"]
    )
    assert any(
        "(DHCP Snooping) Missing VLAN(s) On Device" in r
        for r in result["critical_issues"]
    )
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_snooping_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_snooping(
        mock_sesh,
        mock_sesh.device_ip,
        {"dhcp_snooping": {}},
        {},
        mock_device_result,
        mock_log,
    )

    assert result["actions_taken"] == []
    assert result["initial_issues"] == []
