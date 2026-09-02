import pytest
from unittest.mock import MagicMock, patch
from src.compliance.services.dhcp.compliance import compliance_dhcp
from src.core.enums import OperationalStatus


@pytest.fixture
def mock_sesh():
    sesh = MagicMock()
    sesh.device_ip = "192.168.1.1"
    sesh.transport = "NETCONF"
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
def exp_dhcp():
    return {
        "excluded_addresses": [{"start_ip": "192.168.1.10", "end_ip": "192.168.1.20"}],
        "pool": [
            {
                "pool_name": "voice",
                "lease_days": "2",
                "lease_hours": "20",
                "lease_minutes": "10",
                "default_router": "192.168.1.1",
                "dns_ip": "200.0.113.1",
                "pool_ip": "203.0.113.0",
                "pool_mask": "255.255.255.0",
            }
        ],
        "helper": {
            "interfaces": [
                {"helper_ip": "192.168.1.1", "interface_name": "gigabitethernet1"}
            ]
        },
    }


@pytest.fixture
def mock_context(exp_dhcp):
    return {"dhcp": exp_dhcp}


@patch("src.compliance.services.dhcp.compliance.build_dhcp")
@patch("src.compliance.services.dhcp.compliance.check_dhcp")
def test_compliance_dhcp_already_compliant(
    mock_check_dhcp,
    mock_build_dhcp,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dhcp.return_value = {}
    mock_check_dhcp.return_value = (True, [])

    result = compliance_dhcp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any(
        "DHCP Configuration Already Compliant" in r for r in result["actions_taken"]
    )
    assert result["initial_issues"] == []

@patch("src.compliance.services.dhcp.compliance.collect_netconf_state")
@patch("src.compliance.services.dhcp.compliance.configure_dhcp")
@patch("src.compliance.services.dhcp.compliance.build_dhcp")
@patch("src.compliance.services.dhcp.compliance.check_dhcp")
def test_compliance_dhcp_non_compliant_config_successful(
    mock_check_dhcp,
    mock_build_dhcp,
    mock_configure_dhcp,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dhcp.return_value = {}
    mock_check_dhcp.side_effect = [(False, ["(DHCP) Mismatched Lease Duration"]), (True, [])]
    mock_configure_dhcp.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DHCP Successfully Configured",
    }
    mock_collect_netconf_state.return_value = {}
    result = compliance_dhcp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any(
        "(DHCP) Mismatched Lease Duration" in r for r in result["initial_issues"]
    )
    assert any("DHCP Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.services.dhcp.compliance.configure_dhcp")
@patch("src.compliance.services.dhcp.compliance.build_dhcp")
@patch("src.compliance.services.dhcp.compliance.check_dhcp")
def test_compliance_dhcp_non_compliant_config_failed(
    mock_check_dhcp,
    mock_build_dhcp,
    mock_configure_dhcp,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dhcp.return_value = {}
    mock_check_dhcp.return_value = (False, ["(DHCP) Mismatched Lease Duration"])
    mock_configure_dhcp.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure DHCP",
    }

    result = compliance_dhcp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any(
        "(DHCP) Mismatched Lease Duration" in r for r in result["initial_issues"]
    )
    assert any("Failed To Configure DHCP" in r for r in result["actions_taken"])
    assert any("Failed To Remediate DHCP" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.services.dhcp.compliance.DRY_RUN", True)
@patch("src.compliance.services.dhcp.compliance.configure_dhcp")
@patch("src.compliance.services.dhcp.compliance.build_dhcp")
@patch("src.compliance.services.dhcp.compliance.check_dhcp")
def test_compliance_dhcp_dry_run(
    mock_check_dhcp,
    mock_build_dhcp,
    mock_configure_dhcp,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dhcp.return_value = {}
    mock_check_dhcp.return_value = (False, ["(DHCP) Mismatched Lease Duration"])
    mock_configure_dhcp.return_value = {}

    result = compliance_dhcp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_dhcp.assert_not_called()
    assert any(
        "(DHCP) Mismatched Lease Duration" in r for r in result["initial_issues"]
    )
    assert any("[DRY_RUN] Would Configure DHCP" in r for r in result["actions_taken"])


@patch("src.compliance.services.dhcp.compliance.collect_netconf_state")
@patch("src.compliance.services.dhcp.compliance.configure_dhcp")
@patch("src.compliance.services.dhcp.compliance.build_dhcp")
@patch("src.compliance.services.dhcp.compliance.check_dhcp")
def test_compliance_dhcp_post_validation_successful(
    mock_check_dhcp,
    mock_build_dhcp,
    mock_configure_dhcp,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dhcp.return_value = {}
    mock_check_dhcp.side_effect = [
        (False, ["(DHCP) Mismatched Lease Duration"]),
        (True, []),
    ]
    mock_configure_dhcp.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DHCP Successfully Configured",
    }

    result = compliance_dhcp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_netconf_state.assert_called_once()
    mock_log.error.assert_not_called()
    assert any(
        "(DHCP) Mismatched Lease Duration" in r for r in result["initial_issues"]
    )
    assert any("DHCP Successfully Configured" in r for r in result["actions_taken"])
    assert any(
        "DHCP Configuration Post Validation Successful" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.services.dhcp.compliance.collect_netconf_state")
@patch("src.compliance.services.dhcp.compliance.configure_dhcp")
@patch("src.compliance.services.dhcp.compliance.build_dhcp")
@patch("src.compliance.services.dhcp.compliance.check_dhcp")
def test_compliance_dhcp_post_validation_failed(
    mock_check_dhcp,
    mock_build_dhcp,
    mock_configure_dhcp,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dhcp.return_value = {}
    mock_check_dhcp.side_effect = [
        (False, ["(DHCP) Mismatched Lease Duration"]),
        (False, ["(DHCP) Mismatched Lease Duration"]),
    ]
    mock_configure_dhcp.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DHCP Successfully Configured",
    }

    result = compliance_dhcp(mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log)

    mock_log.warning.assert_called_once()
    mock_collect_netconf_state.assert_called_once()
    mock_log.error.assert_called_once()
    assert any(
        "(DHCP) Mismatched Lease Duration" in r for r in result["initial_issues"]
    )
    assert any("DHCP Successfully Configured" in r for r in result["actions_taken"])
    assert any(
        "(DHCP) Mismatched Lease Duration" in r for r in result["critical_issues"]
    )
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_dhcp_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_dhcp(
        mock_sesh, mock_sesh.device_ip, {"dhcp": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []
