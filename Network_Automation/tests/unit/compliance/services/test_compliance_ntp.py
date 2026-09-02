import pytest
from unittest.mock import MagicMock, patch
from src.compliance.services.ntp.compliance import compliance_ntp
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
def exp_ntp():
    return {
        "keys": [{"id": 1, "trusted": True}],
        "servers": [{"server_ip": "192.168.20.1", "server_id": 1}],
    }


@pytest.fixture
def mock_context(exp_ntp):
    return {"ntp": exp_ntp}


@patch("src.compliance.services.ntp.compliance.build_ntp")
@patch("src.compliance.services.ntp.compliance.check_ntp")
def test_compliance_ntp_already_compliant(
    mock_check_ntp,
    mock_build_ntp,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_ntp.return_value = {}
    mock_check_ntp.return_value = (True, [])

    result = compliance_ntp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any("NTP Already Compliant" in r for r in result["actions_taken"])

@patch("src.compliance.services.ntp.compliance.collect_netconf_state")
@patch("src.compliance.services.ntp.compliance.configure_ntp")
@patch("src.compliance.services.ntp.compliance.build_ntp")
@patch("src.compliance.services.ntp.compliance.check_ntp")
def test_compliance_ntp_non_compliant_config_successful(
    mock_check_ntp,
    mock_build_ntp,
    mock_configure_ntp,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_ntp.return_value = {}
    mock_check_ntp.side_effect = [(False, ["(NTP) Mismatched Server Key ID"]), (True, [])]
    mock_configure_ntp.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "NTP Configuration Successful",
    }
    mock_collect_netconf_state.return_value = {}
    result = compliance_ntp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(NTP) Mismatched Server Key ID" in r for r in result["initial_issues"])
    assert any("NTP Configuration Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.services.ntp.compliance.configure_ntp")
@patch("src.compliance.services.ntp.compliance.build_ntp")
@patch("src.compliance.services.ntp.compliance.check_ntp")
def test_compliance_ntp_non_compliant_config_failed(
    mock_check_ntp,
    mock_build_ntp,
    mock_configure_ntp,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_ntp.return_value = {}
    mock_check_ntp.return_value = (False, ["(NTP) Mismatched Server Key ID"])
    mock_configure_ntp.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure NTP",
    }

    result = compliance_ntp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(NTP) Mismatched Server Key ID" in r for r in result["initial_issues"])
    assert any("Failed To Configure NTP" in r for r in result["actions_taken"])
    assert any("Failed To Remediate NTP" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.services.ntp.compliance.DRY_RUN", True)
@patch("src.compliance.services.ntp.compliance.configure_ntp")
@patch("src.compliance.services.ntp.compliance.build_ntp")
@patch("src.compliance.services.ntp.compliance.check_ntp")
def test_compliance_ntp_dry_run(
    mock_check_ntp,
    mock_build_ntp,
    mock_configure_ntp,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_ntp.return_value = {}
    mock_check_ntp.return_value = (False, ["(NTP) Mismatched Server Key ID"])
    mock_configure_ntp.return_value = {}

    result = compliance_ntp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_ntp.assert_not_called()
    assert any("(NTP) Mismatched Server Key ID" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure NTP" in r for r in result["actions_taken"])


@patch("src.compliance.services.ntp.compliance.collect_netconf_state")
@patch("src.compliance.services.ntp.compliance.configure_ntp")
@patch("src.compliance.services.ntp.compliance.build_ntp")
@patch("src.compliance.services.ntp.compliance.check_ntp")
def test_compliance_ntp_post_validation_successful(
    mock_check_ntp,
    mock_build_ntp,
    mock_configure_ntp,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_ntp.return_value = {}
    mock_check_ntp.side_effect = [
        (False, ["(NTP) Mismatched Server Key ID"]),
        (True, []),
    ]
    mock_configure_ntp.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "NTP Configuration Successful",
    }

    result = compliance_ntp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )
    mock_collect_netconf_state.return_value = {}

    mock_log.warning.assert_called_once()
    mock_configure_ntp.assert_called_once()
    mock_log.error.assert_not_called()
    assert any("(NTP) Mismatched Server Key ID" in r for r in result["initial_issues"])
    assert any("NTP Configuration Successful" in r for r in result["actions_taken"])
    assert any("NTP Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.services.ntp.compliance.collect_netconf_state")
@patch("src.compliance.services.ntp.compliance.configure_ntp")
@patch("src.compliance.services.ntp.compliance.build_ntp")
@patch("src.compliance.services.ntp.compliance.check_ntp")
def test_compliance_ntp_post_validation_failed(
    mock_check_ntp,
    mock_build_ntp,
    mock_configure_ntp,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_ntp.return_value = {}
    mock_check_ntp.side_effect = [
        (False, ["(NTP) Mismatched Server Key ID"]),
        (False, ["(NTP) Mismatched Server Key ID"]),
    ]
    mock_configure_ntp.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "NTP Configuration Successful",
    }
    mock_collect_netconf_state.return_value = {}

    result = compliance_ntp(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_log.info.assert_not_called()
    mock_log.error.assert_called_once()
    mock_collect_netconf_state.assert_called_once()
    assert any("(NTP) Mismatched Server Key ID" in r for r in result["initial_issues"])
    assert any("NTP Configuration Successful" in r for r in result["actions_taken"])
    assert any("(NTP) Mismatched Server Key ID" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_ntp_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_ntp(
        mock_sesh, mock_sesh.device_ip, {"ntp": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []
