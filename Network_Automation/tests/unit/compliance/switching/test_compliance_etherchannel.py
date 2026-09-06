import pytest
from unittest.mock import MagicMock, patch
from src.compliance.switching.etherchannel.compliance import compliance_etherchannel
from src.core.enums import OperationalStatus


@pytest.fixture
def mock_sesh():
    sesh = MagicMock()
    sesh.device_ip = "192.168.1.1"
    sesh.transport = "NETMIKO"
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
def exp_etherchannel():
    return {
        "enabled": True,
        "groups": {
            1: {
                "mode": "active",
                "type": "lacp",
                "interfaces": ["gigabitethernet0/3", "gigabitethernet1/0", ],
                "description": "server farm",
                "switchport_mode": "access"
            }
        }
    }


@pytest.fixture
def mock_context(exp_etherchannel):
    return {"etherchannel": exp_etherchannel}


@patch("src.compliance.switching.etherchannel.compliance.build_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.check_etherchannel")
def test_compliance_etherchannel_already_compliant(
        mock_check_etherchannel, mock_build_etherchannel, mock_sesh,
        mock_context, mock_device_result, mock_log
):
    mock_build_etherchannel.return_value = {}
    mock_check_etherchannel.return_value = (True, [])

    result = compliance_etherchannel(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_not_called()
    mock_log.info.assert_called_once()
    assert any("Etherchannel Configuration Already Compliant" in r for r in result["actions_taken"])
    assert result["initial_issues"] == []


@patch("src.compliance.switching.etherchannel.compliance.collect_device_state")
@patch("src.compliance.switching.etherchannel.compliance.configure_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.build_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.check_etherchannel")
def test_compliance_etherchannel_non_compliant_config_successful(
        mock_check_etherchannel, mock_build_etherchannel, mock_configure_etherchannel, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_etherchannel.return_value = {}
    mock_check_etherchannel.side_effect = [(False, ["(Etherchannel) Mode Mismatch"]), (True, [])]
    mock_configure_etherchannel.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Etherchannel Configuration Successful"
    }
    mock_collect_device_state.return_value = {}


    result = compliance_etherchannel(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("Etherchannel) Mode Mismatch" in r for r in result["initial_issues"])
    assert any("Etherchannel Configuration Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.switching.etherchannel.compliance.configure_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.build_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.check_etherchannel")
def test_compliance_etherchannel_non_compliant_config_failed(
        mock_check_etherchannel, mock_build_etherchannel, mock_configure_etherchannel,
        mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_etherchannel.return_value = {}
    mock_check_etherchannel.return_value = (False, ["(Etherchannel) Mode Mismatch"])
    mock_configure_etherchannel.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure Etherchannel"
    }

    result = compliance_etherchannel(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(Etherchannel) Mode Mismatch" in r for r in result["initial_issues"])
    assert any("Failed To Configure Etherchannel" in r for r in result["actions_taken"])
    assert any("Etherchannel Configuration Remediation Failed" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.switching.etherchannel.compliance.DRY_RUN", True)
@patch("src.compliance.switching.etherchannel.compliance.configure_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.build_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.check_etherchannel")
def test_compliance_etherchannel_dry_run(
        mock_check_etherchannel, mock_build_etherchannel, mock_configure_etherchannel,
        mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_etherchannel.return_value = {}
    mock_check_etherchannel.return_value = (False, ["(Etherchannel) Mode Mismatch"])
    mock_configure_etherchannel.return_value = {}

    result = compliance_etherchannel(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_etherchannel.assert_not_called()
    assert any("(Etherchannel) Mode Mismatch" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure Etherchannel" in r for r in result["actions_taken"])


@patch("src.compliance.switching.etherchannel.compliance.collect_device_state")
@patch("src.compliance.switching.etherchannel.compliance.configure_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.build_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.check_etherchannel")
def test_compliance_etherchannel_post_validation_successful(
        mock_check_etherchannel, mock_build_etherchannel, mock_configure_etherchannel,
        mock_collect_device_state, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_etherchannel.return_value = {}
    mock_check_etherchannel.side_effect = [(False, ["(Etherchannel) Mode Mismatch"]),
                                           (True, [])
                                           ]
    mock_configure_etherchannel.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Etherchannel Configuration Successful"
    }
    mock_collect_device_state.return_value = {}

    result = compliance_etherchannel(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_not_called()
    assert any("(Etherchannel) Mode Mismatch" in r for r in result["initial_issues"])
    assert any("Etherchannel Configuration Successful" in r for r in result["actions_taken"])
    assert any("Etherchannel Configuration Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.switching.etherchannel.compliance.collect_device_state")
@patch("src.compliance.switching.etherchannel.compliance.configure_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.build_etherchannel")
@patch("src.compliance.switching.etherchannel.compliance.check_etherchannel")
def test_compliance_etherchannel_post_validation_failed(
        mock_check_etherchannel, mock_build_etherchannel, mock_configure_etherchannel,
        mock_collect_device_state, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_etherchannel.return_value = {}
    mock_check_etherchannel.side_effect = [(False, ["(Etherchannel) Mode Mismatch"]),
                                           (False, ["(Etherchannel) Mode Mismatch"])
                                           ]
    mock_configure_etherchannel.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Etherchannel Configuration Successful"
    }
    mock_collect_device_state.return_value = {}

    result = compliance_etherchannel(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.info.assert_not_called()
    mock_log.error.assert_called_once()
    assert any("(Etherchannel) Mode Mismatch" in r for r in result["initial_issues"])
    assert any("Etherchannel Configuration Successful" in r for r in result["actions_taken"])
    assert any("(Etherchannel) Mode Mismatch" in r for r in result["critical_issues"])
    result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_etherchannel_empty(
        mock_sesh, mock_device_result, mock_log
):
    result = compliance_etherchannel(
        mock_sesh, mock_sesh.device_ip, {"etherchannel": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []
