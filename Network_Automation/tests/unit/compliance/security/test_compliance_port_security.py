import pytest
from unittest.mock import MagicMock, patch
from src.compliance.security.port_security.compliance import compliance_port_security
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
        "status": "SUCCESS"
    }


@pytest.fixture
def exp_port_security():
    return {
        "interfaces": {
            "gigabitethernet1": {
                "enabled": True,
                "mac_addresses": ["aaaa.bbbb.cccc"],
                "maximum": 2,
                "sticky": False,
                "violation": "restict"
            }
        }
    }


@pytest.fixture
def mock_context(exp_port_security):
    return {"port_security": exp_port_security}


@patch("src.compliance.security.port_security.compliance.build_port_security")
@patch("src.compliance.security.port_security.compliance.check_port_security")
def test_compliance_dai_already_compliant(
        mock_check_port_security, mock_build_port_security, mock_sesh, mock_context,
        mock_device_result, mock_log
):
    mock_build_port_security.return_value = {}
    mock_check_port_security.return_value = (True, [])

    result = compliance_port_security(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result,
        mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert result["initial_issues"] == []
    assert any("Port Security Configuration Already Compliant" in r for r in result["actions_taken"])

@patch("src.compliance.security.port_security.compliance.collect_device_state")
@patch("src.compliance.security.port_security.compliance.configure_psecurity")
@patch("src.compliance.security.port_security.compliance.build_port_security")
@patch("src.compliance.security.port_security.compliance.check_port_security")
def test_compliance_dai_non_compliant_config_successful(
        mock_configure_psecurity, mock_check_port_security, mock_build_port_security, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_port_security.return_value = {}
    mock_check_port_security.side_effect = [(False, ["(Port Security) Mismatched Maximum Allowed"]), (True, [])]
    mock_configure_psecurity.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Port Security Successfully Configured"
    }
    mock_collect_device_state.return_value = {}

    result = compliance_port_security(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(Port Security) Mismatched Maximum Allowed" in r for r in result["initial_issues"])
    assert any("Port Security Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.security.port_security.compliance.configure_psecurity")
@patch("src.compliance.security.port_security.compliance.build_port_security")
@patch("src.compliance.security.port_security.compliance.check_port_security")
def test_compliance_dai_config_failed(
        mock_check_port_security, mock_build_port_security, mock_configure_psecurity,
        mock_sesh, mock_context, mock_device_result, mock_log

):

    mock_build_port_security.return_value = {}
    mock_check_port_security.return_value = (False, ["(Port Security) Mismatched Maximum Allowed"])
    mock_configure_psecurity.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure Port Security"
    }

    result = compliance_port_security(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(Port Security) Mismatched Maximum Allowed" in r for r in result["initial_issues"])
    assert any("Failed To Configure Port Security" in r for r in result["actions_taken"])
    assert any("Port Security Remediation Failed" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.security.port_security.compliance.DRY_RUN", True)
@patch("src.compliance.security.port_security.compliance.configure_psecurity")
@patch("src.compliance.security.port_security.compliance.build_port_security")
@patch("src.compliance.security.port_security.compliance.check_port_security")
def test_compliance_dai_dry_run(
        mock_check_port_security, mock_build_port_security, mock_configure_psecurity,
        mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_port_security.return_value = {}
    mock_check_port_security.return_value = (False, ["(Port Security) Mismatched Maximum Allowed"])
    mock_configure_psecurity.return_value = {}

    result = compliance_port_security(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_psecurity.assert_not_called()
    assert any("(Port Security) Mismatched Maximum Allowed" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure Port Security" in r for r in result["actions_taken"])


@patch("src.compliance.security.port_security.compliance.collect_device_state")
@patch("src.compliance.security.port_security.compliance.configure_psecurity")
@patch("src.compliance.security.port_security.compliance.build_port_security")
@patch("src.compliance.security.port_security.compliance.check_port_security")
def test_compliance_dai_post_validation_successful(
        mock_check_port_security, mock_build_port_security, mock_configure_psecurity,
        mock_collect_device_state, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_port_security.return_value = {}
    mock_check_port_security.side_effect = [(False, ["(Port Security) Mismatched Maximum Allowed"]),
                                            (True, [])
                                            ]
    mock_configure_psecurity.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Port Security Successfully Configured"
    }
    mock_collect_device_state.return_value = {}
    result = compliance_port_security(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_not_called()
    assert any("(Port Security) Mismatched Maximum Allowed" in r for r in result["initial_issues"])
    assert any("Port Security Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value
    assert any("Port Security Configuration Post Validation Successful" in r for r in result["actions_taken"])


@patch("src.compliance.security.port_security.compliance.collect_device_state")
@patch("src.compliance.security.port_security.compliance.configure_psecurity")
@patch("src.compliance.security.port_security.compliance.build_port_security")
@patch("src.compliance.security.port_security.compliance.check_port_security")
def test_compliance_dai_post_validation_failed(
        mock_check_port_security, mock_build_port_security, mock_configure_psecurity,
        mock_collect_device_state, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_build_port_security.return_value = {}
    mock_check_port_security.side_effect = [(False, ["(Port Security) Mismatched Maximum Allowed"]),
                                            (False, ["(Port Security) Mismatched Maximum Allowed"])
                                            ]
    mock_configure_psecurity.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Port Security Successfully Configured"
    }
    mock_collect_device_state.return_value = {}
    result = compliance_port_security(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_called_once()
    assert any("(Port Security) Mismatched Maximum Allowed" in r for r in result["initial_issues"])
    assert any("Port Security Successfully Configured" in r for r in result["actions_taken"])
    assert any("(Port Security) Mismatched Maximum Allowed" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_dai_empty(
        mock_sesh, mock_device_result, mock_log
):
    result = compliance_port_security(
        mock_sesh, mock_sesh.device_ip, {"port_security": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []
