import pytest
from unittest.mock import MagicMock, patch
from src.compliance.services.qos.compliance import compliance_qos
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
def exp_qos():
    return {
        "policies": [
            {
                "policy_name": "voice",
                "attachments": [
                    {"interface": "gigabitethernet1", "direction": "output"}
                ],
                "class_maps": [
                    {
                        "name": "voice",
                        "match_type": "match-any",
                        "protocol": "rtp audio",
                        "action_type": "priority",
                        "bandwidth": "",
                        "priority": "1000",
                    }
                ],
            }
        ]
    }


@pytest.fixture
def mock_context(exp_qos):
    return {"qos": exp_qos}


@patch("src.compliance.services.qos.compliance.build_qos")
@patch("src.compliance.services.qos.compliance.check_qos")
def test_compliance_qos_already_compliant(
    mock_check_qos,
    mock_build_qos,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_qos.return_value = {}
    mock_check_qos.return_value = (True, [])

    result = compliance_qos(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any("QOS Already Compliant" in r for r in result["actions_taken"])
    assert result["initial_issues"] == []


@patch("src.compliance.services.qos.compliance.configure_qos")
@patch("src.compliance.services.qos.compliance.build_qos")
@patch("src.compliance.services.qos.compliance.check_qos")
def test_compliance_qos_non_compliant_config_successful(
    mock_check_qos,
    mock_build_qos,
    mock_configure_qos,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_qos.return_value = {}
    mock_check_qos.return_value = (False, ["Expected Class Map Missing"])
    mock_configure_qos.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "QOS Successfully Configured",
    }
    result = compliance_qos(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("Expected Class Map Missing" in r for r in result["initial_issues"])
    assert any("QOS Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.services.qos.compliance.configure_qos")
@patch("src.compliance.services.qos.compliance.build_qos")
@patch("src.compliance.services.qos.compliance.check_qos")
def test_compliance_qos_non_compliant_config_failed(
    mock_check_qos,
    mock_build_qos,
    mock_configure_qos,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_qos.return_value = {}
    mock_check_qos.return_value = (False, ["Expected Class Map Missing"])
    mock_configure_qos.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure QOS",
    }
    result = compliance_qos(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("Expected Class Map Missing" in r for r in result["initial_issues"])
    assert any("Failed To Configure QOS" in r for r in result["actions_taken"])
    assert any("Failed To Remediate QOS" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.services.qos.compliance.DRY_RUN", True)
@patch("src.compliance.services.qos.compliance.configure_qos")
@patch("src.compliance.services.qos.compliance.build_qos")
@patch("src.compliance.services.qos.compliance.check_qos")
def test_compliance_qos_dry_run(
    mock_check_qos,
    mock_build_qos,
    mock_configure_qos,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_qos.return_value = {}
    mock_check_qos.return_value = (False, ["Expected Class Map Missing"])
    mock_configure_qos.return_value = {}

    result = compliance_qos(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_qos.assert_not_called()
    assert any("Expected Class Map Missing" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure QOS" in r for r in result["actions_taken"])


@patch("src.compliance.services.qos.compliance.collect_netconf_state")
@patch("src.compliance.services.qos.compliance.configure_qos")
@patch("src.compliance.services.qos.compliance.build_qos")
@patch("src.compliance.services.qos.compliance.check_qos")
def test_compliance_qos_post_validation_successful(
    mock_check_qos,
    mock_build_qos,
    mock_configure_qos,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_qos.return_value = {}
    mock_check_qos.side_effect = [(False, ["Expected Class Map Missing"]), (True, [])]
    mock_configure_qos.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "QOS Successfully Configured",
    }
    mock_collect_netconf_state.return_value = {}

    result = compliance_qos(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )
    mock_log.warning.assert_called_once()
    mock_log.error.assert_not_called()
    mock_collect_netconf_state.assert_called_once()
    assert any("Expected Class Map Missing" in r for r in result["initial_issues"])
    assert any("QOS Successfully Configured" in r for r in result["actions_taken"])
    assert any("QOS Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.services.qos.compliance.collect_netconf_state")
@patch("src.compliance.services.qos.compliance.configure_qos")
@patch("src.compliance.services.qos.compliance.build_qos")
@patch("src.compliance.services.qos.compliance.check_qos")
def test_compliance_qos_post_validation_failed(
    mock_check_qos,
    mock_build_qos,
    mock_configure_qos,
    mock_collect_netconf_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_qos.return_value = {}
    mock_check_qos.side_effect = [
        (False, ["Expected Class Map Missing"]),
        (False, ["Expected Class Map Missing"]),
    ]
    mock_configure_qos.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "QOS Successfully Configured",
    }
    mock_collect_netconf_state.return_value = {}
    result = compliance_qos(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_log.error.assert_called_once()
    mock_log.info.assert_not_called()
    mock_collect_netconf_state.assert_called_once()
    assert any("Expected Class Map Missing" in r for r in result["initial_issues"])
    assert any("QOS Successfully Configured" in r for r in result["actions_taken"])
    assert any("Expected Class Map Missing" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_qos_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_qos(
        mock_sesh, mock_sesh.device_ip, {"qos": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []
