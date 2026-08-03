import pytest
from unittest.mock import MagicMock, patch
from src.compliance.security.dai import compliance_dai
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
def exp_dai():
    return {
        "arp_inspection": True,
        "enabled_vlans": [10, 20, 30, 40, 50],
        "interfaces": {
            "gigabitethernet1": {"rate_limit": 20, "trusted": False},
            "gigabitethernet2": {"rate_limit": None, "trusted": True},
        },
        "log_buffer": {"enabled": True, "entries": 1024},
    }


@pytest.fixture
def mock_context(exp_dai):
    return {"dai": exp_dai}


@patch("src.compliance.security.dai.compliance.build_dai")
@patch("src.compliance.security.dai.compliance.check_dai")
def test_compliance_dai_already_compliant(
    mock_check_dai,
    mock_build_dai,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dai.return_value = {}
    mock_check_dai.return_value = (True, [])

    result = compliance_dai(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any(
        "DAI Configuration Already Compliant" in r for r in result["actions_taken"]
    )
    assert result["initial_issues"] == []


@patch("src.compliance.security.dai.compliance.configure_dai")
@patch("src.compliance.security.dai.compliance.build_dai")
@patch("src.compliance.security.dai.compliance.check_dai")
def test_compliance_dai_non_compliant_config_successful(
    mock_check_dai,
    mock_build_dai,
    mock_configure_dai,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dai.return_value = {}
    mock_check_dai.return_value = (False, ["(DAI) Missing VLAN(s)"])
    mock_configure_dai.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DAI Configuration Successfully Configured",
    }

    result = compliance_dai(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(DAI) Missing VLAN(s)" in r for r in result["initial_issues"])
    assert any(
        "DAI Configuration Successfully Configured" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.security.dai.compliance.configure_dai")
@patch("src.compliance.security.dai.compliance.build_dai")
@patch("src.compliance.security.dai.compliance.check_dai")
def test_compliance_dai_config_failed(
    mock_check_dai,
    mock_build_dai,
    mock_configure_dai,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dai.return_value = {}
    mock_check_dai.return_value = (False, ["(DAI) Missing VLAN(s)"])
    mock_configure_dai.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure DAI",
    }

    result = compliance_dai(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )
    mock_log.warning.assert_called_once()
    assert any("(DAI) Missing VLAN(s)" in r for r in result["initial_issues"])
    assert any(
        "DAI Configuration Remediation Failed" in r for r in result["critical_issues"]
    )
    assert any("Failed To Configure DAI" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.security.dai.compliance.DRY_RUN", True)
@patch("src.compliance.security.dai.compliance.configure_dai")
@patch("src.compliance.security.dai.compliance.build_dai")
@patch("src.compliance.security.dai.compliance.check_dai")
def test_compliance_dai_dry_run(
    mock_check_dai,
    mock_build_dai,
    mock_configure_dai,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dai.return_value = {}
    mock_check_dai.return_value = (False, ["(DAI) Missing VLAN(s)"])
    mock_configure_dai.return_value = {}

    result = compliance_dai(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_dai.assert_not_called()
    assert any("(DAI) Missing VLAN(s)" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure DAI" in r for r in result["actions_taken"])


@patch("src.compliance.security.dai.compliance.collect_device_state")
@patch("src.compliance.security.dai.compliance.configure_dai")
@patch("src.compliance.security.dai.compliance.build_dai")
@patch("src.compliance.security.dai.compliance.check_dai")
def test_compliance_dai_post_validation_successful(
    mock_collect_device_state,
    mock_check_dai,
    mock_build_dai,
    mock_configure_dai,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dai.return_value = {}
    mock_check_dai.side_effect = [(False, ["(DAI) Missing VLAN(s)"]), (True, [])]
    mock_configure_dai.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DAI Configuration Successfully Configured",
    }

    result = compliance_dai(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_not_called()
    assert any("(DAI) Missing VLAN(s)" in r for r in result["initial_issues"])
    assert any(
        "DAI Configuration Successfully Configured" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value
    assert any(
        "DAI Configuration Post Validation Successful" in r
        for r in result["actions_taken"]
    )


@patch("src.compliance.security.dai.compliance.collect_device_state")
@patch("src.compliance.security.dai.compliance.configure_dai")
@patch("src.compliance.security.dai.compliance.build_dai")
@patch("src.compliance.security.dai.compliance.check_dai")
def test_compliance_dai_post_validation_failed(
    mock_collect_device_state,
    mock_check_dai,
    mock_build_dai,
    mock_configure_dai,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_dai.return_value = {}
    mock_check_dai.side_effect = [
        (False, ["(DAI) Missing VLAN(s)"]),
        (False, ["(DAI) Missing VLAN(s)"]),
    ]
    mock_configure_dai.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "DAI Configuration Successfully Configured",
    }

    result = compliance_dai(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_called_once()
    assert any("(DAI) Missing VLAN(s)" in r for r in result["initial_issues"])
    assert any(
        "DAI Configuration Successfully Configured" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value
    assert any("(DAI) Missing VLAN(s)" in r for r in result["critical_issues"])


def test_compliance_dai_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_dai(
        mock_sesh, mock_sesh.device_ip, {"dai": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []
