import pytest
from unittest.mock import MagicMock, patch
from src.compliance.routing.roas import compliance_roas
from src.core.enums import OperationalStatus


@pytest.fixture
def mock_sesh():
    sesh = MagicMock()
    sesh.transport = "RESTCONF"
    sesh.device_ip = "192.168.1.1"
    return sesh


@pytest.fixture
def mock_log():
    return MagicMock()


@pytest.fixture
def device_result():
    return {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS",
    }


@pytest.fixture
def exp_roas():
    return {
        "gigabitethernet1.10": {
            "interface": "gigabitethernet1.10",
            "router_vlan": 10,
            "ip": "192.168.10.1",
            "mask": "255.255.255.0",
        }
    }


@pytest.fixture
def mock_context(exp_roas):
    return {"roas": exp_roas}


@patch("src.compliance.routing.roas.compliance.build_roas")
@patch("src.compliance.routing.roas.compliance.check_roas")
def test_compliance_roas_already_compliant(
    mock_check_roas,
    mock_build_roas,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_roas.return_value = {}
    mock_check_roas.return_value = (True, [])

    result = compliance_roas(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any(
        "ROAS Configuration Already Compliant" in r for r in result["actions_taken"]
    )
    assert result["initial_issues"] == []


@patch("src.compliance.routing.roas.compliance.configure_roas")
@patch("src.compliance.routing.roas.compliance.build_roas")
@patch("src.compliance.routing.roas.compliance.check_roas")
def test_compliance_roas_non_compliant_and_config_success(
    mock_check_roas,
    mock_build_roas,
    mock_configure_roas,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_roas.return_value = {}
    mock_check_roas.return_value = (False, ["roas VLAN Mismatch"])
    mock_configure_roas.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "ROAS Successfully Configured",
    }
    result = compliance_roas(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("ROAS VLAN Mismatch" in r for r in result["initial_issues"])
    assert any("ROAS Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.routing.roas.compliance.configure_roas")
@patch("src.compliance.routing.roas.compliance.build_roas")
@patch("src.compliance.routing.roas.compliance.check_roas")
def test_compliance_roas_config_failed(
    mock_configure_roas,
    mock_check_roas,
    mock_build_roas,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_roas.return_value = {}
    mock_check_roas.return_value = (False, ["ROAS VLAN Mismatch"])
    mock_configure_roas.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed to Configure ROAS",
    }

    result = compliance_roas(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("ROAS VLAN Mismatch" in r for r in result["initial_issues"])
    assert any("Failed to Configure ROAS" in r for r in result["actions_taken"])
    assert any("Failed to Remediate ROAS" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.routing.roas.compliance.collect_restconf_state")
@patch("src.compliance.routing.roas.compliance.configure_roas")
@patch("src.compliance.routing.roas.compliance.build_roas")
@patch("src.compliance.routing.roas.compliance.check_roas")
def test_compliance_roas_post_validation_successful(
    mock_collect_restconf_state,
    mock_configure_roas,
    mock_check_roas,
    mock_build_roas,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_roas.return_value = {}
    mock_check_roas.side_effect = [(False, ["ROAS VLAN Mismatch"]), (True, [])]
    mock_configure_roas.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "ROAS Successfully Configured",
    }
    mock_collect_restconf_state.return_value = {}

    result = compliance_roas(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("ROAS VLAN Mismatch" in r for r in result["initial_issues"])
    assert any("ROAS Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value
    mock_collect_restconf_state.assert_called_once()
    assert any(
        "ROAS Configuration Validation Successful" in r for r in result["actions_taken"]
    )
    mock_log.error.assert_not_called()


@patch("src.compliance.routing.roas.compliance.collect_restconf_state")
@patch("src.compliance.routing.roas.compliance.configure_roas")
@patch("src.compliance.routing.roas.compliance.build_roas")
@patch("src.compliance.routing.roas.compliance.check_roas")
def test_compliance_roas_post_validation_failed(
    mock_collect_restconf_state,
    mock_configure_roas,
    mock_check_roas,
    mock_build_roas,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_roas.return_value = {}
    mock_check_roas.return_value = (False, ["ROAS VLAN Mismatch"])
    mock_configure_roas.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "message": "ROAS Configuration Successful",
    }
    mock_collect_restconf_state.return_value = {}

    result = compliance_roas(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_log.error.assert_called_once()
    mock_log.info.assert_not_called()
    assert any("ROAS VLAN Mismatch" in r for r in result["initial_issues"])
    assert any("ROAS Configuration Successful" in r for r in result["actions_taken"])
    assert any("ROAS VLAN Mismatch" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_roas_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_roas(
        mock_sesh, "192.168.1.1", {"roas": {}}, {}, mock_device_result, mock_log
    )

    assert result["actions_taken"] == []
    assert result["initial_issues"] == []


@patch("src.compliance.routing.roas.compliance.DRY_RUN", True)
@patch("src.compliance.routing.roas.compliance.collect_restconf_state")
@patch("src.compliance.routing.roas.compliance.configure_roas")
@patch("src.compliance.routing.roas.compliance.build_roas")
@patch("src.compliance.routing.roas.compliance.check_roas")
def test_compliance_roas_dry_run(
    mock_collect_restconf_state,
    mock_configure_roas,
    mock_check_roas,
    mock_build_roas,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_roas.return_value = {}
    mock_check_roas.return_value = (False, ["ROAS VLAN Mismatch"])
    mock_configure_roas.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "ROAS Configuration Successful",
    }
    mock_collect_restconf_state.return_value = {}

    result = compliance_roas(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_collect_restconf_state.assert_not_called()
    mock_configure_roas.assert_not_called()
    mock_log.warning.assert_called_once()
    assert any("ROAS VLAN Mismatch" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure roas" in r for r in result["actions_taken"])


@patch("src.compliance.routing.roas.compliance.collect_restconf_state")
@patch("src.compliance.routing.roas.compliance.configure_roas")
@patch("src.compliance.routing.roas.compliance.build_roas")
@patch("src.compliance.routing.roas.compliance.check_roas")
def test_compliance_roas_multiple_config(
    mock_configure_roas,
    mock_check_roas,
    mock_build_roas,
    mock_sesh,
    mock_device_result,
    mock_log,
):
    context = {
        "roas": {
            "gigabitethernet1.10": {
                "interface": "gigabitethernet1.10",
                "router_vlan": 10,
                "ip": "192.168.10.1",
                "mask": "255.255.255.0",
            },
            "gigabitethernet1.20": {
                "interface": "gigabitethernet1.20",
                "router_vlan": 20,
                "ip": "192.168.20.1",
                "mask": "255.255.255.0",
            },
        }
    }

    mock_build_roas.return_value = {}
    mock_check_roas.side_effect = [(True, []), (False, ["ROAS VLAN Mismatch"])]
    mock_configure_roas.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "ROAS Successfully Configured",
    }

    result = compliance_roas(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_roas.assert_called_once()
    assert any(
        "ROAS Configuration Already Compliant" in r for r in result["actions_taken"]
    )
    assert any("ROAS VLAN Mismatch" in r for r in result["initial_issues"])
    assert any("ROAS Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value
