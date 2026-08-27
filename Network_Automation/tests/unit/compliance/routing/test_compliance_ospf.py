import pytest
from unittest.mock import MagicMock, patch
from src.compliance.routing.ospf.compliance import compliance_ospf
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
def mock_device_result():
    return {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS",
    }


@pytest.fixture
def exp_ospf():
    return [
        {
            "process_id": 1,
            "router_id": "1.1.1.1",
            "interfaces": {"gigabitethernet1": {}, "gigabitethernet2": {}},
        }
    ]


@pytest.fixture
def mock_context(exp_ospf):
    return {"ospf": exp_ospf}


@patch("src.compliance.routing.ospf.compliance.check_ospf")
@patch("src.compliance.routing.ospf.compliance.build_ospf")
def test_compliance_ospf_already_compliant(
        mock_build_ospf,
        mock_check_ospf,
        mock_sesh,
        mock_context,
        mock_device_result,
        mock_log,
):
    mock_build_ospf.return_value = {}
    mock_check_ospf.return_value = (True, [])

    result = compliance_ospf(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert result["initial_issues"] == []
    assert any("OSPF Already Compliant" in r for r in result["actions_taken"])

@patch("src.compliance.routing.ospf.compliance.collect_restconf_state")
@patch("src.compliance.routing.ospf.compliance.configure_ospf")
@patch("src.compliance.routing.ospf.compliance.check_ospf")
@patch("src.compliance.routing.ospf.compliance.build_ospf")
def test_compliance_ospf_non_compliant_and_config_successful(
        mock_build_ospf,
        mock_check_ospf, 
        mock_configure_ospf,
        mock_collect_restconf_state,
        mock_sesh,
        mock_context,
        mock_device_result,
        mock_log,
):
    mock_build_ospf.return_value = {}
    mock_check_ospf.side_effect = [(False, ["(OSPF) Mismatched Router ID"]), (True, [])]
    mock_configure_ospf.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "OSPF Configuration Successful",
    }
    mock_collect_restconf_state.return_value = {}
    result = compliance_ospf(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_ospf.assert_called_once()
    assert any("(OSPF) Mismatched Router ID" in r for r in result["initial_issues"])
    assert any("OSPF Configuration Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value

@patch("src.compliance.routing.ospf.compliance.collect_restconf_state")
@patch("src.compliance.routing.ospf.compliance.configure_ospf")
@patch("src.compliance.routing.ospf.compliance.check_ospf")
@patch("src.compliance.routing.ospf.compliance.build_ospf")
def test_compliance_ospf_config_failed(
        mock_build_ospf,
        mock_check_ospf, 
        mock_configure_ospf,
        mock_collect_restconf_state,
        mock_sesh,
        mock_context,
        mock_device_result,
        mock_log,
):
    mock_build_ospf.return_value = {}
    mock_check_ospf.return_value = (False, ["(OSPF) Mismatched Router ID"])
    mock_configure_ospf.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed to Configure OSPF",
    }

    result = compliance_ospf(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )
    mock_collect_restconf_state.return_value = {}
    mock_log.warning.assert_called_once()
    assert any("(OSPF) Mismatched Router ID" in r for r in result["initial_issues"])
    assert any("Failed to Configure OSPF" in r for r in result["actions_taken"])
    assert any("Failed to Remediate OSPF" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.routing.ospf.compliance.DRY_RUN", True)
@patch("src.compliance.routing.ospf.compliance.configure_ospf")
@patch("src.compliance.routing.ospf.compliance.check_ospf")
@patch("src.compliance.routing.ospf.compliance.build_ospf")
def test_compliance_ospf_dry_run(
        mock_build_ospf,
        mock_check_ospf, 
        mock_configure_ospf,
        mock_sesh,
        mock_context,
        mock_device_result,
        mock_log,
):
    mock_build_ospf.return_value = {}
    mock_check_ospf.return_value = (False, ["(OSPF) Mismatched Router ID"])
    mock_configure_ospf.return_value = {}

    result = compliance_ospf(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_ospf.assert_not_called()
    assert any("(OSPF) Mismatched Router ID" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure OSPF" in r for r in result["actions_taken"])


@patch("src.compliance.routing.ospf.compliance.collect_restconf_state")
@patch("src.compliance.routing.ospf.compliance.configure_ospf")
@patch("src.compliance.routing.ospf.compliance.check_ospf")
@patch("src.compliance.routing.ospf.compliance.build_ospf")
def test_compliance_ospf_post_validation_successful(
        mock_build_ospf,
        mock_check_ospf, 
        mock_configure_ospf,
        mock_collect_restconf_state,
        mock_sesh,
        mock_context,
        mock_device_result,
        mock_log,
):
    mock_build_ospf.return_value = {}
    mock_check_ospf.side_effect = [(False, ["(OSPF) Mismatched Router ID"]), (True, [])]
    mock_configure_ospf.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "OSPF Successfully Configured",
    }
    mock_collect_restconf_state.return_value = {}

    result = compliance_ospf(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_collect_restconf_state.assert_called_once()


    mock_log.info.assert_called_once()
    mock_log.error.assert_not_called()
    mock_log.warning.assert_called_once()
    assert any("(OSPF) Mismatched Router ID" in r for r in result["initial_issues"])
    assert any("OSPF Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value
    assert any(
        "OSPF Configuration Post Validation Successful" in r
        for r in result["actions_taken"]
    )


@patch("src.compliance.routing.ospf.compliance.collect_restconf_state")
@patch("src.compliance.routing.ospf.compliance.configure_ospf")
@patch("src.compliance.routing.ospf.compliance.check_ospf")
@patch("src.compliance.routing.ospf.compliance.build_ospf")
def test_compliance_ospf_post_validation_failed(
        mock_build_ospf,
        mock_check_ospf, 
        mock_configure_ospf,
        mock_collect_restconf_state,
        mock_sesh,
        mock_context,
        mock_device_result,
        mock_log
):
    mock_build_ospf.return_value = {}
    mock_check_ospf.side_effect = [
        (False, ["(OSPF) Mismatched Router ID"]),
        (False, ["(OSPF) Mismatched Router ID"]),
    ]
    mock_configure_ospf.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "OSPF Successfully Configured",
    }
    mock_collect_restconf_state.return_value = {}

    result = compliance_ospf(
        mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
    )

    mock_log.error.assert_called_once()


    mock_log.info.assert_not_called()
    mock_collect_restconf_state.assert_called_once()
    mock_log.warning.assert_called_once()
    assert any("(OSPF) Mismatched Router ID" in r for r in result["initial_issues"])
    assert any("OSPF Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value
    assert any("(OSPF) Mismatched Router ID" in r for r in result["critical_issues"])


def test_compliance_ospf_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_ospf(
        mock_sesh, "192.168.1.1", {"ospf": []}, {}, mock_device_result, mock_log
    )

    assert result["actions_taken"] == []
    assert result["initial_issues"] == []
