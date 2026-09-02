import pytest
from unittest.mock import MagicMock, patch
from src.compliance.switching.vlan.compliance import compliance_vlan
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
def exp_vlan():
    return [{
        "name": "Management", 
        "vlan_id": 10
    }]

@pytest.fixture
def mock_context(exp_vlan): 
    return {"vlans": exp_vlan}

@patch("src.compliance.switching.vlan.compliance.build_vlan")
@patch("src.compliance.switching.vlan.compliance.check_vlan")
def test_compliance_vlan_already_compliant(
        mock_check_vlan, mock_build_vlan, mock_sesh, mock_context, mock_device_result, 
        mock_log
    ): 
    
    mock_build_vlan.return_value = {}
    mock_check_vlan.return_value = (True, [])

    result = compliance_vlan(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_not_called()
    mock_log.info.assert_called_once()
    assert any("VLAN Already Compliant" in r for r in result["actions_taken"])
    assert result["initial_issues"] == []

@patch("src.compliance.switching.vlan.compliance.collect_device_state")
@patch("src.compliance.switching.vlan.compliance.configure_vlan")
@patch("src.compliance.switching.vlan.compliance.build_vlan")
@patch("src.compliance.switching.vlan.compliance.check_vlan")
def test_compliance_vlan_non_compliant_config_successful(
        mock_check_vlan, mock_build_vlan, mock_configure_vlan, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_vlan.return_value = {}
    mock_check_vlan.side_effect = [(False, ["VLAN Name Mismatch"]), (True, [])]
    mock_configure_vlan.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "VLAN Configuration Successful"
    }
    mock_collect_device_state.return_value = {}
    result = compliance_vlan(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("VLAN Name Mismatch" in r for r in result["initial_issues"])
    assert any("VLAN Configuration Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.vlan.compliance.configure_vlan")
@patch("src.compliance.switching.vlan.compliance.build_vlan")
@patch("src.compliance.switching.vlan.compliance.check_vlan")
def test_compliance_vlan_non_compliant_config_failed(
        mock_check_vlan, mock_build_vlan, mock_configure_vlan, 
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_vlan.return_value = {}
    mock_check_vlan.return_value = (False, ["VLAN Name Mismatch"])
    mock_configure_vlan.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure VLAN"
    }

    result = compliance_vlan(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("VLAN Name Mismatch" in r for r in result["initial_issues"])
    assert any("Failed To Configure VLAN" in r for r in result["actions_taken"])
    assert any("Failed To Remediate VLAN" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value 

@patch("src.compliance.switching.vlan.compliance.DRY_RUN", True)
@patch("src.compliance.switching.vlan.compliance.configure_vlan")
@patch("src.compliance.switching.vlan.compliance.build_vlan")
@patch("src.compliance.switching.vlan.compliance.check_vlan")
def test_compliance_vlan_dry_run(
        mock_check_vlan, mock_build_vlan, mock_configure_vlan, 
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_vlan.return_value = {}
    mock_check_vlan.return_value = (False, ["VLAN Name Mismatch"])
    mock_configure_vlan.return_value = {}

    result = compliance_vlan(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_configure_vlan.assert_not_called()
    assert any("VLAN Name Mismatch" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure VLAN" in r for r in result["actions_taken"])

@patch("src.compliance.switching.vlan.compliance.collect_device_state")
@patch("src.compliance.switching.vlan.compliance.configure_vlan")
@patch("src.compliance.switching.vlan.compliance.build_vlan")
@patch("src.compliance.switching.vlan.compliance.check_vlan")
def test_compliance_vlan_post_validation_successful(
        mock_check_vlan, mock_build_vlan, mock_configure_vlan, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_vlan.return_value = {}
    mock_check_vlan.side_effect = [(False, ["VLAN Name Mismatch"]), 
                                   (True, [])
                                  ]
    mock_configure_vlan.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "VLAN Configuration Successful"
    }
    mock_collect_device_state.return_value = {}

    result = compliance_vlan(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.info.assert_called()
    mock_log.error.assert_not_called()
    assert any("VLAN Name Mismatch" in r for r in result["initial_issues"])
    assert any("VLAN Configuration Successful" in r for r in result["actions_taken"])
    assert any("VLAN Configuration Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.vlan.compliance.collect_device_state")
@patch("src.compliance.switching.vlan.compliance.configure_vlan")
@patch("src.compliance.switching.vlan.compliance.build_vlan")
@patch("src.compliance.switching.vlan.compliance.check_vlan")
def test_compliance_vlan_post_validation_failed(
        mock_check_vlan, mock_build_vlan, mock_configure_vlan, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_vlan.return_value = {}
    mock_check_vlan.side_effect = [(False, ["VLAN Name Mismatch"]), 
                                   (False, ["VLAN Name Mismatch"])
                                  ]
    mock_configure_vlan.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "VLAN Configuration Successful"
    }
    mock_collect_device_state.return_value = {}

    result = compliance_vlan(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.info.assert_not_called()
    mock_log.error.assert_called_once()
    assert any("VLAN Name Mismatch" in r for r in result["initial_issues"])
    assert any("VLAN Configuration Successful" in r for r in result["actions_taken"])
    assert any("VLAN Name Mismatch" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value

def test_compliance_vlan_empty(
        mock_sesh, mock_device_result, mock_log 
    ):
    
    result = compliance_vlan(
            mock_sesh, mock_sesh.device_ip, {"vlans": []}, {}, mock_device_result, mock_log
        )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []