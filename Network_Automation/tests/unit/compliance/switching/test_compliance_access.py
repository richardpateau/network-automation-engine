import pytest
from unittest.mock import MagicMock, patch
from src.compliance.switching.access.compliance import compliance_access
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
def exp_access():
    return [{
        "access_interface": "gigabitethernet1",
        "access_vlan": 10
    }]

@pytest.fixture
def mock_context(exp_access): 
    return {"access_ports": exp_access}

@patch("src.compliance.switching.access.compliance.build_access")
@patch("src.compliance.switching.access.compliance.check_access")
def test_compliance_access_already_compliant(
        mock_check_access, mock_build_access, mock_sesh, mock_context, mock_device_result, 
        mock_log
    ): 
    
    mock_build_access.return_value = {}
    mock_check_access.return_value = (True, [])

    result = compliance_access(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )
    
    mock_log.warning.assert_not_called()
    mock_log.info.assert_called_once()
    assert any("Access Interface Already Compliant" in r for r in result["actions_taken"])
    assert result["initial_issues"] == []

@patch("src.compliance.switching.access.compliance.collect_device_state")
@patch("src.compliance.switching.access.compliance.configure_access")
@patch("src.compliance.switching.access.compliance.build_access")
@patch("src.compliance.switching.access.compliance.check_access")
def test_compliance_access_non_compliant_config_successful(
        mock_check_access, mock_build_access, mock_configure_access, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_access.return_value = {}
    mock_check_access.side_effect = [(False, ["Mismatched Access Port VLAN"]), (True, [])]
    mock_configure_access.return_value = {
        "status": OperationalStatus.SUCCESS.value, 
        "summary": "Access Port Successfully Configured"
    }
    mock_collect_device_state.return_value = {}
    result = compliance_access(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("Mismatched Access Port VLAN" in r for r in result["initial_issues"])
    assert any("Access Port Successfully Configured" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.access.compliance.configure_access")
@patch("src.compliance.switching.access.compliance.build_access")
@patch("src.compliance.switching.access.compliance.check_access")
def test_compliance_access_non_compliant_config_failed(
        mock_check_access, mock_build_access, mock_configure_access, mock_sesh, mock_context, 
        mock_device_result, mock_log
    ): 
    
    mock_build_access.return_value = {}
    mock_check_access.return_value = (False, ["Mismatched Access Port VLAN"])
    mock_configure_access.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value, 
        "summary": "Failed To Configure Access Port"
    }
    
    result = compliance_access(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("Mismatched Access Port VLAN" in r for r in result["initial_issues"])
    assert any("Failed To Configure Access Port" in r for r in result["actions_taken"])
    assert any("Failed To Remediate Access Port" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value 

@patch("src.compliance.switching.access.compliance.DRY_RUN", True)
@patch("src.compliance.switching.access.compliance.configure_access")
@patch("src.compliance.switching.access.compliance.build_access")
@patch("src.compliance.switching.access.compliance.check_access")
def test_compliance_access_dry_run(
        mock_check_access, mock_build_access, mock_configure_access, mock_sesh, mock_context, 
        mock_device_result, mock_log
    ): 
    
    mock_build_access.return_value = {}
    mock_check_access.return_value = (False, ["Mismatched Access Port VLAN"])
    mock_configure_access.return_value = {}
    
    result = compliance_access(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_configure_access.assert_not_called()
    assert any("Mismatched Access Port VLAN" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure Access Port" in r for r in result["actions_taken"]) 

@patch("src.compliance.switching.access.compliance.collect_device_state")
@patch("src.compliance.switching.access.compliance.configure_access")
@patch("src.compliance.switching.access.compliance.build_access")
@patch("src.compliance.switching.access.compliance.check_access")
def test_compliance_access_post_validation_successful(
        mock_check_access, mock_build_access, mock_configure_access, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_access.return_value = {}
    mock_check_access.side_effect = [(False, ["Mismatched Access Port VLAN"]),
                                     (True, [])
                                     ] 
    mock_configure_access.return_value = {
        "status": OperationalStatus.SUCCESS.value, 
        "summary": "Access Port Successfully Configured"
    }
    mock_collect_device_state.return_value = {}    
    
    result = compliance_access(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    assert any("Mismatched Access Port VLAN" in r for r in result["initial_issues"])
    assert any("Access Port Successfully Configured" in r for r in result["actions_taken"])
    assert any("Access Interface Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.access.compliance.collect_device_state")
@patch("src.compliance.switching.access.compliance.configure_access")
@patch("src.compliance.switching.access.compliance.build_access")
@patch("src.compliance.switching.access.compliance.check_access")
def test_compliance_access_post_validation_failed(
        mock_check_access, mock_build_access, mock_configure_access, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_access.return_value = {}
    mock_check_access.side_effect = [(False, ["Mismatched Access Port VLAN"]),
                                     (False, ["Mismatched Access Port VLAN"])
                                     ] 
    mock_configure_access.return_value = {
        "status": OperationalStatus.SUCCESS.value, 
        "summary": "Access Port Successfully Configured"
    }
    mock_collect_device_state.return_value = {}    
    
    result = compliance_access(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_log.info.assert_not_called()
    mock_log.error.assert_called_once()
    mock_collect_device_state.assert_called_once()
    assert any("Mismatched Access Port VLAN" in r for r in result["initial_issues"])
    assert any("Access Port Successfully Configured" in r for r in result["actions_taken"])
    assert any("Mismatched Access Port VLAN" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value 

def test_compliance_access_empty(
        mock_sesh, mock_device_result, mock_log
    ):  
    
    result = compliance_access(
            mock_sesh, mock_sesh.device_ip, {"access_ports": {}}, {}, mock_device_result, mock_log
        )
    assert result["initial_issues"] == []
    assert result["actions_taken"] == []