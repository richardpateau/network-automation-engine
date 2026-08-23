import pytest
from unittest.mock import MagicMock, patch
from src.compliance.switching.trunk.compliance import compliance_trunk
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
def exp_trunk():
    return [{
        "trunk_interface": "gigabitethernet1", 
        "mode": "trunk",
        "allowed_vlans": "10,20,30,40,50"
    }]

@pytest.fixture
def mock_context(exp_trunk): 
    return {"trunk_ports": exp_trunk}

@patch("src.compliance.switching.trunk.compliance.build_trunk")
@patch("src.compliance.switching.trunk.compliance.check_trunk")
def test_compliance_trunk_already_compliant(
        mock_check_trunk, mock_build_trunk, mock_sesh, mock_context, mock_device_result, 
        mock_log
    ): 
    
    mock_build_trunk.return_value = {}
    mock_check_trunk.return_value = (True, [])

    result = compliance_trunk(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any("Trunk Interface Already Compliant" in r for r in result["actions_taken"])
    assert result["initial_issues"] == []

@patch("src.compliance.switching.trunk.compliance.configure_trunk")
@patch("src.compliance.switching.trunk.compliance.build_trunk")
@patch("src.compliance.switching.trunk.compliance.check_trunk")
def test_compliance_trunk_non_complaint_config_succesful(
        mock_check_trunk, mock_build_trunk, mock_configure_trunk,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_trunk.return_value = {}
    mock_check_trunk.return_value = (False, ["(Trunk) Mismatch Found - Allowed VLANs"])
    mock_configure_trunk.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Trunk Port Configuration Successful"
    }
    result = compliance_trunk(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("(Trunk) Mismatch Found - Allowed VLANs" in r for r in result["initial_issues"])
    assert any("Trunk Port Configuration Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.trunk.compliance.configure_trunk")
@patch("src.compliance.switching.trunk.compliance.build_trunk")
@patch("src.compliance.switching.trunk.compliance.check_trunk")
def test_compliance_trunk_non_complaint_config_failed(
        mock_check_trunk, mock_build_trunk, mock_configure_trunk,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_trunk.return_value = {}
    mock_check_trunk.return_value = (False, ["(Trunk) Mismatch Found - Allowed VLANs"])
    mock_configure_trunk.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure Trunk Port"
    }
    
    result = compliance_trunk(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("(Trunk) Mismatch Found - Allowed VLANs" in r for r in result["initial_issues"])
    assert any("Failed To Configure Trunk Port" in r for r in result["actions_taken"])
    assert any("Failed To Remediate Trunk Port Configuration" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value 

@patch("src.compliance.switching.trunk.compliance.DRY_RUN", True)
@patch("src.compliance.switching.trunk.compliance.configure_trunk")
@patch("src.compliance.switching.trunk.compliance.build_trunk")
@patch("src.compliance.switching.trunk.compliance.check_trunk")
def test_compliance_trunk_dry_run(
        mock_check_trunk, mock_build_trunk, mock_configure_trunk,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_trunk.return_value = {}
    mock_check_trunk.return_value = (False, ["(Trunk) Mismatch Found - Allowed VLANs"])
    mock_configure_trunk.return_value = {}
    result = compliance_trunk(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_configure_trunk.assert_not_called()
    assert any("(Trunk) Mismatch Found - Allowed VLANs" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure_Trunk Port" in r for r in result["actions_taken"])

@patch("src.compliance.switching.trunk.compliance.collect_device_state")
@patch("src.compliance.switching.trunk.compliance.configure_trunk")
@patch("src.compliance.switching.trunk.compliance.build_trunk")
@patch("src.compliance.switching.trunk.compliance.check_trunk")
def test_compliance_trunk_post_validation_successful(
        mock_check_trunk, mock_build_trunk, mock_configure_trunk, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_trunk.return_value = {}
    mock_check_trunk.side_effect = [(False, ["(Trunk) Mismatch Found - Allowed VLANs"]),
                                    (True, [])
                                    ]
    mock_configure_trunk.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Trunk Port Configuration Successful"
    }
    
    mock_collect_device_state.return_value = {}

    result = compliance_trunk(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    
    mock_log.warning.assert_called_once()
    mock_log.error.assert_not_called()
    mock_log.info.assert_called()
    mock_collect_device_state.assert_called_once()
    assert any("(Trunk) Mismatch Found - Allowed VLANs" in r for r in result["initial_issues"])
    assert any("Trunk Port Configuration Successful" in r for r in result["actions_taken"])
    assert any("Trunk Interface Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value

@patch("src.compliance.switching.trunk.compliance.collect_device_state")
@patch("src.compliance.switching.trunk.compliance.configure_trunk")
@patch("src.compliance.switching.trunk.compliance.build_trunk")
@patch("src.compliance.switching.trunk.compliance.check_trunk")
def test_compliance_trunk_post_validation_failed(
        mock_check_trunk, mock_build_trunk, mock_configure_trunk, mock_collect_device_state,
        mock_sesh, mock_context, mock_device_result, mock_log
    ): 
    
    mock_build_trunk.return_value = {}
    mock_check_trunk.side_effect = [(False, ["(Trunk) Mismatch Found - Allowed VLANs"]),
                                    (False, ["(Trunk) Mismatch Found - Allowed VLANs"])
                                    ]
    
    mock_configure_trunk.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Trunk Port Configuration Successful"
    }
    mock_collect_device_state.return_value = {}
    
    result = compliance_trunk(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.info.assert_not_called()
    mock_log.error.assert_called_once()
    assert any("(Trunk) Mismatch Found - Allowed VLANs" in r for r in result["initial_issues"])
    assert any("Trunk Port Configuration Successful" in r for r in result["actions_taken"])
    assert any("(Trunk) Mismatch Found - Allowed VLANs" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value 

def test_compliance_trunk_empty(
        mock_sesh, mock_device_result, mock_log
    ):

    result = compliance_trunk(
            mock_sesh, mock_sesh.device_ip, {"trunk_ports": []}, {}, mock_device_result, 
            mock_log
        )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []