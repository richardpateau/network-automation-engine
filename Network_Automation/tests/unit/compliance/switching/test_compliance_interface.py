import pytest
from unittest.mock import MagicMock, patch
from src.compliance.switching.interface.compliance import compliance_interface
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
def exp_interface():
    return [{
        "interface": "gigabitethernet1", 
        "should_be_up": True, 
        "description": "link to WAN ROUTER"
    }]

@pytest.fixture
def mock_context(exp_interface): 
    return {"interfaces": exp_interface}

@patch("src.compliance.switching.interface.compliance.build_interface")
@patch("src.compliance.switching.interface.compliance.check_interface")
def test_compliance_interface_already_compliant(
        mock_check_interface, mock_build_interface, mock_sesh, mock_context, 
        mock_device_result, mock_log
    ):
    
    mock_build_interface.return_value = {}
    mock_check_interface.return_value = (True, [])

    result = compliance_interface(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any("Interface Configuration Already Compliant" in r for r in result["actions_taken"])
    assert result["initial_issues"] == []

@patch("src.compliance.switching.interface.compliance.configure_interface")
@patch("src.compliance.switching.interface.compliance.build_interface")
@patch("src.compliance.switching.interface.compliance.check_interface")
def test_compliance_interface_non_compliant_config_successful(
        mock_check_interface, mock_build_interface, mock_configure_interface,
        mock_sesh, mock_context, mock_device_result, mock_log
    ):
    
    mock_build_interface.return_value = {}
    mock_check_interface.return_value = (False, ["Mismatched Interface State"])
    mock_configure_interface.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Interface Configuration Successful"
    }
    result = compliance_interface(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("Mismatched Interface State" in r for r in result["initial_issues"])
    assert any("Interface Configuration Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.interface.compliance.configure_interface")
@patch("src.compliance.switching.interface.compliance.build_interface")
@patch("src.compliance.switching.interface.compliance.check_interface")
def test_compliance_interface_non_compliant_config_failed(
        mock_check_interface, mock_build_interface, mock_configure_interface,
        mock_sesh, mock_context, mock_device_result, mock_log
    ):
    
    mock_build_interface.return_value = {}
    mock_check_interface.return_value = (False, ["Mismatched Interface State"])
    mock_configure_interface.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure Interface"
    }
    
    result = compliance_interface(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    assert any("Mismatched Interface State" in r for r in result["initial_issues"])
    assert any("Failed To Configure Interface" in r for r in result["actions_taken"])
    assert any("Failed To Remediate Interface Configuration" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value 

@patch("src.compliance.switching.interface.compliance.DRY_RUN", True)
@patch("src.compliance.switching.interface.compliance.configure_interface")
@patch("src.compliance.switching.interface.compliance.build_interface")
@patch("src.compliance.switching.interface.compliance.check_interface")
def test_compliance_interface_dry_run(
        mock_check_interface, mock_build_interface, mock_configure_interface,
        mock_sesh, mock_context, mock_device_result, mock_log
    ):
    
    mock_build_interface.return_value = {}
    mock_check_interface.return_value = (False, ["Mismatched Interface State"])
    mock_configure_interface.return_value = {}
    result = compliance_interface(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_configure_interface.assert_not_called()
    assert any("Mismatched Interface State" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure Interface" in r for r in result["actions_taken"])

@patch("src.compliance.switching.interface.compliance.collect_device_state")
@patch("src.compliance.switching.interface.compliance.configure_interface")
@patch("src.compliance.switching.interface.compliance.build_interface")
@patch("src.compliance.switching.interface.compliance.check_interface")
def test_compliance_interface_post_validation_successful(
        mock_check_interface, mock_build_interface, mock_configure_interface,
        mock_collect_device_state, mock_sesh, mock_context, mock_device_result, mock_log
    ):
    
    mock_build_interface.return_value = {}
    mock_check_interface.side_effect = [(False, ["Mismatched Interface State"]),
                                        (True, [])
                                       ]
    mock_configure_interface.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Interface Configuration Successful"
    }
    mock_collect_device_state.return_value = {}

    result = compliance_interface(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_not_called()
    assert any("Mismatched Interface State" in r for r in result["initial_issues"])
    assert any("Interface Configuration Successful" in r for r in result["actions_taken"])
    assert any("Interface Configuration Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.interface.compliance.collect_device_state")
@patch("src.compliance.switching.interface.compliance.configure_interface")
@patch("src.compliance.switching.interface.compliance.build_interface")
@patch("src.compliance.switching.interface.compliance.check_interface")
def test_compliance_interface_post_validation_failed(
        mock_check_interface, mock_build_interface, mock_configure_interface,
        mock_collect_device_state, mock_sesh, mock_context, mock_device_result, mock_log
    ):
    
    mock_build_interface.return_value = {}
    mock_check_interface.side_effect = [(False, ["Mismatched Interface State"]),
                                        (False, ["Mismatched Interface State"])
                                       ]
    mock_configure_interface.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "Interface Configuration Successful"
    }
    mock_collect_device_state.return_value = {}

    result = compliance_interface(
            mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
        )

    mock_log.warning.assert_called_once()
    mock_log.info.assert_not_called()
    mock_log.error.assert_called_once()
    mock_collect_device_state.assert_called_once()
    assert any("Mismatched Interface State" in r for r in result["initial_issues"])
    assert any("Interface Configuration Successful" in r for r in result["actions_taken"])
    assert any("Mismatched Interface State" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value

def test_compliance_interface_empty(
        mock_sesh, mock_device_result, mock_log
    ):
    
    result = compliance_interface(
            mock_sesh, mock_sesh.device_ip, {"interfaces": []}, {}, mock_device_result, mock_log
        )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []