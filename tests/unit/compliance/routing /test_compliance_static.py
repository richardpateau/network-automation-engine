import pytest 
from unittest.mock import MagicMock, patch 
from src.compliance.routing.static import compliance_static 
from src.core.enums import OperationalStatus

@pytest.fixture 
def mock_sesh():
	sesh = MagicMock()
	sesh.transport = "NETCONF"
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
			"status": "SUCCESS"
		}
@pytest.fixture
def exp_static():
	return [{
        "AD": 1,
        "network_address": "192.168.10.0",
        "mask": "255.255.255.0",
        "next_hop": ["192.168.1.2"],
        "exit_interface": None,
        "name": "Corporate_Route",
    	}]

@pytest.fixture
def mock_context(exp_static): 
	return {"static": exp_static}



@patch("src.compliance.routing.compliance.static_routes.compliance.build_static")
@patch("src.compliance.routing.static_routes.compliance.check_static")
def test_compliance_static_already_compliant(
		mock_check_static, mock_build_static, mock_sesh, mock_context,
		mock_device_result, mock_log
	):
	
	mock_build_static.return_value = []
	mock_check_static.return_value = (True, [])

	result = compliance_static(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, 
			mock_log
		)

    mock_log.info.assert_called_once()
	mock_log.warning.assert_not_called()
	assert result["initial_issues"] == []
	assert any("Already Compliant" in a 
			for a in result["actions_taken"]
		)
@patch("src.compliance.routing.static_routes.compliance.configure_static")
@patch("src.compliance.routing.compliance.static_routes.compliance.build_static")
@patch("src.compliance.routing.static_routes.compliance.check_static")
def test_compliance_static_non_compliant_and_config_success(
		mock_configure_static, mock_check_static, mock_build_static, mock_sesh, mock_context,
		mock_device_result, mock_log
	):
	
	mock_build_static.return_value = []
	mock_check_static.return_value = (False, ["(Static Routing) AD Mismatch"])
	mock_configure_static.return_value = {
		"status": OperationalStatus.SUCCESS.value,
		"summary": "Static Route Successfully Configured"
	}

	result = compliance_static(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, 
			mock_log
		)

	mock_configure_static.assert_called_once()
	mock_log.warning.assert_called_once()
	assert any("(Static Routing) AD Mismatch" in a for a in result["initial_issues"])
	assert any("Static Route Successfully Configured" in a for a in result["actions_taken"])
	assert result["status"] == OperationalStatus.SUCCESS.value  

@patch("src.compliance.routing.static_routes.compliance.configure_static")
@patch("src.compliance.routing.compliance.static_routes.compliance.build_static")
@patch("src.compliance.routing.static_routes.compliance.check_static")
def test_compliance_static_config_failed(
		mock_configure_static, mock_check_static, mock_build_static, mock_sesh, 
		mock_context,mock_device_result, mock_log
	):
	
	mock_build_static.return_value = []
	mock_check_static.return_value = (False, ["(Static Routing) AD Mismatch"])
	mock_configure_static.return_value = {
		"status": OperationalStatus.FAILED_CONFIG.value,
		"summary": "Failed to Configure Static Route"
	}

	result = compliance_static(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, 
			mock_log
		)

	mock_log.warning.assert_called_once()
	assert result["status"] == OperationalStatus.FAILED_CONFIG.value 
	assert any("(Static Routing) AD Mismatch" in a for a in result["initial_issues"])
	assert any("Failed to Configure Static Route" in a for a in result["actions_taken"])
	assert any("Static Routing Remediation Failed" in a for a in result["critical_issues"])

@patch("src.compliance.routing.static_routes.compliance.collect_netconf_state")
@patch("src.compliance.routing.static_routes.compliance.configure_static")
@patch("src.compliance.routing.compliance.static_routes.compliance.build_static")
@patch("src.compliance.routing.static_routes.compliance.check_static")

def test_compliance_static_post_validation_successful(
		mock_collect_netconf_state, mock_configure_static, mock_check_static, 
		mock_build_static, mock_sesh, mock_context,mock_device_result, mock_log
	):
	
	mock_build_static.return_value = []
    mock_check_static.side_effect = [(False, ["(Static Routing) AD Mismatch"]), 
    								 (True, [])
    								]
    mock_configure_static.return_value = {
    		"status": OperationalStatus.SUCCESS.value,
    		"summary": "Static Configuration Successful"
    }
    mock_collect_netconf_state.return_value = {}
    result = compliance_static(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, 
			mock_log
		)

   	mock_log.warning.assert_called_once()
   	mock_log.info.assert_called()
   	mock_log.error.assert_not_called()
   	mock_collect_netconf_state.assert_called_once()
   	assert result["status"] == OperationalStatus.SUCCESS.value
   	assert any("(Static Routing) AD Mismatch" in a for a in result["initial_issues"])
   	assert any("Static Configuration Successful" in a for a in result["actions_taken"])
   	assert any("Static Routing Configuration Post Validation Successful" in a 
   			 	for a in result["actions_taken"]
   		)

@patch("src.compliance.routing.static_routes.compliance.collect_netconf_state")
@patch("src.compliance.routing.static_routes.compliance.configure_static")
@patch("src.compliance.routing.compliance.static_routes.compliance.build_static")
@patch("src.compliance.routing.static_routes.compliance.check_static")

def test_compliance_static_post_validation_failed(
		mock_collect_netconf_state, mock_configure_static, mock_check_static, 
		mock_build_static, mock_sesh, mock_context,mock_device_result, mock_log
	):
	
	mock_build_static.return_value = []
    mock_check_static.side_effect = [(False, ["(Static Routing) AD Mismatch"]), 
    								 (False, ["(Static Routing) AD Mismatch"])
    								]
    mock_configure_static.return_value = {
    		"status": OperationalStatus.SUCCESS.value,
    		"summary": "Static Configuration Successful"
    }
    mock_collect_netconf_state.return_value = {}
    
    result = compliance_static(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, 
			mock_log
		)

    mock_log.warning.assert_called_once()
    mock_log.error.assert_called_once()
    mock_log.info.assert_not_called()
    mock_collect_netconf_state.assert_called_once()
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value
    assert any("(Static Routing) AD Mismatch" in a for a in result["initial_issues"])
    assert any("Static Configuration Successful" in a for a in result["actions_taken"])
    assert any("(Static Routing) AD Mismatch" in a for a in result["critical_issues"])

def test_compliance_static_empty(
		 mock_sesh, mock_device_result, mock_log
	):
	
	result = compliance_static(
			mock_sesh, "192.168.1.1", {"static": []}, {}, mock_device_result, 
			mock_log
		)

	assert result["actions_taken"] == []
	assert result["initial_issues"] == []

@patch("src.compliance.routing.static_routes.compliance.DRY_RUN", True)
@patch("src.compliance.routing.static_routes.compliance.configure_static")
@patch("src.compliance.routing.compliance.static_routes.compliance.build_static")
@patch("src.compliance.routing.static_routes.compliance.check_static")
def test_compliance_static_dry_run(
	mock_collect_netconf_state, mock_configure_static, mock_check_static, 
	mock_build_static, mock_sesh, mock_context,mock_device_result, mock_log
	):
	

	mock_build_static.return_value = []
	mock_check_static.return_value = (False, ["(Static Routing) AD Mismatch"])
	
	result = compliance_static(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, 
			mock_log
		)

	mock_log.warning.assert_called_once()
	mock_configure_static.assert_not_called()
	assert any("(Static Routing) AD Mismatch" in a for a in result["initial_issues"])
	assert any("[DRY_RUN] Would Configure Static Route" in a for a in result["actions_taken"])

