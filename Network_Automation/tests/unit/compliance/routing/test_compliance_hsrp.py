import pytest 
from unittest.mock import MagicMock, patch 
from src.compliance.routing.hsrp import compliance_hsrp 
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
def exp_hsrp():
	return [
		{
			"group": 10,
			"interface": "GigabitEthernet1",
			"router_vlan": 10,
			"version": 2,
			"vip": "192.168.10.1"
		}
	]
@pytest.fixture
def mock_context(exp_hsrp): 
	return {"hsrp": exp_hsrp}

@pytest.fixture
def actual_hsrp():
    return {
        "gigabitethernet1": {
            "group": 10,
            "priority": 110,
            "version": 2,
            "vip": "192.168.10.1"
        }
    }

@patch("src.compliance.routing.hsrp.compliance.build_hsrp")
@patch("src.compliance.routing.hsrp.compliance.check_hsrp")
def test_compliance_hsrp_already_compliant(
		mock_build_hsrp, mock_check_hsrp, mock_sesh, mock_context, mock_device_result,mock_log
	):
	
	mock_build_hsrp.return_value = {}
	mock_check_hsrp.return_value = (True, [])

	result = compliance_hsrp(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
		)

	assert result["initial_issues"] == []
	assert any("Already Compliant" in a for a in result["actions_taken"])
	mock_log.info.assert_called()
	mock_log.warning.assert_not_called()

@patch("src.compliance.routing.hsrp.compliance.configure_hsrp")
@patch("src.compliance.routing.hsrp.compliance.build_hsrp")
@patch("src.compliance.routing.hsrp.compliance.check_hsrp")
def test_compliance_hsrp_non_compliant_and_config_successful(
		mock_check_hsrp, mock_build_hsrp, mock_configure_hsrp, mock_sesh,
	    mock_context, mock_device_result, mock_log
	):
	mock_build_hsrp.return_value = {}
	mock_check_hsrp.return_value = (False, ["(HSRP) Mismatched Virtual IP"])
	mock_configure_hsrp.return_value = {
		"status": "SUCCESS", 
		"summary": "HSRP Configuration Successful"
	}

	result = compliance_hsrp(
			mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
		)

	mock_configure_hsrp.assert_called_once()
	mock_log.warning.assert_called()
	assert "(HSRP) Mismatched Virtual IP" in result["initial_issues"]
	assert "HSRP Configuration Configuration Successful" in result["actions_taken"]
	assert result["status"] == OperationalStatus.SUCCESS.value

@patch("src.compliance.routing.hsrp.compliance.configure_hsrp")
@patch("src.compliance.routing.hsrp.compliance.build_hsrp")
@patch("src.compliance.routing.hsrp.compliance.check_hsrp")

def test_compliance_hsrp_configuration_failed(
	mock_check_hsrp, mock_build_hsrp, mock_configure_hsrp, mock_sesh, 
	mock_context, mock_device_result, mock_log
	):
	
	mock_build_hsrp.return_value = {}
	mock_check_hsrp.return_value = (False, ["(HSRP) Mismatched Virtual IP"])
	mock_configure_hsrp.return_value = {
		"status": OperationalStatus.FAILED_CONFIG.value,
		"summary": "HSRP Configuration Failed"
	}

	result = compliance_hsrp(
		mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
	)

	mock_log.warning.assert_called_once()
 	mock_configure_hsrp.assert_called_once()
	assert result["status"] == OperationalStatus.FAILED_CONFIG.value
	assert any("HSRP Configuration Failed" in r for r in result["actions_taken"])
	assert any("(HSRP) Mismatched Virtual IP" in r for r in result["initial_issues"])
	assert any("Failed to Remediate HSRP" in r for r in result["critical_issues"])

@patch("src.compliance.routing.hsrp.compliance.collect_netconf_state")
@patch("src.compliance.routing.hsrp.compliance.configure_hsrp")
@patch("src.compliance.routing.hsrp.compliance.build_hsrp")
@patch("src.compliance.routing.hsrp.compliance.check_hsrp")
def test_compliance_hsrp_post_validation_successful(
	mock_check_hsrp, mock_build_hsrp, mock_configure_hsrp, mock_collect_netconf_state, 
	mock_sesh, mock_context, mock_device_result, mock_log
	):
	
	mock_build_hsrp.return_value = {}
	mock_check_hsrp.side_effect = [(False, ["(HSRP) Mismatched Virtual IP"]), (True, [])]
	mock_configure_hsrp.return_value = {
		"status": OperationalStatus.SUCCESS.value,
		"summary": "HSRP Configuration Successful"
	}
	mock_collect_netconf_state.return_value = {}
	result = compliance_hsrp(
		mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
	)

	mock_log.warning.assert_called_once()
	assert any("(HSRP) Mismatched Virtual IP" in r for r in result["initial_issues"])
	assert any("Post Validation Successful" in a for a in result["actions_taken"])
    mock_log.error.assert_not_called()
    mock_collect_netconf_state.assert_called_once()
    mock_log.info.assert_called_once()
	assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.routing.hsrp.compliance.collect_netconf_state")
@patch("src.compliance.routing.hsrp.compliance.configure_hsrp")
@patch("src.compliance.routing.hsrp.compliance.build_hsrp")
@patch("src.compliance.routing.hsrp.compliance.check_hsrp")

def test_compliance_hsrp_post_validation_failed(
	mock_check_hsrp, mock_build_hsrp, mock_configure_hsrp, mock_collect_netconf_state, 
	mock_sesh, mock_context, mock_device_result, mock_log
	):
	
	mock_build_hsrp.return_value = {}
	mock_check_hsrp.side_effect = [(False, ["(HSRP) Mismatched Virtual IP"]), 
									(False, ["(HSRP) Post Validation Failed"])
								  ]
	mock_configure_hsrp.return_value = {
			"status": OperationalStatus.SUCCESS.value,
		    "summary": "HSRP Configuration Successful"
	}
	mock_collect_netconf_state.return_value = {}

	result = compliance_hsrp(
		mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
	)

	mock_log.warning.assert_called_once()
	mock_log.error.assert_called_once()
	mock_log.info.assert_not_called()
	mock_collect_netconf_state.assert_called_once()
	assert result["status"] == OperationalStatus.FAILED_VALIDATION.value
	assert any("(HSRP) Post Validation Failed" in r for r in result["critical_issues"])
	assert any("(HSRP) Mismatched Virtual IP" in r for r in result["initial_issues"])
	assert any("HSRP Configuration Successful" in r for r in result["actions_taken"])

@patch("src.compliance.routing.hsrp.compliance.build_hsrp")
def test_compliance_hsrp_empty(
		mock_build_hsrp, mock_sesh, mock_log, mock_device_result
	):
	
	mock_build_hsrp.return_value = {}

	result = compliance_hsrp(
		  mock_sesh, "192.168.1.1", {"hsrp": []}, {}, mock_device_result, mock_log
		)

	assert result["actions_taken"] == []
	assert result["initial_issues"] == []
	assert result["critical_issues"] == []
	assert result["status"] == "SUCCESS"

@patch("src.compliance.routing.hsrp.compliance.DRY_RUN", True)
@patch("src.compliance.routing.hsrp.compliance.build_hsrp")
@patch("src.compliance.routing.hsrp.compliance.check_hsrp")
@patch("src.compliance.routing.hsrp.compliance.configure_hsrp")
def test_compliance_hsrp_dry_run(
	mock_configure_hsrp, mock_check_hsrp, mock_build_hsrp, 
	mock_sesh, mock_context, mock_device_result, mock_log
	):
		
	mock_build_hsrp.return_value = {}
	mock_check_hsrp.return_value = (False, ["(HSRP) Mismatched Virtual IP"])
	mock_configure_hsrp.return_value = {}
	result = compliance_hsrp(
		mock_sesh, "192.168.1.1", mock_context, {}, mock_device_result, mock_log
	)
	
	mock_log.warning.assert_called()
	mock_configure_hsrp.assert_not_called()
	assert any("(HSRP) Mismatched Virtual IP" in r for r in result["initial_issues"])
	assert any("[DRY_RUN] Would configure HSRP" in r for r in result["actions_taken"])
