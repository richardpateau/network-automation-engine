import pytest
from unittest.mock import MagicMock, patch
from src.compliance.services.cdp.compliance import compliance_cdp
from src.core.enums import OperationalStatus

TRANSPORTS = ["NETCONF", "NETMIKO"] 

@pytest.fixture 
def mock_sesh():
	sesh = MagicMock()
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
		"status": "SUCCESS"
	}

@pytest.fixture
def exp_cdp():
	return {
		"enabled": True,
		"timer": 60,
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled":True},
			"gigabitethernet2": {"enabled":False}
		}
	}

@pytest.fixture
def mock_context(exp_cdp): 
	return {"cdp": exp_cdp}

def patch_for_transport(transport): 
	if transport == "NETCONF": 
		return {
			"build_cdp": "src.compliance.services.cdp.compliance.build_cdp_netconf",
			"check_cdp": "src.compliance.services.cdp.compliance.check_cdp",
			"configure_cdp": "src.compliance.services.cdp.compliance.configure_cdp_netconf",
			"collect_cdp_state": "src.compliance.services.cdp.compliance.collect_netconf_state"
		}

	if transport == "NETMIKO": 
		return {
			"build_cdp": "src.compliance.services.cdp.compliance.build_cdp_netmiko",
			"check_cdp": "src.compliance.services.cdp.compliance.check_cdp",
			"configure_cdp": "src.compliance.services.cdp.compliance.configure_cdp_netmiko",
			"collect_cdp_state": "src.compliance.services.cdp.compliance.collect_device_state"
		}

@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_cdp_already_compliant(
		transport, mock_sesh, mock_context, mock_device_result, mock_log
	): 
	
	mock_sesh.transport = transport 
	patch_transport = patch_for_transport(transport)

	with patch(patch_transport["build_cdp"]) as mock_build_cdp,\
		 patch(patch_transport["check_cdp"]) as mock_check_cdp: 

		mock_build_cdp.return_value = {}
		mock_check_cdp.return_value = (True, [])

		result = compliance_cdp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			 )

		mock_log.info.assert_called_once()
		mock_log.error.assert_not_called()
		assert any("CDP Configuration Already Compliant" in r for r in result["actions_taken"])
		assert result["initial_issues"] == []


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_cdp_non_compliant_config_successful(
		transport, mock_sesh, mock_context, mock_device_result, mock_log
	): 
	
	mock_sesh.transport = transport 
	patch_transport = patch_for_transport(transport)

	with (patch(patch_transport["collect_cdp_state"]) as mock_collect_device_state,\
		 patch(patch_transport["configure_cdp"]) as mock_configure_cdp,\
		 patch(patch_transport["build_cdp"]) as mock_build_cdp,\
		 patch(patch_transport["check_cdp"]) as mock_check_cdp):

		mock_build_cdp.return_value = {}
		mock_check_cdp.side_effect = [(False, ["(CDP) Timer Mismatch"]), (True, [])]
		mock_configure_cdp.return_value = {
			"status": OperationalStatus.SUCCESS.value,
			"summary": "CDP Successfully Configured"
		}
		mock_collect_device_state.return_value = {}
		result = compliance_cdp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			 )

		mock_log.warning.assert_called_once()
		assert any("(CDP) Timer Mismatch" in r for r in result["initial_issues"])
		assert any("CDP Successfully Configured" in r for r in result["actions_taken"])
		assert result["status"] == OperationalStatus.SUCCESS.value 

@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_cdp_non_compliant_config_failed(
		transport, mock_sesh, mock_context, mock_device_result, mock_log
	): 
	
	mock_sesh.transport = transport 
	patch_transport = patch_for_transport(transport)

	with patch(patch_transport["configure_cdp"]) as mock_configure_cdp,\
		 patch(patch_transport["build_cdp"]) as mock_build_cdp,\
		 patch(patch_transport["check_cdp"]) as mock_check_cdp: 

		mock_build_cdp.return_value = {}
		mock_check_cdp.return_value = (False, ["(CDP) Timer Mismatch"])
		mock_configure_cdp.return_value = {
			"status": OperationalStatus.FAILED_CONFIG.value,
			"summary": "Failed To Configure CDP"
		}

		result = compliance_cdp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			 )

		mock_log.warning.assert_called_once()
		assert any("(CDP) Timer Mismatch" in r for r in result["initial_issues"])
		assert any("Failed To Configure CDP" in r for r in result["actions_taken"])
		assert any("CDP Configuration Remediation Failed" in r for r in result["critical_issues"])
		assert result["status"] == OperationalStatus.FAILED_CONFIG.value

@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_cdp_dry_run(
		transport, mock_sesh, mock_context, mock_device_result, mock_log
	): 
	
	mock_sesh.transport = transport 
	patch_transport = patch_for_transport(transport)

	with patch("src.compliance.services.cdp.compliance.DRY_RUN", True),\
	     patch(patch_transport["configure_cdp"]) as mock_configure_cdp,\
		 patch(patch_transport["build_cdp"]) as mock_build_cdp,\
		 patch(patch_transport["check_cdp"]) as mock_check_cdp: 

		mock_build_cdp.return_value = {}
		mock_check_cdp.return_value = (False, ["(CDP) Timer Mismatch"])
		mock_configure_cdp.return_value = {}

		result = compliance_cdp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			 )

		mock_log.warning.assert_called_once()
		mock_configure_cdp.assert_not_called()
		mock_log.info.assert_not_called()
		assert any("(CDP) Timer Mismatch" in r for r in result["initial_issues"])
		assert any("[DRY_RUN] Would Configure CDP" in r for r in result["actions_taken"])


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_cdp_post_validation_successful(
		transport, mock_sesh, mock_context, mock_device_result, mock_log
	): 
	
	mock_sesh.transport = transport 
	patch_transport = patch_for_transport(transport)

	with patch(patch_transport["collect_cdp_state"]) as mock_collect_cdp_state,\
		 patch(patch_transport["configure_cdp"]) as mock_configure_cdp,\
		 patch(patch_transport["build_cdp"]) as mock_build_cdp,\
		 patch(patch_transport["check_cdp"]) as mock_check_cdp: 

		mock_build_cdp.return_value = {}
		mock_check_cdp.side_effect = [(False, ["(CDP) Timer Mismatch"]),
									  (True, [])
									 ]
		mock_configure_cdp.return_value = {
			"status": OperationalStatus.SUCCESS.value,
			"summary": "CDP Successfully Configured"
		}
		mock_collect_cdp_state.return_value = {}

		result = compliance_cdp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			 )

		mock_log.warning.assert_called_once()
		mock_collect_cdp_state.assert_called_once()
		mock_log.error.assert_not_called()
		assert any("(CDP) Timer Mismatch" in r for r in result["initial_issues"])
		assert any("CDP Successfully Configured" in r for r in result["actions_taken"])
		assert any("CDP Configuration Post Validation Successful" in r for r in result["actions_taken"])
		assert result["status"] == OperationalStatus.SUCCESS.value 

@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_cdp_post_validation_failed(
		transport, mock_sesh, mock_context, mock_device_result, mock_log
	): 
	
	mock_sesh.transport = transport 
	patch_transport = patch_for_transport(transport)

	with patch(patch_transport["collect_cdp_state"]) as mock_collect_cdp_state,\
		 patch(patch_transport["configure_cdp"]) as mock_configure_cdp,\
		 patch(patch_transport["build_cdp"]) as mock_build_cdp,\
		 patch(patch_transport["check_cdp"]) as mock_check_cdp: 

		mock_build_cdp.return_value = {}
		mock_check_cdp.side_effect = [(False, ["(CDP) Timer Mismatch"]),
									  (False, ["(CDP) Timer Mismatch"])
									 ]
		mock_configure_cdp.return_value = {
			"status": OperationalStatus.SUCCESS.value,
			"summary": "CDP Successfully Configured"
		}
		mock_collect_cdp_state.return_value = {}

		result = compliance_cdp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			 )

		mock_log.warning.assert_called_once()
		mock_collect_cdp_state.assert_called_once()
		mock_log.error.assert_called_once()
		assert any("(CDP) Timer Mismatch" in r for r in result["initial_issues"])
		assert any("CDP Successfully Configured" in r for r in result["actions_taken"])
		assert any("(CDP) Timer Mismatch" in r for r in result["critical_issues"])
		assert result["status"] == OperationalStatus.FAILED_VALIDATION.value 

@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_cdp_empty(
		transport, mock_sesh, mock_context, mock_device_result, mock_log
	): 
	
	mock_sesh.transport = transport 
	patch_transport = patch_for_transport(transport)

	result = compliance_cdp(
			mock_sesh, mock_sesh.device_ip, {"cdp": {}}, {}, mock_device_result, mock_log
		)

	assert result["initial_issues"] == []
	assert result["actions_taken"] == []