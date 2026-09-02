import pytest
from unittest.mock import MagicMock, patch
from src.compliance.services.snmp.compliance import compliance_snmp
from src.core.enums import OperationalStatus

TRANSPORT = ["NETCONF", "NETMIKO"]
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
        "status": "SUCCESS",
    }

@pytest.fixture
def exp_snmp():
	return {
		"communities": [{"snmp_name": "private", "permission": "rw"}],
		"contact": "network-team@example.com",
		"location": "new york datacenter rack 10",
		"traps": {"snmp": True, "syslog": True, "config": True}
	}

@pytest.fixture
def mock_context(exp_snmp):
	return {"snmp": exp_snmp}

def patch_transports(transport): 
	if transport == "NETCONF": 
		return {
			"build_snmp": "src.compliance.services.snmp.compliance.build_snmp_netconf",
			"check_snmp": "src.compliance.services.snmp.compliance.check_snmp",
			"configure_snmp": "src.compliance.services.snmp.compliance.configure_snmp_netconf",
			"collect_snmp_state": "src.compliance.services.snmp.compliance.collect_netconf_state"
		}
	if transport == "NETMIKO": 
		return {
			"build_snmp": "src.compliance.services.snmp.compliance.build_snmp_netmiko",
			"check_snmp": "src.compliance.services.snmp.compliance.check_snmp",
			"configure_snmp": "src.compliance.services.snmp.compliance.configure_snmp_netmiko",
			"collect_snmp_state": "src.compliance.services.snmp.compliance.collect_device_state"
		}

@pytest.mark.parametrize("transport", TRANSPORT)
def test_compliance_snmp_already_compliant(
		mock_sesh, mock_context, mock_device_result, mock_log, transport
	):
	
	mock_sesh.transport = transport
	transport_patch = patch_transports(transport)

	with patch(transport_patch["build_snmp"]) as mock_build_snmp,\
		 patch(transport_patch["check_snmp"]) as mock_check_snmp:

		mock_build_snmp.return_value = {}
		mock_check_snmp.return_value = (True, [])

		result = compliance_snmp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			)

		mock_log.info.assert_called_once()
		mock_log.warning.assert_not_called()
		assert any("SNMP Configuration Already Compliant" in r for r in result["actions_taken"])
		assert result["initial_issues"] == []

@pytest.mark.parametrize("transport", TRANSPORT)
def test_compliance_snmp_non_compliant_config_successful(
		mock_sesh, mock_context, mock_device_result, mock_log, transport
	):
	
	mock_sesh.transport = transport
	transport_patch = patch_transports(transport)

	with patch(transport_patch["collect_snmp_state"]) as mock_collect_snmp_state,\
		 patch(transport_patch["configure_snmp"]) as mock_configure_snmp,\
		 patch(transport_patch["build_snmp"]) as mock_build_snmp,\
		 patch(transport_patch["check_snmp"]) as mock_check_snmp:

		mock_build_snmp.return_value = {}
		mock_check_snmp.side_effect = [(False, ["(SNMP) Mismatched Community Permission"]),(True, [])]
		mock_configure_snmp.return_value = {
			"status": OperationalStatus.SUCCESS.value, 
			"summary": "SNMP Successfully Configured"
		}
		mock_collect_snmp_state.return_value = {}
		result = compliance_snmp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			)

		mock_log.warning.assert_called_once()
		assert any("(SNMP) Mismatched Community Permission" in r for r in result["initial_issues"])
		assert any("SNMP Successfully Configured" in r for r in result["actions_taken"])
		assert result["status"] == OperationalStatus.SUCCESS.value 

@pytest.mark.parametrize("transport", TRANSPORT)
def test_compliance_snmp_non_compliant_config_failed(
		mock_sesh, mock_context, mock_device_result, mock_log, transport
	):
	
	mock_sesh.transport = transport
	transport_patch = patch_transports(transport)

	with patch(transport_patch["configure_snmp"]) as mock_configure_snmp,\
		 patch(transport_patch["build_snmp"]) as mock_build_snmp,\
		 patch(transport_patch["check_snmp"]) as mock_check_snmp:

		mock_build_snmp.return_value = {}
		mock_check_snmp.return_value = (False, ["(SNMP) Mismatched Community Permission"])
		mock_configure_snmp.return_value = {
			"status": OperationalStatus.FAILED_CONFIG.value, 
			"summary": "Failed To Configure SNMP"
		}
		result = compliance_snmp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			)

		mock_log.warning.assert_called_once()
		assert any("(SNMP) Mismatched Community Permission" in r for r in result["initial_issues"])
		assert any("Failed To Configure SNMP" in r for r in result["actions_taken"])
		assert any("Failed To Remediate SNMP" in r for r in result["critical_issues"])
		assert result["status"] == OperationalStatus.FAILED_CONFIG.value 

@pytest.mark.parametrize("transport", TRANSPORT)
def test_compliance_snmp_dry_run(
		mock_sesh, mock_context, mock_device_result, mock_log, transport
	):
	
	mock_sesh.transport = transport
	transport_patch = patch_transports(transport)

	with patch("src.compliance.services.snmp.compliance.DRY_RUN", True),\
		 patch(transport_patch["configure_snmp"]) as mock_configure_snmp,\
		 patch(transport_patch["build_snmp"]) as mock_build_snmp,\
		 patch(transport_patch["check_snmp"]) as mock_check_snmp:

		mock_build_snmp.return_value = {}
		mock_check_snmp.return_value = (False, ["(SNMP) Mismatched Community Permission"])
		mock_configure_snmp.return_value = {}

		result = compliance_snmp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			)
	
		
		mock_log.warning.assert_called_once()
		mock_configure_snmp.assert_not_called()
		assert any("(SNMP) Mismatched Community Permission" in r for r in result["initial_issues"])
		assert any("[DRY_RUN] Would Configure SNMP" in r for r in result["actions_taken"])

@pytest.mark.parametrize("transport", TRANSPORT)
def test_compliance_snmp_post_validation_successful(
		mock_sesh, mock_context, mock_device_result, mock_log, transport
	):
	
	mock_sesh.transport = transport
	transport_patch = patch_transports(transport)

	with patch(transport_patch["collect_snmp_state"]) as mock_collect_snmp_state,\
		 patch(transport_patch["configure_snmp"]) as mock_configure_snmp,\
		 patch(transport_patch["build_snmp"]) as mock_build_snmp,\
		 patch(transport_patch["check_snmp"]) as mock_check_snmp:

		mock_build_snmp.return_value = {}
		mock_check_snmp.side_effect = [(False, ["(SNMP) Mismatched Community Permission"]),
									   (True, [])
									  ]
		mock_configure_snmp.return_value = {
			"status": OperationalStatus.SUCCESS.value, 
			"summary": "SNMP Successfully Configured"
		}
		mock_collect_snmp_state.return_value = {}
		
		result = compliance_snmp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			)
		
		mock_log.warning.assert_called_once()
		mock_log.error.assert_not_called()
		mock_collect_snmp_state.assert_called_once()
		assert any("(SNMP) Mismatched Community Permission" in r for r in result["initial_issues"])
		assert any("SNMP Successfully Configured" in r for r in result["actions_taken"])
		assert any("SNMP Configuration Post Validation Successful" in r for r in result["actions_taken"])
		assert result["status"] == OperationalStatus.SUCCESS.value 

@pytest.mark.parametrize("transport", TRANSPORT)
def test_compliance_snmp_post_validation_failed(
		mock_sesh, mock_context, mock_device_result, mock_log, transport
	):
	
	mock_sesh.transport = transport
	transport_patch = patch_transports(transport)

	with patch(transport_patch["collect_snmp_state"]) as mock_collect_snmp_state,\
		 patch(transport_patch["configure_snmp"]) as mock_configure_snmp,\
		 patch(transport_patch["build_snmp"]) as mock_build_snmp,\
		 patch(transport_patch["check_snmp"]) as mock_check_snmp:

		mock_build_snmp.return_value = {}
		mock_check_snmp.side_effect = [(False, ["(SNMP) Mismatched Community Permission"]),
									   (False, ["(SNMP) Mismatched Community Permission"])
									  ]
		mock_configure_snmp.return_value = {
			"status": OperationalStatus.SUCCESS.value, 
			"summary": "SNMP Successfully Configured"
			}
		mock_collect_snmp_state.return_value = {}
		
		result = compliance_snmp(
				mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
			)

		mock_log.warning.assert_called_once()
		mock_log.info.assert_not_called()
		mock_log.error.assert_called_once()
		mock_collect_snmp_state.assert_called_once()
		assert any("(SNMP) Mismatched Community Permission" in r for r in result["initial_issues"])
		assert any("SNMP Successfully Configured" in r for r in result["actions_taken"])
		assert any("(SNMP) Mismatched Community Permission" in r for r in result["critical_issues"])
		assert result["status"] == OperationalStatus.FAILED_VALIDATION.value

@pytest.mark.parametrize("transport", TRANSPORT)
def test_compliance_snmp_empty(
		mock_sesh, mock_device_result, mock_log, transport
	):
	mock_sesh.transport = transport
	result = compliance_snmp(
			mock_sesh, mock_sesh.device_ip, {"snmp": {}}, {}, mock_device_result, mock_log
		)
	
	assert result["initial_issues"] == []
	assert result["actions_taken"] == []