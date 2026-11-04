import pytest
from unittest.mock import MagicMock, patch
from src.compliance.switching.stp.compliance import (
    compliance_stp_global,
    compliance_stp_interfaces,
)
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
def exp_stp_global():
    return {"mode": "rapid_pvst", "vlan_priorities": {10: 32768, 20: 4096, 30: 8192}}


@pytest.fixture
def mock_context(exp_stp_global):
    return {"stp": exp_stp_global}


@pytest.fixture
def exp_stp_interfaces():
    return {  
          "interface": "gigabitethernet1",
          "stp": {
            "portfast": True,
            "bpduguard": True,
            "loop_guard": False,
            "root_guard": False,
            "bpdufilter": False,
        }
      }


@pytest.fixture
def mock_context_2(exp_stp_interfaces):
    return {"interfaces": exp_stp_interfaces}


@patch("src.compliance.switching.stp.compliance.build_stp_global")
@patch("src.compliance.switching.stp.compliance.check_stp_global")
def test_compliance_stp_global_already_compliant(
    mock_check_stp_global,
    mock_build_stp_global,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_stp_global.return_value = {}
    mock_check_stp_global.return_value = (True, [])

    result = compliance_stp_global(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any(
        "STP Global Configuration Already Compliant" in r
        for r in result["actions_taken"]
    )
    assert result["initial_issues"] == []


@patch("src.compliance.switching.stp.compliance.configure_stp_global")
@patch("src.compliance.switching.stp.compliance.build_stp_global")
@patch("src.compliance.switching.stp.compliance.check_stp_global")
def test_compliance_stp_global_non_compliant_config_successful(
    mock_check_stp_global,
    mock_build_stp_global,
    mock_configure_stp_global,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_stp_global.return_value = {}
    mock_check_stp_global.return_value = (False, ["(STP) Mismatched Bridge Priority"])
    mock_configure_stp_global.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Global Configuration Successful",
    }

    result = compliance_stp_global(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any(
        "(STP) Mismatched Bridge Priority" in r for r in result["initial_issues"]
    )
    assert any(
        "STP Global Configuration Successful" in r for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.switching.stp.compliance.configure_stp_global")
@patch("src.compliance.switching.stp.compliance.build_stp_global")
@patch("src.compliance.switching.stp.compliance.check_stp_global")
def test_compliance_stp_global_non_compliant_config_failed(
    mock_check_stp_global,
    mock_build_stp_global,
    mock_configure_stp_global,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_stp_global.return_value = {}
    mock_check_stp_global.return_value = (False, ["(STP) Mismatched Bridge Priority"])
    mock_configure_stp_global.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure STP Global",
    }

    result = compliance_stp_global(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any(
        "(STP) Mismatched Bridge Priority" in r for r in result["initial_issues"]
    )
    assert any("Failed To Configure STP Global" in r for r in result["actions_taken"])
    assert any("STP Global Remediation Failed" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@patch("src.compliance.switching.stp.compliance.DRY_RUN", True)
@patch("src.compliance.switching.stp.compliance.configure_stp_global")
@patch("src.compliance.switching.stp.compliance.build_stp_global")
@patch("src.compliance.switching.stp.compliance.check_stp_global")
def test_compliance_stp_global_dry_run(
    mock_check_stp_global,
    mock_build_stp_global,
    mock_configure_stp_global,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_stp_global.return_value = {}
    mock_check_stp_global.return_value = (False, ["(STP) Mismatched Bridge Priority"])
    mock_configure_stp_global.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Global Configuration Successful",
    }

    result = compliance_stp_global(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_stp_global.assert_not_called()
    assert any(
        "(STP) Mismatched Bridge Priority" in r for r in result["initial_issues"]
    )
    assert any(
        "[DRY_RUN] Would Configure Global STP" in r for r in result["actions_taken"]
    )


@patch("src.compliance.switching.stp.compliance.collect_device_state")
@patch("src.compliance.switching.stp.compliance.configure_stp_global")
@patch("src.compliance.switching.stp.compliance.build_stp_global")
@patch("src.compliance.switching.stp.compliance.check_stp_global")
def test_compliance_stp_global_post_validation_successful(
    mock_check_stp_global,
    mock_build_stp_global,
    mock_configure_stp_global,
    mock_collect_device_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_stp_global.return_value = {}
    mock_check_stp_global.side_effect = [
        (False, ["(STP) Mismatched Bridge Priority"]),
        (True, []),
    ]
    mock_configure_stp_global.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Global Configuration Successful",
    }
    mock_collect_device_state.return_value = {}

    result = compliance_stp_global(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_not_called()
    assert any(
        "(STP) Mismatched Bridge Priority" in r for r in result["initial_issues"]
    )
    assert any(
        "STP Global Configuration Successful" in r for r in result["actions_taken"]
    )
    assert any(
        "STP Global Configuration Post Validation Successful" in r
        for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.switching.stp.compliance.collect_device_state")
@patch("src.compliance.switching.stp.compliance.configure_stp_global")
@patch("src.compliance.switching.stp.compliance.build_stp_global")
@patch("src.compliance.switching.stp.compliance.check_stp_global")
def test_compliance_stp_global_post_validation_failed(
    mock_check_stp_global,
    mock_build_stp_global,
    mock_configure_stp_global,
    mock_collect_device_state,
    mock_sesh,
    mock_context,
    mock_device_result,
    mock_log,
):
    mock_build_stp_global.return_value = {}
    mock_check_stp_global.side_effect = [
        (False, ["(STP) Mismatched Bridge Priority"]),
        (False, ["(STP) Mismatched Bridge Priority"]),
    ]
    mock_configure_stp_global.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Global Configuration Successful",
    }
    mock_collect_device_state.return_value = {}

    result = compliance_stp_global(
        mock_sesh, mock_sesh.device_ip, mock_context, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_called_once()
    mock_log.info.assert_not_called()
    assert any(
        "(STP) Mismatched Bridge Priority" in r for r in result["initial_issues"]
    )
    assert any(
        "STP Global Configuration Successful" in r for r in result["actions_taken"]
    )
    assert any(
        "(STP) Mismatched Bridge Priority" in r for r in result["critical_issues"]
    )
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


def test_compliance_stp_global_empty(mock_sesh, mock_device_result, mock_log):
    result = compliance_stp_global(
        mock_sesh, mock_sesh.device_ip, {"stp": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []


# STP INTERFACES
@patch("src.compliance.switching.stp.compliance.build_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.check_stp_interfaces")
def test_compliance_stp_interfaces_already_compliant(
    mock_check_stp_interfaces,
    mock_build_stp_interfaces,
    mock_sesh,
    mock_context_2,
    mock_device_result,
    mock_log,
):
    mock_build_stp_interfaces.return_value = {}
    mock_check_stp_interfaces.return_value = (True, [])

    result = compliance_stp_interfaces(
        mock_sesh, mock_sesh.device_ip, mock_context_2, {}, mock_device_result, mock_log
    )

    mock_log.info.assert_called_once()
    mock_log.warning.assert_not_called()
    assert any(
        "STP Interface Configuration Already Compliant" in r
        for r in result["actions_taken"]
    )
    assert result["initial_issues"] == []


@patch("src.compliance.switching.stp.compliance.configure_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.build_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.check_stp_interfaces")
def test_compliance_stp_interfaces_non_compliant_config_successful(
    mock_check_stp_interfaces,
    mock_build_stp_interfaces,
    mock_configure_stp_interfaces,
    mock_sesh,
    mock_context_2,
    mock_device_result,
    mock_log,
):
    mock_build_stp_interfaces.return_value = {}
    mock_check_stp_interfaces.return_value = (False, ["(STP) Mismatched STP Mode"])
    mock_configure_stp_interfaces.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Interfaces Configuration Successful",
    }
    result = compliance_stp_interfaces(
        mock_sesh, mock_sesh.device_ip, mock_context_2, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(STP) Mismatched STP Mode" in r for r in result["initial_issues"])
    assert any(
        "STP Interfaces Configuration Successful" in r for r in result["actions_taken"]
    )
    assert result["status"] == OperationalStatus.SUCCESS.value


@patch("src.compliance.switching.stp.compliance.configure_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.build_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.check_stp_interfaces")
def test_compliance_stp_interfaces_non_compliant_config_failed(
    mock_check_stp_interfaces,
    mock_build_stp_interfaces,
    mock_configure_stp_interfaces,
    mock_sesh,
    mock_context_2,
    mock_device_result,
    mock_log,
):
    mock_build_stp_interfaces.return_value = {}
    mock_check_stp_interfaces.return_value = (False, ["(STP) Mismatched STP Mode"])
    mock_configure_stp_interfaces.return_value = {
        "status": OperationalStatus.FAILED_CONFIG.value,
        "summary": "Failed To Configure STP Interfaces",
    }
    result = compliance_stp_interfaces(
        mock_sesh, mock_sesh.device_ip, mock_context_2, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    assert any("(STP) Mismatched STP Mode" in r for r in result["initial_issues"])
    assert any("Failed To Configure STP Interfaces" in r for r in result["actions_taken"])
    assert any("STP Interface Remediation Failed" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_CONFIG.value 

@patch("src.compliance.switching.stp.compliance.DRY_RUN", True)
@patch("src.compliance.switching.stp.compliance.configure_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.build_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.check_stp_interfaces")
def test_compliance_stp_interfaces_dry_run(
    mock_check_stp_interfaces,
    mock_build_stp_interfaces,
    mock_configure_stp_interfaces,
    mock_sesh,
    mock_context_2,
    mock_device_result,
    mock_log,
):
    mock_build_stp_interfaces.return_value = {}
    mock_check_stp_interfaces.return_value = (False, ["(STP) Mismatched STP Mode"])
    mock_configure_stp_interfaces.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Interfaces Configuration Successful",
    }
    result = compliance_stp_interfaces(
        mock_sesh, mock_sesh.device_ip, mock_context_2, {}, mock_device_result, mock_log
    )

    mock_log.warning.assert_called_once()
    mock_configure_stp_interfaces.assert_not_called()
    assert any("(STP) Mismatched STP Mode" in r for r in result["initial_issues"])
    assert any("[DRY_RUN] Would Configure STP Interfaces" in r for r in result["actions_taken"])

@patch("src.compliance.switching.stp.compliance.collect_device_state")
@patch("src.compliance.switching.stp.compliance.configure_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.build_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.check_stp_interfaces")
def test_compliance_stp_interfaces_post_validation_successful(
    mock_check_stp_interfaces,
    mock_build_stp_interfaces,
    mock_configure_stp_interfaces,
    mock_collect_device_state,
    mock_sesh,
    mock_context_2,
    mock_device_result,
    mock_log,
):
    mock_build_stp_interfaces.return_value = {}
    mock_check_stp_interfaces.side_effect = [(False, ["(STP) Mismatched STP Mode"]), 
                                             (True, [])
                                            ]
    mock_configure_stp_interfaces.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Interfaces Configuration Successful",
    }
    mock_collect_device_state.return_value = {}
    
    result = compliance_stp_interfaces(
        mock_sesh, mock_sesh.device_ip, mock_context_2, {}, mock_device_result, mock_log
      )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_not_called()
    assert any("(STP) Mismatched STP Mode" in r for r in result["initial_issues"])
    assert any("STP Interfaces Configuration Successful" in r for r in result["actions_taken"])
    assert any("STP Interface Configuration Post Validation Successful" in r for r in result["actions_taken"])
    assert result["status"] == OperationalStatus.SUCCESS.value 

@patch("src.compliance.switching.stp.compliance.collect_device_state")
@patch("src.compliance.switching.stp.compliance.configure_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.build_stp_interfaces")
@patch("src.compliance.switching.stp.compliance.check_stp_interfaces")
def test_compliance_stp_interfaces_post_validation_failed(
    mock_check_stp_interfaces,
    mock_build_stp_interfaces,
    mock_configure_stp_interfaces,
    mock_collect_device_state,
    mock_sesh,
    mock_context_2,
    mock_device_result,
    mock_log,
):
    mock_build_stp_interfaces.return_value = {}
    mock_check_stp_interfaces.side_effect = [(False, ["(STP) Mismatched STP Mode"]), 
                                             (False, ["(STP) Mismatched STP Mode"])
                                            ]
    mock_configure_stp_interfaces.return_value = {
        "status": OperationalStatus.SUCCESS.value,
        "summary": "STP Interfaces Configuration Successful",
    }
    mock_collect_device_state.return_value = {}
    
    result = compliance_stp_interfaces(
        mock_sesh, mock_sesh.device_ip, mock_context_2, {}, mock_device_result, mock_log
      )

    mock_log.warning.assert_called_once()
    mock_collect_device_state.assert_called_once()
    mock_log.error.assert_called_once()
    assert any("(STP) Mismatched STP Mode" in r for r in result["initial_issues"])
    assert any("STP Interfaces Configuration Successful" in r for r in result["actions_taken"])
    assert any("(STP) Mismatched STP Mode" in r for r in result["critical_issues"])
    assert result["status"] == OperationalStatus.FAILED_VALIDATION.value 

def test_compliance_stp_interfaces_empty(
        mock_sesh, mock_device_result, mock_log
    ): 
    
    result = compliance_stp_interfaces(
            mock_sesh, mock_sesh.device_ip, {"interfaces": {}}, {}, mock_device_result, mock_log
        )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []