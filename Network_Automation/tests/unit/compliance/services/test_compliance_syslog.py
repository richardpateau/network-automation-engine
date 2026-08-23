import pytest
from unittest.mock import MagicMock, patch
from src.compliance.services.syslog.compliance import compliance_syslog
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
        "status": "SUCCESS",
    }


@pytest.fixture
def exp_syslog():
    return {
        "hosts": ["192.168.2.1"],
        "facility": "local7",
        "trap_level": "informational",
        "source_interface": "loopback0",
        "timestamps": True,
    }


@pytest.fixture
def mock_context(exp_syslog):
    return {"syslog": exp_syslog}


def patch_for_transport(transport):
    if transport == "NETCONF":
        return {
            "build_syslog": "src.compliance.services.syslog.compliance.build_syslog_netconf",
            "check_syslog": "src.compliance.services.syslog.compliance.check_syslog",
            "configure_syslog": "src.compliance.services.syslog.compliance.configure_syslog_netconf",
            "collect_syslog_state": "src.compliance.services.syslog.compliance.collect_netconf_state",
        }
    if transport == "NETMIKO":
        return {
            "build_syslog": "src.compliance.services.syslog.compliance.build_syslog_netmiko",
            "check_syslog": "src.compliance.services.syslog.compliance.check_syslog",
            "configure_syslog": "src.compliance.services.syslog.compliance.configure_syslog_netmiko",
            "collect_syslog_state": "src.compliance.services.syslog.compliance.collect_device_state",
        }


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_syslog_already_compliant(
    transport, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_sesh.transport = transport
    patch_targets = patch_for_transport(transport)

    with patch(patch_targets["build_syslog"]) as mock_build_syslog, patch(
        patch_targets["check_syslog"]
    ) as mock_check_syslog:
        mock_build_syslog.return_value = {}
        mock_check_syslog.return_value = (True, [])

        result = compliance_syslog(
            mock_sesh,
            mock_sesh.device_ip,
            mock_context,
            {},
            mock_device_result,
            mock_log,
        )

        mock_log.info.assert_called_once()
        mock_log.warning.assert_not_called()
        assert any(
            "Syslog Configuration Already Compliant" in r
            for r in result["actions_taken"]
        )
        assert result["initial_issues"] == []


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_syslog_non_compliant_config_successful(
    transport, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_sesh.transport = transport
    patch_targets = patch_for_transport(transport)

    with patch(patch_targets["configure_syslog"]) as mock_configure_syslog, patch(
        patch_targets["build_syslog"]
    ) as mock_build_syslog, patch(patch_targets["check_syslog"]) as mock_check_syslog:
        mock_build_syslog.return_value = {}
        mock_check_syslog.return_value = (False, ["(SYSLOG) Mismatched Trap Level"])
        mock_configure_syslog.return_value = {
            "status": OperationalStatus.SUCCESS.value,
            "summary": "Syslog Configuration Successfully Configured",
        }

        result = compliance_syslog(
            mock_sesh,
            mock_sesh.device_ip,
            mock_context,
            {},
            mock_device_result,
            mock_log,
        )

        mock_log.warning.assert_called_once()
        assert any(
            "(SYSLOG) Mismatched Trap Level" in r for r in result["initial_issues"]
        )
        assert any(
            "Syslog Configuration Successfully Configured" in r
            for r in result["actions_taken"]
        )
        assert result["status"] == OperationalStatus.SUCCESS.value


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_syslog_non_compliant_config_failed(
    transport, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_sesh.transport = transport
    patch_targets = patch_for_transport(transport)

    with patch(patch_targets["configure_syslog"]) as mock_configure_syslog, patch(
        patch_targets["build_syslog"]
    ) as mock_build_syslog, patch(patch_targets["check_syslog"]) as mock_check_syslog:
        mock_build_syslog.return_value = {}
        mock_check_syslog.return_value = (False, ["(SYSLOG) Mismatched Trap Level"])
        mock_configure_syslog.return_value = {
            "status": OperationalStatus.FAILED_CONFIG.value,
            "summary": "Failed To Configure Syslog",
        }

        result = compliance_syslog(
            mock_sesh,
            mock_sesh.device_ip,
            mock_context,
            {},
            mock_device_result,
            mock_log,
        )

        mock_log.warning.assert_called_once()
        assert any(
            "(SYSLOG) Mismatched Trap Level" in r for r in result["initial_issues"]
        )
        assert any("Failed To Configure Syslog" in r for r in result["actions_taken"])
        assert any("Failed To Remediate Syslog" in r for r in result["critical_issues"])
        assert result["status"] == OperationalStatus.FAILED_CONFIG.value


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_syslog_dry_run(
    transport, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_sesh.transport = transport
    patch_targets = patch_for_transport(transport)

    with patch("src.compliance.services.syslog.compliance.DRY_RUN", True), patch(
        patch_targets["configure_syslog"]
    ) as mock_configure_syslog, patch(
        patch_targets["build_syslog"]
    ) as mock_build_syslog, patch(
        patch_targets["check_syslog"]
    ) as mock_check_syslog:
        mock_build_syslog.return_value = {}
        mock_check_syslog.return_value = (False, ["(SYSLOG) Mismatched Trap Level"])
        mock_configure_syslog.return_value = {}

        result = compliance_syslog(
            mock_sesh,
            mock_sesh.device_ip,
            mock_context,
            {},
            mock_device_result,
            mock_log,
        )

        mock_log.warning.assert_called_once()
        mock_configure_syslog.assert_not_called()
        assert any(
            "(SYSLOG) Mismatched Trap Level" in r for r in result["initial_issues"]
        )
        assert any(
            "[DRY_RUN] Would Configure Syslog" in r for r in result["actions_taken"]
        )


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_syslog_post_validation_successful(
    transport, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_sesh.transport = transport
    patch_targets = patch_for_transport(transport)

    with patch(
        patch_targets["collect_syslog_state"]
    ) as mock_collect_syslog_state, patch(
        patch_targets["configure_syslog"]
    ) as mock_configure_syslog, patch(
        patch_targets["build_syslog"]
    ) as mock_build_syslog, patch(
        patch_targets["check_syslog"]
    ) as mock_check_syslog:
        mock_build_syslog.return_value = {}
        mock_check_syslog.side_effect = [
            (False, ["(SYSLOG) Mismatched Trap Level"]),
            (True, []),
        ]
        mock_configure_syslog.return_value = {
            "status": OperationalStatus.SUCCESS.value,
            "summary": "Syslog Configuration Successfully Configured",
        }
        mock_collect_syslog_state.return_value = {}

        result = compliance_syslog(
            mock_sesh,
            mock_sesh.device_ip,
            mock_context,
            {},
            mock_device_result,
            mock_log,
        )

        mock_log.warning.assert_called_once()
        mock_log.error.assert_not_called()
        mock_log.info.assert_called()
        mock_collect_syslog_state.assert_called_once()
        assert any(
            "(SYSLOG) Mismatched Trap Level" in r for r in result["initial_issues"]
        )
        assert any(
            "Syslog Configuration Successfully Configured" in r
            for r in result["actions_taken"]
        )
        assert any(
            "Syslog Configuration Post Validation Successful" in r
            for r in result["actions_taken"]
        )
        assert result["status"] == OperationalStatus.SUCCESS.value


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_syslog_post_validation_failed(
    transport, mock_sesh, mock_context, mock_device_result, mock_log
):
    mock_sesh.transport = transport
    patch_targets = patch_for_transport(transport)

    with patch(
        patch_targets["collect_syslog_state"]
    ) as mock_collect_syslog_state, patch(
        patch_targets["configure_syslog"]
    ) as mock_configure_syslog, patch(
        patch_targets["build_syslog"]
    ) as mock_build_syslog, patch(
        patch_targets["check_syslog"]
    ) as mock_check_syslog:
        mock_build_syslog.return_value = {}
        mock_check_syslog.side_effect = [
            (False, ["(SYSLOG) Mismatched Trap Level"]),
            (False, ["(SYSLOG) Mismatched Trap Level"]),
        ]
        mock_configure_syslog.return_value = {
            "status": OperationalStatus.SUCCESS.value,
            "summary": "Syslog Configuration Successfully Configured",
        }
        mock_collect_syslog_state.return_value = {}

        result = compliance_syslog(
            mock_sesh,
            mock_sesh.device_ip,
            mock_context,
            {},
            mock_device_result,
            mock_log,
        )

        mock_log.warning.assert_called_once()
        mock_log.error.assert_called_once()
        mock_collect_syslog_state.assert_called_once()
        assert any(
            "(SYSLOG) Mismatched Trap Level" in r for r in result["initial_issues"]
        )
        assert any(
            "Syslog Configuration Successfully Configured" in r
            for r in result["actions_taken"]
        )
        assert any(
            "(SYSLOG) Mismatched Trap Level" in r for r in result["critical_issues"]
        )
        assert result["status"] == OperationalStatus.FAILED_VALIDATION.value


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_compliance_syslog_empty(transport, mock_sesh, mock_device_result, mock_log):
    mock_sesh.transport = transport

    result = compliance_syslog(
        mock_sesh, mock_sesh.device_ip, {"syslog": {}}, {}, mock_device_result, mock_log
    )

    assert result["initial_issues"] == []
    assert result["actions_taken"] == []
