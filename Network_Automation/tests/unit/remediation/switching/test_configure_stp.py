import pytest
from unittest.mock import MagicMock, patch
from src.remediation.switching.stp import configure_stp_global, configure_stp_interfaces
from src.core.enums import OperationalStatus


@pytest.fixture
def mock_conn():
    conn = MagicMock()
    conn.device_ip = "192.168.1.1"
    conn.transport = "NETMIKO"
    return conn


@pytest.fixture
def mock_log():
    return MagicMock()


@pytest.fixture
def stp_data():
    return {
        "mode": "rapid-pvst",
        "vlan_priorities": {
            10: 32768,
            20: 4096,
            30: 28672,
            40: 24576

        }
    }


@pytest.fixture
def stp_interface_data():
    return {
        "interface": "gigabitethernet1",
        "stp": {
            "portfast": True,
            "bpdu_guard": True,
            "root_guard": True,
            "loop_guard": False,
            "bpdu_filter": False
        }
    }


@patch("src.remediation.switching.stp.DRY_RUN", True)
def test_configure_stp_global_dry_run(mock_conn, stp_data, mock_log):
    result = configure_stp_global(mock_conn, stp_data, mock_log)

    assert result["status"] == OperationalStatus.DRY_RUN.value
    assert "DRY_RUN" in result["summary"]
    assert "rapid-pvst" in result["summary"]
    assert "VLAN: 10 Priority: 32768" in result["summary"]
    mock_conn.send_config_set.assert_not_called()


@patch("src.remediation.switching.stp.DRY_RUN", False)
def test_configure_stp_global_successful(mock_conn, stp_data, mock_log):
    result = configure_stp_global(mock_conn, stp_data, mock_log)

    assert result["status"] == OperationalStatus.SUCCESS.value
    assert "STP Successfully Configured" in result["summary"]
    assert "rapid-pvst" in result["summary"]


    assert "VLAN: 10 Priority: 32768" in result["summary"]
    mock_conn.send_config_set.assert_called_once()
    mock_log.info.assert_called_once()


@patch("src.remediation.switching.stp.DRY_RUN", False)
def test_configure_stp_global_exception(mock_conn, stp_data, mock_log):
    mock_conn.send_config_set.side_effect = Exception("Connection lost")
    result = configure_stp_global(mock_conn, stp_data, mock_log)

    assert result["status"] == OperationalStatus.ERROR.value
    assert "error" in result
    assert "Connection lost" in result["error"]
    mock_log.error.assert_called_once()


@patch("src.remediation.switching.stp.DRY_RUN", True)
def test_configure_stp_interface_dry_run(mock_conn, stp_interface_data, mock_log):
    result = configure_stp_interfaces(mock_conn, stp_interface_data, mock_log)

    assert result["status"] == OperationalStatus.DRY_RUN.value
    assert "DRY_RUN" in result["summary"]
    assert "Would Configure STP Interface Feature" in result["summary"]
    assert "gigabitethernet1" in result["summary"]
    mock_conn.send_config_set.assert_not_called()


@patch("src.remediation.switching.stp.DRY_RUN", False)
def test_configure_stp_interface_successful(mock_conn, stp_interface_data, mock_log):
    result = configure_stp_interfaces(mock_conn, stp_interface_data, mock_log)

    assert result["status"] == OperationalStatus.SUCCESS.value
    assert "STP Interface Feature Successfully Configured" in result["summary"]
    assert "gigabitethernet1" in result["summary"]
    mock_conn.send_config_set.assert_called_once()
    mock_log.info.assert_called_once()


@patch("src.remediation.switching.stp.DRY_RUN", False)
def test_configure_stp_interface_exception(mock_conn, stp_interface_data, mock_log):
    mock_conn.send_config_set.side_effect = Exception("Connection lost")


    result = configure_stp_interfaces(mock_conn, stp_interface_data, mock_log)
    assert result["status"] == OperationalStatus.ERROR.value
    assert "error" in result
    assert "Connection lost" in result["error"]
    mock_log.error.assert_called_once()
