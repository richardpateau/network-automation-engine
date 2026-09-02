import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.switching.interface import configure_interface
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
def interface_data():
	return {
		"interface": "gigabitethernet1",
		"description": "link to R1",
		"should_be_up": True 
	}

@patch("src.remediation.switching.interface.DRY_RUN", True)
def test_configure_interface_dry_run(mock_conn, interface_data, mock_log): 
	result = configure_interface(mock_conn, interface_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "gigabitethernet1" in result["summary"]
	assert "True" in result["summary"]
	mock_conn.send_config_set.assert_not_called()

@patch("src.remediation.switching.interface.DRY_RUN", False)
def test_configure_interface_successful(mock_conn, interface_data, mock_log): 
	result = configure_interface(mock_conn, interface_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "Interface Status Successfully Changed" in result["summary"]
	assert "gigabitethernet1" in result["summary"]
	assert "True" in result["summary"]
	mock_conn.send_config_set.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.switching.interface.DRY_RUN", False)
def test_configure_interface_failed(mock_conn, interface_data, mock_log): 
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_interface(mock_conn, interface_data, mock_log)

	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()