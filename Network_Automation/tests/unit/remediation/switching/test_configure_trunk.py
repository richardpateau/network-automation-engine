import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.switching.trunk import configure_trunk
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
def trunk_data():
	return {
		"trunk_interface": "gigabitethernet1",
		"allowed_vlans": "10,20,30"
	}

@patch("src.remediation.switching.trunk.DRY_RUN", True)
def test_configure_trunk_dry_run(mock_conn, trunk_data, mock_log): 
	result = configure_trunk(mock_conn, trunk_data, mock_log)
	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "gigabitethernet1" in result["summary"]
	assert "10,20,30" in result["summary"]
	mock_conn.send_config_set.assert_not_called()

@patch("src.remediation.switching.trunk.DRY_RUN", False)
def test_configure_trunk_successful(mock_conn, trunk_data, mock_log):
	result = configure_trunk(mock_conn, trunk_data, mock_log)
	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "gigabitethernet1" in result["summary"]
	assert "10,20,30" in result["summary"]
	mock_conn.send_config_set.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.switching.trunk.DRY_RUN", False)
def test_configure_trunk_failed(mock_conn, trunk_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	
	result = configure_trunk(mock_conn, trunk_data, mock_log)
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()