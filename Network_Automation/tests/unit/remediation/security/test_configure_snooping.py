import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.security.dhcp_snooping import configure_snooping
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
def snooping_data():
	return {
		"enabled_vlans": [10,20,30,40,50],
		"interfaces": {
			"gigabitethernet1":{
			"rate_limit": 30,
			"trusted": False
			}
		},
		"option82": False 
	}

@patch("src.remediation.security.dhcp_snooping.DRY_RUN", True)
def test_configure_snooping_dry_run(mock_conn, snooping_data, mock_log):
	result = configure_snooping(mock_conn, snooping_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "gigabitethernet1" in result["summary"]
	assert "VLANs: [10,20,30,40,50]" in result["summary"]
	mock_conn.send_config_set.assert_not_called()

@patch("src.remediation.security.dhcp_snooping.DRY_RUN", False)
def test_configure_snooping_successful(mock_conn, snooping_data, mock_log):
	result = configure_snooping(mock_conn, snooping_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "gigabitethernet1" in result["summary"]
	assert "VLANs: [10, 20, 30, 40, 50]" in result["summary"]
	assert "Rate Limit: 30" in result["summary"]
 	assert mock_conn.send_config_set.call_count == 2
 	mock_log.info.assert_called_once()

@patch("src.remediation.security.dhcp_snooping.DRY_RUN", False)
def test_configure_snooping_failed(mock_conn, snooping_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_snooping(mock_conn, snooping_data, mock_log)	
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()
