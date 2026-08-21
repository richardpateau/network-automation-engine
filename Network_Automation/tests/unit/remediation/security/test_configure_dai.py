import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.security.dai import configure_dai
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
def dai_data():
	return {
		"arp_inspection": True, 
		"enabled_vlans": [10,20,30,40,50],
		"interfaces": {
			"gigabitethernet1": {
			"rate_limt": 20,
			"trusted": False
			}
		},
		"log_buffer": {
			"enabled": True,
			"entries": 1024
		}
	}

@patch("src.remediation.security.dai.DRY_RUN", True)
def test_configure_dai_dry_run(mock_conn, dai_data, mock_log): 
	result = configure_dai(mock_conn, dai_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "VLANs: [10, 20, 30, 40, 50]" in result["summary"]
	assert "Interface: gigabitethernet1" in result["summary"
	mock_conn.
 
@patch("src.remediation.security.dai.DRY_RUN", False)
def test_configure_dai_successful(mock_conn, dai_data, mock_log): 
	result = configure_dai(mock_conn, dai_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value


@patch("src.remediation.security.dai.DRY_RUN", False)
def test_configure_dai_failed(mock_conn, dai_data, mock_log): 
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_dai(mock_conn, snooping_data, mock_log)	
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()
