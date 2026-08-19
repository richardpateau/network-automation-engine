import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.switching.etherchannel import configure_etherchannel
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
def etherchannel_data():
	return {
		"enabled": True,
		"groups": {
			2: {
				"mode": "active", 
				"interfaces": ["gigabitethernet1", "gigabitethernet2", "gigabitethernet3"],
				"description": "link to R1",
				"switchport_mode": "trunk",
				"type": "lacp"
			}
		}
	}

@patch("src.remediation.switching.etherchannel.DRY_RUN", True)
def test_configure_etherchannel_dry_run(mock_conn, etherchannel_data, mock_log):
	result = configure_etherchannel(mock_conn, etherchannel_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["status"]
	assert "Group #: 2" in result["status"]
	assert "Mode: active" in result["status"]
	assert "Type: lacp" in result["status"]
	mock_conn.send_config_set.assert_not_called() 

@patch("src.remediation.switching.etherchannel.DRY_RUN", False)
def test_configure_etherchannel_successful(mock_conn, etherchannel_data, mock_log):
	result = configure_etherchannel(mock_conn, etherchannel_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "Group #: 2" in result["status"]
	assert "Mode: active" in result["status"]
	assert "Type: lacp" in result["status"]
	mock_conn.send_config_set.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.switching.etherchannel.DRY_RUN", False)
def test_configure_etherchannel_successful(mock_conn, etherchannel_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_etherchannel(mock_conn, etherchannel_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value 
	