import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.security.port_security import configure_psecurity
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
def port_security_data():
	return {
		"interfaces": {
			"gigabitethernet1": {
				"enabled": True,
				"maximum": 2,
				"violation": "restrict",
				"sticky": True,
				"mac_addresses": []
			}
		}
	}

@patch("src.remediation.security.port_security.DRY_RUN", True)
def test_configure_port_security_dry_run(mock_conn, port_security_data, mock_log):
	result = configure_psecurity(mock_conn, port_security_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "Interface: gigabitethernet1" in result["summary"]
	assert "Maximum: 2" in result["summary"]
	mock_conn.send_config_set.assert_not_called()

@patch("src.remediation.security.port_security.DRY_RUN", False)
def test_configure_port_security_successful(mock_conn, port_security_data, mock_log):
	result = configure_psecurity(mock_conn, port_security_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "Interface: gigabitethernet1" in result["summary"]
	assert "Maximum: 2" in result["summary"]
	assert "Sticky: True" in result["summary"] 
	mock_conn.send_config_set.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.security.port_security.DRY_RUN", False)
def test_configure_port_security_failed(mock_conn, port_security_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_psecurity(mock_conn, port_security_data, mock_log)	
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()