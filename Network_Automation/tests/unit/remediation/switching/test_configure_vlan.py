import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.switching.vlan import configure_vlan
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
def vlan_data():
	return {
		"vlan_id": 10,
		"name": "users"
	}

@patch("src.remediation.switching.vlan.DRY_RUN", True)
def test_configure_vlan_dry_run(mock_conn, vlan_data, mock_log): 
	result = configure_vlan(mock_conn, vlan_data, mock_log)
	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "10" in result["summary"]
	assert "users" in  result["summary"]
	mock_conn.send_config_set.assert_not_called()

@patch("src.remediation.switching.vlan.DRY_RUN", False)
def test_configure_vlan_success(mock_conn, vlan_data, mock_log):
	result = configure_vlan(mock_conn, vlan_data, mock_log)
	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "summary" in result
	assert "10" in result["summary"]
	assert "users" in result["summary"]
	mock_conn.send_config_set.assert_called_once()
	mock_log.info.assert_called()


@patch("src.remediation.switching.vlan.DRY_RUN", False)
def test_configure_vlan_exception(mock_conn, vlan_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	
	result = configure_vlan(mock_conn, vlan_data, mock_log)
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()

