import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.services.snmp import configure_snmp_netmiko, configure_snmp_netconf
from src.core.enums import OperationalStatus

@pytest.fixture 
def mock_conn():
	conn = MagicMock()
	conn.device_ip = "192.168.1.1"
	conn.transport = "NETMIKO"
	return conn  

@pytest.fixture 
def mock_session():
	conn = MagicMock()
	conn.device_ip = "192.168.1.1"
	conn.transport = "NETCONF"
	return conn 

@pytest.fixture
def mock_log():
	return MagicMock()

@pytest.fixture
def snmp_data():
	return {
		"communities": [{"snmp_name": "private", "permission": "rw"},
						 {"snmp_name": "public", "permission": "ro"}
		],
		"contact": "network-team@example.com",
		"location": "new york datacenter rack 10",
		"hosts": [{
			"community_name": "private",
			"snmp_ip": "10.10.10.50",
			"snmp_version": "2c" 
		   }]
	}

@patch("src.remediation.services.snmp.DRY_RUN", True)
def test_configure_snmp_netmiko_dry_run(mock_conn, snmp_data, mock_log):
	result = configure_snmp_netmiko(mock_conn, snmp_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "private" in result["summary"]
	assert "2c" in result["summary"]
	mock_conn.send_config_set.assert_not_called()

@patch("src.remediation.services.snmp.DRY_RUN", False)
def test_configure_snmp_netmiko_successful(mock_conn, snmp_data, mock_log):
	result = configure_snmp_netmiko(mock_conn, snmp_data, mock_log)
	
	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "private" in result["summary"]
	assert "2c" in result["summary"]
	assert "10.10.10.50" in result["summary"]
	mock_conn.send_config_set.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.services.snmp.DRY_RUN", False)
def test_configure_snmp_netmiko_failed(mock_conn, snmp_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_snmp_netmiko(mock_conn, snmp_data, mock_log)

	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()

@patch("src.remediation.services.snmp.DRY_RUN", True)
def test_configure_snmp_netconf_dry_run(mock_session, snmp_data, mock_log):
	result = configure_snmp_netconf(mock_session, snmp_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "private" in result["summary"]
	assert "2c" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.services.snmp.DRY_RUN", False)
def test_configure_snmp_netconf_successful(mock_session, snmp_data, mock_log):
	result = configure_snmp_netconf(mock_session, snmp_data, mock_log)
	
	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "private" in result["summary"]
	assert "2c" in result["summary"]
	assert "10.10.10.50" in result["summary"]
	mock_session.edit_config.assert_called_once()
	mock_log.info.assert_called_once()
	
@patch("src.remediation.services.snmp.DRY_RUN", False)
def test_configure_snmp_netconf_failed(mock_session, snmp_data, mock_log):
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_snmp_netconf(mock_session, snmp_data, mock_log)

	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()
