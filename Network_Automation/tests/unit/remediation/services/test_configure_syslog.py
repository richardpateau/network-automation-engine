import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.services.syslog import configure_syslog_netmiko, configure_syslog_netconf
from src.core.enums import OperationalStatus

@pytest.fixture 
def mock_conn_netmiko():
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
def syslog_data():
	return {
		"hosts":["192.168.10.10", "192.168.20.20"],
		"facility": "local6",
		"trap_level": "warnings",
		"source_interface": "loopback0",
		"timestamps": True
	}

@patch("src.remediation.services.syslog.DRY_RUN", True)
def test_configure_syslog_netmiko_dry_run(mock_conn_netmiko, syslog_data, mock_log):
	result = configure_syslog_netmiko(mock_conn_netmiko, syslog_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "192.168.10.10" in result["summary"]
	assert "192.168.20.20" in result["summary"]
	assert "loopback0" in result["summary"]
	mock_conn_netmiko.send_config_set.assert_not_called()

@patch("src.remediation.services.syslog.DRY_RUN", False)
def test_configure_syslog_netmiko_successful(mock_conn_netmiko, syslog_data, mock_log):
	result = configure_syslog_netmiko(mock_conn_netmiko, syslog_data, mock_log)
	
	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "Syslog Configuration Successful" in result["summary"]
	assert "192.168.10.10" in result["summary"]
	assert "192.168.20.20" in result["summary"]
	assert "loopback0" in result["summary"]
	mock_conn_netmiko.send_config_set.assert_called_once()
	mock_log.info.assert_called_once()


@patch("src.remediation.services.syslog.DRY_RUN", False)
def test_configure_syslog_netmiko_failed(mock_conn_netmiko, syslog_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_syslog_netmiko(mock_conn_netmiko, syslog_data, mock_log)

	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()

@patch("src.remediation.services.syslog.DRY_RUN", True)
def test_configure_syslog_netconf_dry_run(mock_session, syslog_data, mock_log):
	result = configure_syslog_netconf(mock_session, syslog_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "192.168.10.10" in result["summary"]
	assert "192.168.20.20" in result["summary"]
	assert "loopback0" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.services.syslog.DRY_RUN", False)
def test_configure_syslog_netconf_successful(mock_session, syslog_data, mock_log):
	result = configure_syslog_netconf(mock_session, syslog_data, mock_log)
	
	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "Syslog Configuration Successful" in result["summary"]
	assert "192.168.10.10" in result["summary"]
	assert "192.168.20.20" in result["summary"]
	assert "loopback0" in result["summary"]
	assert mock_session.edit_config.call_count == 2
	mock_log.info.assert_called_once()


@patch("src.remediation.services.syslog.DRY_RUN", False)
def test_configure_syslog_netconf_failed(mock_session, syslog_data, mock_log):
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_syslog_netconf(mock_session, syslog_data, mock_log)

	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()
