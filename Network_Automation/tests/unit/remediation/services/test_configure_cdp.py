import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.services.cdp import configure_cdp_netmiko, configure_cdp_netconf
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
def cdp_data():
	return {
		"enabled": True, 
		"timer": 60,
		"holdtime": 180,
		"interfaces": {
			"gigabitethernet1": {"enabled": True},
			"gigabitethernet2": {"enabled": False}
		}
	}

@patch("src.remediation.services.cdp.DRY_RUN", True)
def test_configure_cdp_netmiko_dry_run(mock_conn, cdp_data, mock_log):
	result = configure_cdp_netmiko(mock_conn, cdp_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "True" in result["summary"]
	assert "Interface/Enabled: gigabitethernet1/True" in result["summary"]
	mock_conn.send_config_set.assert_not_called()

@patch("src.remediation.services.cdp.DRY_RUN", False)
def test_configure_cdp_netmiko_successful(mock_conn, cdp_data, mock_log):
	result = configure_cdp_netmiko(mock_conn, cdp_data, mock_log)
	
	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "CDP Configuration Successful" in result["summary"]
	assert "True" in result["summary"]
	assert "Interface/Enabled: gigabitethernet1/True" in result["summary"]
	assert "60" in result["summary"]
	mock_conn.send_config_set.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.services.cdp.DRY_RUN", False)
def test_configure_cdp_netmiko_failed(mock_conn, cdp_data, mock_log):
	mock_conn.send_config_set.side_effect = Exception("Connection lost")
	result = configure_cdp_netmiko(mock_conn, cdp_data, mock_log)
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()

@patch("src.remediation.services.cdp.DRY_RUN", True)
def test_configure_cdp_netconf_dry_run(mock_session, cdp_data, mock_log): 
	result = configure_cdp_netconf(mock_session, cdp_data, mock_log)
	
	assert result["status"] == OperationalStatus.DRY_RUN.value
	assert "DRY_RUN" in result["summary"]
	assert "True" in result["summary"]
	assert "Interface/Enabled: gigabitethernet1/True" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.services.cdp.DRY_RUN", False)
def test_configure_cdp_netconf_successful(mock_session, cdp_data, mock_log): 
	result = configure_cdp_netconf(mock_session, cdp_data, mock_log)
	
	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "CDP Configuration Successful" in result["summary"]
	assert "True" in result["summary"]
	assert "Interface/Enabled: gigabitethernet1/True" in result["summary"]
	assert "60" in result["summary"]
	assert mock_session.edit_config.call_count == 3 
	mock_log.info.assert_called_once()

@patch("src.remediation.services.cdp.DRY_RUN", False)
def test_configure_cdp_netconf_failed(mock_session, cdp_data, mock_log): 
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_cdp_netconf(mock_session, cdp_data, mock_log)
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()