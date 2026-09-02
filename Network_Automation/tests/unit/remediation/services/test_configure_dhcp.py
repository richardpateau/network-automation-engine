import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.services.dhcp import configure_dhcp
from src.core.enums import OperationalStatus

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
def dhcp_data():
	return {
		"excluded_addresses": [{"start_ip": "192.168.10.1" , "end_ip": "192.168.10.20"}],
		"pools": [{
				"pool_name": "users",
				"lease_days": 7,
				"lease_hours": 12,
				"lease_minutes": 30,
				"default_gateway": "192.168.10.1",
				"dns_ip": ["4.4.4.4", "8.8.8.8"],
				"domain_name": "company.local",
				"pool_ip": "192.168.10.0",
				"pool_mask": "255.255.255.0"
		}],
		"helper":{
				"interfaces":[
					{"helper_ip": "10.10.10.5" , "interface_name": "gigabitethernet2"}
			]
		}
	}

@patch("src.remediation.services.dhcp.DRY_RUN", True)
def test_configure_dhcp_dry_run(mock_session, dhcp_data, mock_log): 
	result = configure_dhcp(mock_session, dhcp_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "users" in result["summary"]
	assert "192.168.10.0" in result["summary"]
	assert "10.10.10.5" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.services.dhcp.DRY_RUN", False)
def test_configure_dhcp_successful(mock_session, dhcp_data, mock_log): 
	result = configure_dhcp(mock_session, dhcp_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "DHCP Configuration Successful" in result["summary"]
	assert "users" in result["summary"]
	assert "192.168.10.0" in result["summary"]
	assert "10.10.10.5" in result["summary"]
	assert mock_session.edit_config.call_count == 3
	mock_log.info.assert_called_once()

@patch("src.remediation.services.dhcp.DRY_RUN", False) 
def test_configure_dhcp_failed(mock_session, dhcp_data, mock_log): 
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_dhcp(mock_session, dhcp_data, mock_log)

	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()
