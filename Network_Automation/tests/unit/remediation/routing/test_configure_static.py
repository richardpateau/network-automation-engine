import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.routing.static import configure_static
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
def static_data():
	{"static": [{
    "type": "recursive",
    "AD": 1,
    "network_address": "10.10.10.0",
    "mask": "255.255.255.0",
    "next_hop": ["192.168.1.2"],
    "name": None
}]}

@patch("src.remediation.routing.static.DRY_RUN", True)
def test_configure_static_dry_run(mock_session, static_data, mock_log): 
	result = configure_static(mock_session, static_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value 
	assert "DRY_RUN" in result["summary"]
	assert "Network Address: 10.10.10.0" in result["summary"]
	assert "AD: 1" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.routing.static.DRY_RUN", False)
def test_configure_static_successful(mock_session, static_data, mock_log): 
	result = configure_static(mock_session, static_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value 
	assert "Network Address: 10.10.10.0" in result["summary"]
	assert "AD: 1" in result["summary"]
	assert "Next Hop: [192.168.1.2]" in result["summary"]
	mock_session.edit_config.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.routing.static.DRY_RUN", False)
def test_configure_static_failed(mock_session, static_data, mock_log): 
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_static(mock_session, static_data, mock_log)	
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()
