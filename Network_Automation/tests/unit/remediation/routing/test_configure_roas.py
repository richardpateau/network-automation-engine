import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.routing.roas import configure_roas
from src.core.enums import OperationalStatus

@pytest.fixture 
def mock_session():
	conn = MagicMock()
	conn.device_ip = "192.168.1.1"
	conn.transport = "RESTCONF"
	return conn

@pytest.fixture
def mock_log():
	return MagicMock()

@pytest.fixture
def roas_data():
	return {
		"interface": "gigabitethernet1.10",
		"router_vlan": 10,
		"ip": "192.168.1.10",
		"mask": "255.255.255.0"
	}

@patch("src.remediation.routing.roas.DRY_RUN", True)
def test_configure_roas_dry_run(mock_session, roas_data, mock_log): 
	result = configure_roas(mock_session, roas_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value
	assert "DRY_RUN" in result["summary"]
	assert "Interface: gigabitethernet1.10" in result["summary"]
	assert "IP: 192.168.1.10/255.255.255.0" in result["summary"]
	mock_session.patch.assert_not_called()

@patch("src.remediation.routing.roas.DRY_RUN", False)
def test_configure_roas_successful(mock_session, roas_data, mock_log):
	mock_session.patch.return_value.status_code = 204 
	result = configure_roas(mock_session, roas_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "Interface: gigabitethernet1.10" in result["summary"]
	assert "IP: 192.168.1.10/255.255.255.0" in result["summary"]
	assert "VLAN: 10" in result["summary"]
	mock_session.patch.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.routing.roas.DRY_RUN", False)
def test_configure_roas_failed(mock_session, roas_data, mock_log): 
	mock_session.patch.side_effect = Exception("Connection lost")
	result = configure_roas(mock_session, hsrp_data, mock_log)	
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()