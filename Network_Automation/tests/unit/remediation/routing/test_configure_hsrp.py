import pytest
from unittest.mock import MagicMock, patch
from src.remediation.routing.hsrp import configure_hsrp
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
def hsrp_data():
	return {
		"interface": "gigabitethernet1",
		"version": 2,
		"group": 10,
		"vip": "192.168.10.1",
		"preempt": True,
		"priority": 110,
		"router_vlan": 20
	}

@patch("src.remediation.routing.hsrp.DRY_RUN", True)
def test_configure_hsrp_dry_run(mock_session, hsrp_data, mock_log):
	result = configure_hsrp(mock_session, hsrp_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value
	assert "DRY_RUN" in result["summary"]
	assert "Interface: gigabitethernet1" in result["summary"]
	assert "Version: 2" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.routing.hsrp.DRY_RUN", False)
def test_configure_hsrp_successful(mock_session, hsrp_data, mock_log):
	result = configure_hsrp(mock_session, hsrp_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "Interface: gigabitethernet1" in result["summary"]
	assert "Version: 2" in result["summary"]
	assert "VIP: 192.168.10.1" in result["summary"]
	mock_session.edit_config.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.routing.hsrp.DRY_RUN", False)
def test_configure_hsrp_failed(mock_session, hsrp_data, mock_log):
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_hsrp(mock_session, hsrp_data, mock_log)	
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()