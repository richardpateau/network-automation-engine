import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.routing.ospf import configure_ospf
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
def ospf_data():
	return {
		"process_id": 1,
            "router_id": "1.1.1.1",
            "network_list": [
                {
                    "subnet": "192.168.10.0",
                    "wildcard": "0.0.0.255",
                    "area": 0,
                }
            ]
		}

@patch("src.remediation.routing.ospf.DRY_RUN", True)
def test_configure_ospf_dry_run(mock_session, ospf_data, mock_log): 
	result = configure_ospf(mock_session, ospf_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value
	assert "DRY_RUN" in result["summary"]
	assert "Process ID: 1" in result["summary"]
	assert "192.168.10.0/0.0.0.255 area 0" in result["summary"]
	mock_session.patch.assert_not_called()

@patch("src.remediation.routing.ospf.DRY_RUN", False)
def test_configure_ospf_successful(mock_session, ospf_data, mock_log): 
	mock_session.patch.return_value.status_code = 204.
	result = configure_ospf(mock_session, ospf_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "Process ID: 1" in result["summary"]
	assert "192.168.10.0/0.0.0.255 area 0" in result["summary"]
	assert "RID: 1.1.1.1" in result["summary"]
	mock_session.patch.assert_called_once()
	mock_log.info.assert_called_once()

@patch("src.remediation.routing.ospf.DRY_RUN", False)
def test_configure_ospf_failed(mock_session, ospf_data, mock_log): 
	mock_session.patch.side_effect = Exception("Connection lost")
	result = configure_ospf(mock_session, ospf_data, mock_log)
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()