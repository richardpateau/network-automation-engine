import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.routing.nat import configure_nat
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
def nat_data():
	return {
		"static": [{"inside_local": "192.168.1.10", "inside_global": "203.0.113.4"}],
		"dynamic": [
				{
					 "acl": 10, 
					 "pool_name": "internet_pool",
					 "start_ip": "200.1.1.100",
					 "end_ip": "200.1.1.110", 
					 "mask": "255.255.255.0"
				}
			],
		"interfaces": {
			"inside": ["gigabitethernet3"],
			"outside": ["gigabitethernet1", "gigabitethernet2"]
		}

		}
	
@patch("src.remediation.routing.nat.DRY_RUN", True)
def test_configure_nat_dry_run(mock_session, nat_data, mock_log): 
	result = configure_nat(mock_session, nat_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value
	assert "DRY_RUN" in result["summary"]
	assert "Inside Local: 192.168.1.10" in result["summary"]
	assert "Pool: internet_pool" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.routing.nat.DRY_RUN", False)
def test_configure_nat_successful(mock_session, nat_data, mock_log): 
	result = configure_nat(mock_session, nat_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "Inside Local: 192.168.1.10" in result["summary"]
	assert "Pool: internet_pool" in result["summary"]
	assert "ACL: 10" in result["summary"]
	mock_session.edit_config.call_count == 4
	mock_log.info.assert_called()

@patch("src.remediation.routing.nat.DRY_RUN", False)
def test_configure_nat_failed(mock_session, nat_data, mock_log): 
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_nat(mock_session, nat_data, mock_log)	
	
	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()