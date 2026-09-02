import pytest 
from unittest.mock import MagicMock, patch
from src.remediation.services.qos import configure_qos
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
def qos_data():
	return {
		"policy_name": "wan_qos",
		"class_maps":[{
						"name": "voice",
					    "match_type": "match-any",
					    "protocol": "rtp audio",
					    "action_type":"priority",
					    "bandwidth": "",
					    "priority": "1000"
		}],
		"attachments": [{
				 "interface": "gigabitethernet1", 
				 "direction": "output"
		}]
	}

@patch("src.remediation.services.qos.DRY_RUN", True)
def test_configure_qos_dry_run(mock_session, qos_data, mock_log): 
	result = configure_qos(mock_session, qos_data, mock_log)

	assert result["status"] == OperationalStatus.DRY_RUN.value
	assert "DRY_RUN" in result["summary"]
	assert "wan_qos" in result["summary"]
	assert "voice" in result["summary"]
	assert "gigabitethernet1" in result["summary"]
	mock_session.edit_config.assert_not_called()

@patch("src.remediation.services.qos.DRY_RUN", False)
def test_configure_qos_successful(mock_session, qos_data, mock_log): 
	result = configure_qos(mock_session, qos_data, mock_log)

	assert result["status"] == OperationalStatus.SUCCESS.value
	assert "QOS Configuration Successful" in result["summary"]
	assert "wan_qos" in result["summary"]
	assert "voice" in result["summary"]
	assert "gigabitethernet1" in result["summary"]
	assert mock_session.edit_config.call_count == 2
	mock_log.info.assert_called_once()


@patch("src.remediation.services.qos.DRY_RUN", False)
def test_configure_qos_failed(mock_session, qos_data, mock_log): 
	mock_session.edit_config.side_effect = Exception("Connection lost")
	result = configure_qos(mock_session, qos_data, mock_log)

	assert result["status"] == OperationalStatus.ERROR.value 
	assert "error" in result
	assert "Connection lost" in result["error"]
	mock_log.error.assert_called_once()
