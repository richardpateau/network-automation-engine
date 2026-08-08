import pytest
from unittest.mock import MagicMock, patch, call
from src.pipeline.runner import run_pipeline

@pytest.fixture
def mock_log():
    return MagicMock()

@pytest.fixture
def mock_device_result():
    return {
        "actions_taken": [],
        "initial_issues": [],
        "critical_issues": [],
        "status": "SUCCESS"
    }

@pytest.fixture
def mock_session():
    session = MagicMock()
    session.transport = "NETCONF"
    session.device_ip = "192.168.1.1"
    return session

@pytest.fixture
def mock_pipeline():
    return {
        "vlans": {
            "function": MagicMock(return_value=None),
            "depends_on": []
        },
        "interfaces": {
            "function": MagicMock(return_value=None),
            "depends_on": ["vlans"]
        },
        "ospf": {
            "function": MagicMock(return_value=None),
            "depends_on": ["interfaces"]
        }
    }

def test_run_pipeline_all_features(
		mock_pipeline, mock_session, mock_log, mock_device_result
	):
	
	context = {"vlans": {}, "interfaces": {}, "ospf": {}}

	run_pipeline(mock_pipeline, context, mock_session, {}, mock_device_result, mock_log)

	assert mock_pipeline["vlans"]["function"].call_count == 1 
	assert mock_pipeline["interfaces"]["function"].call_count == 1 
	assert mock_pipeline["ospf"]["function"].call_count == 1 

def test_run_pipeline_missing_context(
		mock_pipeline, mock_session, mock_device_result, mock_log
	):
	
	context = {"vlans": {}}

	run_pipeline(mock_pipeline, context, mock_session, {}, mock_device_result, mock_log)

	assert mock_pipeline["vlans"]["function"].call_count == 1
	assert mock_pipeline["interfaces"]["function"].call_count == 0 
	assert mock_pipeline["ospf"]["function"].call_count == 0 

def test_run_pipeline_empty(
		mock_pipeline, mock_session, mock_device_result, mock_log
	):
	
	result = run_pipeline(
			mock_pipeline, {}, mock_session, {}, mock_device_result, mock_log
		)

	assert mock_pipeline["vlans"]["function"].call_count == 0 
	assert result["initial_issues"] == []
	assert result["actions_taken"] == []

def test_run_pipeline_exception_handled(
		mock_session, mock_log, mock_device_result
	):
	
	