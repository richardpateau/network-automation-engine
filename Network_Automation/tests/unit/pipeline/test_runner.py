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

@patch("src.pipeline.runner.resolve_pipeline")
def test_run_pipeline_exception_handled(
		mock_resolve, mock_session, mock_log, mock_device_result
	):
	
	failing_function = MagicMock(side_effect=Exception("Config Failed"))
	passing_function = MagicMock(return_value=None)

	pipeline = {
		"vlans": {"function": failing_function, "depends_on": []},
		"ospf": {"function": passing_function, "depends_on": []}
	}	

	context = {"vlans": {}, "ospf": {}}

	mock_resolve.return_value = ["vlans", "ospf"]
	result = run_pipeline(
			pipeline, context, mock_session, {}, mock_device_result, mock_log
		)

	passing_function.assert_called_once()
	failing_function.assert_called_once()
	assert any("vlans" in r for r in result["critical_issues"])
	assert any("vlans pipeline failure" in r for r in result["critical_issues"])
	mock_log.exception.assert_called()

@patch("src.pipeline.runner.resolve_pipeline")
def test_run_pipeline_order(
		mock_resolve, mock_session, mock_log, mock_device_result
	):
	
	seq_order = []
	
	def vlan_function(*args): seq_order.append("vlans")
	def interface_function(*args): seq_order.append("interfaces")
	def ospf_function(*args): seq_order.append("ospf")

	pipeline = {
		"vlans":      {"function": vlan_function, "depends_on": []},
        "interfaces": {"function": interface_function, "depends_on": ["vlans"]},
        "ospf":       {"function": ospf_function, "depends_on": ["interfaces"]}
	}

	context = {"vlans": {}, "interfaces": {}, "ospf": {}}

	mock_resolve.return_value = ["vlans", "interfaces", "ospf"]

	run_pipeline(pipeline, context, mock_session, {}, mock_device_result, mock_log)

	assert seq_order == ["vlans", "interfaces", "ospf"]

@patch("src.pipeline.runner.resolve_pipeline")
def test_run_pipeline_return_device_result(
		mock_resolve, mock_pipeline, mock_session, mock_device_result, mock_log
	): 

	context = {"vlans": {}, "interfaces": {}, "ospf": {}}
	mock_resolve.return_value = ["vlans", "interfaces", "ospf"]

	result = run_pipeline(mock_pipeline, context, mock_session, {}, mock_device_result, mock_log)

	assert result is mock_device_result

@patch("src.pipeline.runner.resolve_pipeline")
def test_run_pipeline_return_correct_function(
		mock_resolve, mock_pipeline, mock_session, mock_device_result, mock_log
	): 
	mock_function = MagicMock()
	pipeline = {"vlans": {"function": mock_function, "depends_on": []}}
	context = {"vlans": {"vlan_id": 10}}
	device_state = {}
	mock_resolve.return_value = ["vlans"]

	run_pipeline(pipeline, context, mock_session, device_state , mock_device_result, mock_log)

	mock_function.assert_called_once_with(
			mock_session, context, device_state, mock_device_result, mock_log
		)


@patch("src.pipeline.runner.resolve_pipeline")
def test_run_pipeline_return_multiple_exceptions(
		mock_resolve, mock_pipeline, mock_session, mock_device_result, mock_log
	): 
	
	pipeline = {
		"vlans": {"function": MagicMock(side_effect=Exception("vlan error")), "depends_on": []},
		"interfaces": {
			"function": MagicMock(side_effect=Exception("interface error")), "depends_on": ["vlans"]
		}, 
		"ospf": {
			"function": MagicMock(side_effect=Exception("ospf error")), "depends_on": ["interfaces"]
		}
	}
	context = {"vlans": {}, "interfaces": {}, "ospf": {}}
	mock_resolve.return_value = ["vlans", "interfaces", "ospf"]
	device_state = {}
	result = run_pipeline(
		pipeline, context, mock_session, device_state , mock_device_result, mock_log
		)
	assert len(result["critical_issues"]) == 3 
	assert mock_log.exception.call_count == 3 

