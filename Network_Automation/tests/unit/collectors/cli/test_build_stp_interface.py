from src.collectors.cli.builders import build_stp_interfaces


def test_build_stp_interfaces_valid(stp_interface_output):
    result = build_stp_interfaces(stp_interface_output)

    assert len(result) == 9
    assert result["gigabitethernet0/1"]["portfast"] is True
    assert result["gigabitethernet0/1"]["bpdu_filter"] is True
    assert result["gigabitethernet0/1"]["bpdu_guard"] is True
    assert result["gigabitethernet0/1"]["root_guard"] is True
    assert result["gigabitethernet0/2"]["loop_guard"] is True


def test_build_stp_interfaces_no_stp(stp_interface_output):
    result = build_stp_interfaces(stp_interface_output)

    assert result["gigabitethernet0/3"]["portfast"] is False
    assert result["gigabitethernet0/3"]["bpdu_filter"] is False
    assert result["gigabitethernet0/3"]["bpdu_guard"] is False
    assert result["gigabitethernet0/3"]["root_guard"] is False
    assert result["gigabitethernet0/3"]["loop_guard"] is False


def test_build_stp_interfaces_empty():
    assert build_stp_interfaces({}) == {}
    assert build_stp_interfaces(None) == {}
    assert build_stp_interfaces({"not_run": {}}) == {}


def test_build_stp_interfaces_invalid_interface():
    data = {
"running_config": """
interface 
 spanning-tree portfast 
    """
    }

    result = build_stp_interfaces(data)
    assert result == {}
