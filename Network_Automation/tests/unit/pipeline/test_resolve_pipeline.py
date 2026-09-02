import pytest
from src.pipeline.resolver import resolve_pipeline
from src.pipeline.features import PIPELINE


@pytest.fixture
def simple_pipeline():
    return {
        "vlans": {"function": None, "depends_on": []},
        "interfaces": {"function": None, "depends_on": ["vlans"]},
        "ospf": {"function": None, "depends_on": ["interfaces"]}
    }


def test_resolve_pipeline_simple(simple_pipeline):
    result = resolve_pipeline(simple_pipeline)

    assert result.index("vlans") < result.index("interfaces")
    assert result.index("interfaces") < result.index("ospf")


def test_resolve_pipeline_no_dependencies():
    pipeline = {
        "vlans": {"function": None, "depends_on": []},
        "snmp": {"function": None, "depends_on": []},
        "syslog": {"function": None, "depends_on": []},
    }

    result = resolve_pipeline(pipeline)
    assert set(result) == {"vlans", "snmp", "syslog"}
    assert len(result) == 3


def test_resolve_pipeline_exception():
    pipeline = {
        "vlans": {"function": None, "depends_on": ["ospf"]},
        "interfaces": {"function": None, "depends_on": ["vlans"]},
        "ospf": {"function": None, "depends_on": ["interfaces"]}
    }


    with pytest.raises(Exception) as excp:
        resolve_pipeline(pipeline)

    assert "Redundant dependency detected" in str(excp.value)


def test_resolve_pipeline_empty():
    result = resolve_pipeline({})
    assert result == []


def test_resolve_pipeline_single_feature():
    pipeline = {"vlans": {"function": None, "depends_on": []}}
    result = resolve_pipeline(pipeline)
    assert result == ["vlans"]


def test_resolve_actual_pipeline():
    result = resolve_pipeline(PIPELINE)

    assert set(result) == set(PIPELINE.keys())
    assert len(result) == len(set(result))

    assert result.index("vlans") < result.index("interfaces")
    assert result.index("vlans") < result.index("etherchannel")
    assert result.index("etherchannel") < result.index("stp")
    assert result.index("dhcp_snooping") < result.index("dai")
    assert result.index("roas") < result.index("ospf")
    assert result.index("roas") < result.index("hsrp")
    assert result.index("interfaces") < result.index("static_routes")
    assert result.index("access_ports") < result.index("port_security")
