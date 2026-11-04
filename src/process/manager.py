import logging
from datetime import datetime, timezone
logger = logging.getLogger(__name__)
import time
from src.conn_transports.session_manager import get_session
from src.collectors.restconf.collector import collect_restconf_state
from src.collectors.netconf.collector import collect_netconf_state
from src.collectors.cli.collector import collect_device_state
from src.pipeline.runner import run_pipeline
from src.pipeline.features import PIPELINE
from src.core.enums import OperationalStatus
class MergingLoggerAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        extra = kwargs.get("extra", {})

        kwargs["extra"] = {
            **self.extra,
            **extra
        }

        return msg, kwargs
def main_process(task):
    device = task["device"]
    context = task.get("context", {})
    device_ip = device.get("device_ip")
    adapter = MergingLoggerAdapter(
        logger,
        {'dev': device_ip}
    )
    device_result = {
        "device_name": device.get("name"),
        "device_ip": device_ip,
        "hostname": None,

        "status": "COMPLIANT",

        "actions_taken": [],
        "events": [],

        "checks_passed": 0,
        "checks_failed": 0,

        "checks": {
            "vlans": None,
            "access_ports": None,
            "trunk_ports": None,
            "interfaces": None,
            "roas": None,
            "ospf": None,
            "ntp": None,
            "qos": None,
            "stp": None,
            "hsrp": None,
            "nat": None,
            "dhcp": None,
            "snmp": None,
            "syslog": None,
            "port_security": None,
            "dhcp_snooping": None,
            "dai": None,
            "cdp": None,
            "etherchannel": None,
            "static_routes": None
        },

        "initial_issues": [],
        "critical_issues": [],
        "warnings": [],

        "Remediation": {
            "attempted": False,
            "successful": False,
            "changes": []
        },

        "connection": {
            "transport": None,
            "method": None
        },

        "start_time": datetime.now(timezone.utc).isoformat(),
        "end_time": None,
        "duration_seconds": None,

        "errors": []
    }


    start = time.time()

    try:
        with get_session(device) as session:
            transport = device.get("transport", "NETMIKO")

            if transport == "NETMIKO":
                device_state = collect_device_state(
                        session
                    )
            elif transport == "NETCONF":
                device_state = collect_netconf_state(
                        session, adapter
                    )
            elif transport == "RESTCONF":
                device_state = collect_restconf_state(
                        session, adapter
                    )
            else:
                raise ValueError(
                        f"Unsupported Transport {transport}"
                    )

            device_result = run_pipeline(
                    PIPELINE,
                    context,
                    session,
                    device_state,
                    device_result,
                    adapter,
                    device_ip,
                    transport
                )
    except Exception as e:
        adapter.exception(
                f"Main Process Try/Exception Error | {e}"
            )
        device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        device_result["errors"].append(str(e))

    finally:
        end = datetime.now(timezone.utc)

        device_result["end_time"] = (
            end.isoformat()
        )

        device_result["duration_seconds"] = (
                end - datetime.fromisoformat(device_result["start_time"])
        ).total_seconds()

        if device_result["status"] == OperationalStatus.FAILED_VALIDATION.value:
            pass
        elif device_result["critical_issues"]:
            device_result["status"] = "NON-COMPLIANT"
        else:
            device_result["status"] = "COMPLIANT"

    return device_result