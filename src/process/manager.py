def main_process(device):
    device_ip = device.get("device_ip")
    adapter = logging.LoggerAdapter(logger, {'dev': device_ip})

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

        "start_time": datetime.utcnow().isoformat(),
        "end_time": None,
        "duration_seconds": None,

        "errors": []
    }


    start = time.time()

    try:
        with get_session(device) as session:
            device_result["connection"]["transport"] = session.transport
            if session.transport == "NETMIKO":
                device_state = collect_device_state(
                        session, adapter
                    )
            elif session.transport == "NETCONF":
                device_state = collect_netconf_state(
                        session, adapter
                    )
            elif session.transport == "RESTCONF":
                device_state = collect_restconf_state(
                        session, adapter
                    )
            else:
                raise ValueError(
                        f"Unsupported Transport {session.transport}"
                    )

            device_result = run_pipeline(
                    PIPELINE,
                    device.get("context"),
                    session,
                    device_state,
                    device_result,
                    adapter
                )
    except Exception as e:
        adapter.exception(
                f"Main Process Try/Exception Error | {e}"
            )
        device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        device_result["errors"].append(str(e))

    finally:
        end = datetime.utcnow()

        device_result["end_time"] = (
            end.isoformat()
        )

        device_result["duration_seconds"] = (
            end - datetime.fromisoformat(
                device_result["start_time"]
            )
        ).total_seconds()


        if device_result["critical_issues"]:
            device_result["status"] = "NON-COMPLIANT"

        elif device_result["status"] != "FAILED":
            device_result["status"] = "COMPLIANT"

    return device_result