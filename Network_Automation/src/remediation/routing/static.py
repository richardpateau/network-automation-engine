from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_static(session, static_data, log):
    static_log = " | ".join(
        f"Network Address: {s.get('network_address')} | Mask: {s.get('mask')} | "
        f"AD: {s.get('AD', 'N/A')} | Exit Interface : {s.get('exit_interface', 'N/A')} | "
        f"Next Hop IP: {', '.join(s.get('next_hop', 'N/A'))}"
        for s in static_data
    )
    try:
        temp_recursive = template_env.get_template("routing/static_recursive_netconf.j2")
        temp_exit_int = template_env.get_template("routing/static_directly_connected_netconf.j2")
        temp_full = template_env.get_template("routing/static_fully_specified_netconf.j2")

        templates = {
            "recursive": temp_recursive,
            "exit-interface": temp_exit_int,
            "fully-specified": temp_full
        }

        if DRY_RUN:
            return {
                "status": OperationalStatus.DRY_RUN.value,
                "summary": (
                    f"[DRY_RUN] Would Configure Static Routes | "
                    f"{static_log} | Transport: NETCONF"
                )
            }
        else:
            for s in static_data:
                template = templates.get(s.get("type"))
                if not template:
                    continue
                commands = template.render(
                    static=s
                )

                session.edit_config(
                    target="running",
                    config=commands
                )

            log.info(
                "static_config",
                extra={
                    "session.device_ip": session.device_ip,
                    "component": "static_automation",
                    "event_type": "static_config",
                    "status": StepStatus.SUCCESS.value,
                    "message": (
                        f"Static Routes Configuration Successful | "
                        f"{static_log} | Transport: NETCONF"
                    )
                }

            )
            return {
                "status": OperationalStatus.SUCCESS.value,
                "summary": (
                    f"Static Route Configuration Successful | "
                    f"{static_log} | Transport: NETCONF"
                )
            }

    except Exception as e:
        log.error(
            "static_config",
            extra={
                "session.device_ip": session.device_ip,
                "component": "static_automation",
                "event_type": "static_config",
                "status": StepStatus.ERROR.value,
                "error": str(e),
                "message": (f"Try/Exception Error | Static Route Configuration | "
                            f"{static_log} | Transport: NETCONF | "
                            f"Error: {str(e)}"
                            )
            }

        )
        return {
            "status": OperationalStatus.ERROR.value,
            "summary": (
                f"Try/Exception Error | Static Route Configuration | "
                f"{static_log} | Transport: NETCONF | "
                f"Error: {str(e)}"
            ),
            "error": str(e)
        }
