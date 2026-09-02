from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_stp_global(conn, stp_data, log):
    mode = stp_data.get("mode", "")
    vlan_priorities = stp_data.get("vlan_priorities", {})
    vlan_log = " | ".join(
        f"VLAN: {v} Priority: {p}" for v, p in vlan_priorities.items()
    )
    try:
        template = template_env.get_template("switching/stp_global.j2")
        commands = (
            template.render(mode=mode, vlan_priorities=vlan_priorities)
            .splitlines()
        )
        if DRY_RUN:
            return {
                "status": OperationalStatus.DRY_RUN.value,
                "summary": (
                    f"[DRY_RUN] Would Configure STP Globally  | "
                    f"Mode: {mode} | "
                    f"VLAN/Priority: {vlan_log}"
                ),
            }
        conn.send_config_set(commands)

        log.info(
            "stp_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "stp_mode": mode,
                "vlan_priorities": vlan_priorities,
                "message": (
                    f"STP Successfully Configured | "
                    f"Mode: {mode} | "
                    f"VLAN/Priority: {vlan_log}"
                ),
            },
        )
        return {
            "status": OperationalStatus.SUCCESS.value,
            "summary": (
                f"STP Successfully Configured | "
                f"Mode: {mode} | "
                f"VLAN/Priority: {vlan_log}"
            ),
        }
    except Exception as e:
        log.error(
            "stp_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "stp_mode": mode,
                "vlan_priorities": vlan_priorities,
                "message": (
                    f"Try/Exception Error | STP Global Configuration | "
                    f"Mode: {mode} | "
                    f"VLAN/Priority: {vlan_log} | Error: {str(e)}"
                ),
            },
        )
        return {
            "status": OperationalStatus.ERROR.value,
            "summary": (
                f"Try/Exception Error | STP Global Configuration | "
                f"Mode: {mode} | "
                f"VLAN/Priority: {vlan_log} | Error: {str(e)}"
            ),
            "error": str(e),
        }


def configure_stp_interfaces(conn, stp_data, log):
    interface = stp_data.get("interface", "")
    stp_int = stp_data.get("stp", {})
    stp_log = " | ".join(f"{s}:{b}" for s, b in stp_int.items())
    try:
        template = template_env.get_template("switching/stp_interfaces.j2")
        commands = template.render(interface=interface, stp_int=stp_int).splitlines()
        if DRY_RUN:
            return {
                "status": OperationalStatus.DRY_RUN.value,
                "summary": (
                    f"[DRY_RUN] Would Configure STP Interface Feature | "
                    f"Interface: {interface} | Feature: {stp_log}"
                ),
            }
        conn.send_config_set(commands)
        log.info(
            "stp_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "features": stp_log,
                "message": (
                    f"STP Interface Feature Successfully Configured | "
                    f"Interface: {interface} | Feature: {stp_log}"
                ),
            },
        )
        return {
            "status": OperationalStatus.SUCCESS.value,
            "summary": (
                f"STP Interface Feature Successfully Configured | "
                f"Interface: {interface} | Feature: {stp_log}"
            ),
        }
    except Exception as e:
        log.error(
            "stp_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "features": stp_log,
                "message": (
                    f"Try/Exception Error | STP Interface Configuration | "
                    f"Interface: {interface} | Feature: {stp_log} | "
                    f"Error: {str(e)}"
                ),
            },
        )
        return {
            "status": OperationalStatus.ERROR.value,
            "summary": (
                f"Try/Exception Error | STP Interface Configuration | "
                f"Interface: {interface} | Feature: {stp_log} | "
                f"Error: {str(e)}"
            ),
            "error": str(e),
        }
