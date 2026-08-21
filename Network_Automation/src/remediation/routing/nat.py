import re 
from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env


def configure_nat(session, nat_data, log):
    dynamic = nat_data.get("dynamic", [])
    pat = nat_data.get("pat", {})
    static = nat_data.get("static", [])
    nat_interfaces = nat_data.get("interfaces", {})
    inside_list = nat_interfaces.get("inside", [])
    outside_list = nat_interfaces.get("outside", [])
    interface_log = (
        f"Interfaces | "
        f"Inside: {','.join(inside_list)} | "
        f"Outside: {','.join(outside_list)}"
    )
    nat_model = {
        "pat": pat,
        "dynamic": dynamic,
        "static": static,
        "interfaces": {
            "inside": inside_list,
            "outside": outside_list
        }
    }

    log_parts = []
    if pat:
        log_parts.append(
            f"PAT NAT Overload | "
            f"ACL: {pat.get('acl', '')} | "
            f"Interface: {pat.get('interface', '')} | "
            f"Overload: {pat.get('overload')}"
        )
    if dynamic:
        dynamic_log = " | ".join(
            f"Dynamic NAT | "
            f"Pool: {d.get('pool_name', '')} | ACL: {d.get('acl', '')} | "
            f"Start IP: {d.get('start_ip', '')} | End IP: {d.get('end_ip', '')}"
            for d in dynamic
        )
        log_parts.append(dynamic_log)
    if static:
        static_log = " | ".join(
            f"Static NAT | "
            f"Inside Local: {s.get('inside_local')} | "
            f"Inside Global: {s.get('inside_global')}"
            for s in static
        )
        log_parts.append(static_log)
    nat_log = " | ".join(log_parts) if log_parts else "No NAT Configuration"
    try:
        template_dynamic = template_env.get_template("NAT_POOL_NC.j2")
        template_pat = template_env.get_template("PAT_NC.j2")
        template_static = template_env.get_template("NAT_STATIC_NC.j2")
        template_interface = template_env.get_template("NAT_INT_NC.j2")

        all_commands = []
        interface_commands = []

        if nat_model.get("pat"):
            all_commands.append(
                template_pat.render(nat=nat_model)
            )
        if nat_model.get("dynamic"):
            all_commands.append(
                template_dynamic.render(
                    nat=nat_model
                )
            )
        if nat_model.get("static"):
            all_commands.append(
                template_static.render(
                    nat=nat_model
                )
            )
        for i in nat_model.get("interfaces", {}).get("inside", []):
            match = re.match(r"([A-Za-z]+)(.+)", i)
            interface_type = match.group(1) if match else ""
            interface_num = match.group(2) if match else ""
        
            interface_commands.append(
                template_interface.render(
                    interface_type=interface_type,
                    interface_num=interface_num,
                    role="inside"
                )
            )

        for o in nat_model.get("interfaces", {}).get("outside", []):
            match = re.match(r"([A-Za-z]+)(.+)", o)
            interface_type = match.group(1) if match else ""
            interface_num = match.group(2) if match else ""
        
            interface_commands.append(
                template_interface.render(
                    interface_type=interface_type,
                    interface_num=interface_num,
                    role="outside"
                )
            )
        if DRY_RUN:
            return {
                "status": OperationalStatus.DRY_RUN.value,
                "summary": (
                    f"[DRY_RUN] Would Configure NAT | "
                    f"{nat_log} | {interface_log} | Transport: {session.transport}"
                )
            }
        for commands in all_commands:
            session.edit_config(
                target="running",
                config=commands
            )
        for c in interface_commands:
            session.edit_config(
                target="running",
                config=c
            )
        log.info(
            "nat_config",
            extra={
                "device_ip": session.device_ip,
                "component": "nat_automation",
                "event_type": "nat_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "nat": nat_log,
                "interfaces": interface_log,
                "message": (
                    f"NAT Configuration Successful | "
                    f"{nat_log} | {interface_log} "
                )
            }

        )
        return {
            "status": OperationalStatus.SUCCESS.value,
            "summary": (
                f"NAT Configuration Successful | "
                f"{nat_log} | {interface_log} | Transport: {session.transport}"
            )
        }

    except Exception as e:
        log.error(
            "nat_config",
            extra={
                "device_ip": session.device_ip,
                "component": "nat_automation",
                "event_type": "nat_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "nat": nat_log,
                "interfaces": interface_log,
                "error": str(e),
                "message": (f"Try/Exception Error | NAT Configuration | "
                            f"{nat_log} | {interface_log} | "
                            f"Error: {str(e)}"
                            )
            }

        )
        return {
            "status": OperationalStatus.ERROR.value,
            "summary": (
                f"Try/Exception Error | NAT Configuration | "
                f"{nat_log} | {interface_log} | Transport: {session.transport} | "
                f"Error: {str(e)}"
            ),
            "error": str(e)
        }
