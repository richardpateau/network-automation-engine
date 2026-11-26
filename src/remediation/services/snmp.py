from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env


def configure_snmp_netmiko(conn, snmp_data, act_snmp, device_ip, transport, log):
    communities = snmp_data.get("communities", [])
    contact = snmp_data.get("contact", "")
    hosts = snmp_data.get("hosts", [])
    location = snmp_data.get("location", "")
    traps = snmp_data.get("traps", {})

    communities_log = " | ".join(
        f"SNMP Name: {c.get('snmp_name')} | SNMP Permission: {c.get('permission')}"
        for c in communities
    )
    hosts_log = " | ".join(
        f"SNMP IP: {h.get('snmp_ip')} | Version: {h.get('version')}"
        for h in hosts
    )
    try:
        template = template_env.get_template("snmp_netmiko.j2")

        if DRY_RUN:
            return {
                "status": OperationalStatus.DRY_RUN.value,
                "summary": (
                    f"[DRY_RUN] Would Configure SNMP | "
                    f"{communities_log} | {hosts_log} | "
                    f"Location: {location} | Contact: {contact} | "
                    f"Traps: {','.join(traps)} | Transport: {transport}"
                )
            }
        output = conn.send_command("show running-config | include ^snmp-server")

        if output:
            snmp_lines = output.splitlines()
            snmp_lines.reverse()
            negative_commands = [f"no {line}" for line in snmp_lines]
            conn.send_config_set(negative_commands)

        commands = template.render(
            snmp_data=snmp_data,

        ).splitlines()

        conn.send_config_set(commands)
        conn.save_config()

        log.info(
            "snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": transport,
                "status": StepStatus.SUCCESS.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "detail": (
                    f"SNMP (Switch) Configuration Successful | "
                    f"{communities_log} | {hosts_log} | "
                    f"Location: {location} | Contact: {contact} | "
                    f"Traps: {traps}"
                )
            }

        )
        return {
            "status": OperationalStatus.SUCCESS.value,
            "summary": (
                f"SNMP (Switch) Configuration Successful | "
                f"{communities_log} | {hosts_log} | "
                f"Location: {location} | Contact: {contact} | "
                f"Traps: {traps} | Transport: {transport}"
            )
        }

    except Exception as e:
        log.info(
            "snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": transport,
                "status": StepStatus.ERROR.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "error": str(e),
                "detail": (f"Try/Exception Error | SNMP (Switch) Configuration | "
                           f"{communities_log} | {hosts_log} | "
                           f"Location: {location} | Contact: {contact} | "
                           f"Traps: {traps} | "
                           )
            }

        )
        return {
            "status": OperationalStatus.ERROR.value,
            "summary": (
                f"Try/Exception Error | SNMP (Switch) Configuration | "
                f"{communities_log} | {hosts_log} | "
                f"Location: {location} | Contact: {contact} | "
                f"Traps: {traps} | Transport: {transport} | "
                f"Error: {str(e)}"
            ),
            "error": str(e)
        }


def configure_snmp_nc(session, snmp_data, act_snmp, device_ip, transport, log):
    communities = snmp_data.get("communities", [])
    contact = snmp_data.get("contact", "")
    hosts = snmp_data.get("hosts", [])
    location = snmp_data.get("location", "")
    traps = snmp_data.get("traps", {})

    communities_log = " | ".join(
        f"SNMP Name: {c.get('snmp_name')} | SNMP Permission: {c.get('permission')}"
        for c in communities
    )
    hosts_log = " | ".join(
        f"SNMP IP: {h.get('snmp_ip')} | Version: {h.get('snmp_version')}"
        for h in hosts
    )
    try:
        template_netconf = template_env.get_template("SNMP_NC.j2")

        if DRY_RUN:
            return {
                "status": OperationalStatus.DRY_RUN.value,
                "summary": (
                    f"[DRY_RUN] Would Configure SNMP | "
                    f"{communities_log} | {hosts_log} | "
                    f"Location: {location} | Contact: {contact} | "
                    f"Traps: {traps} | Transport: {transport}"
                )
            }
        commands = template_netconf.render(
            communities=communities,
            traps=traps,
            hosts=hosts,
            contact=contact,
            location=location

        )
        session.edit_config(
            target="running",
            config=commands
        )
        log.info(
            "snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": transport,
                "status": StepStatus.SUCCESS.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "detail": (
                    f"SNMP (Router) Configuration Successful | "
                    f"{communities_log} | {hosts_log} | "
                    f"Location: {location} | Contact: {contact} | "
                    f"Traps: {traps}"
                )
            }

        )
        return {
            "status": OperationalStatus.SUCCESS.value,
            "summary": (
                f"SNMP (Router) Configuration Successful | "
                f"{communities_log} | {hosts_log} | "
                f"Location: {location} | Contact: {contact} | "
                f"Traps: {traps} | Transport: {transport}"
            )
        }

    except Exception as e:
        log.info(
            "snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": transport,
                "status": StepStatus.ERROR.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "error": str(e),
                "detail": (f"Try/Exception Error | SNMP (Router) Configuration | "
                           f"{communities_log} | {hosts_log} | "
                           f"Location: {location} | Contact: {contact} | "
                           f"Traps: {traps} "
                           )
            }

        )
        return {
            "status": OperationalStatus.ERROR.value,
            "summary": (
                f"Try/Exception Error | SNMP (Router) Configuration | "
                f"{communities_log} | {hosts_log} | "
                f"Location: {location} | Contact: {contact} | "
                f"Traps: {traps} | Transport: {transport} | "
                f"Error: {str(e)}"
            ),
            "error": str(e)
        }
