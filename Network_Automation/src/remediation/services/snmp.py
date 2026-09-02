from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_snmp_netmiko(conn, snmp_data, log):
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
		template = template_env.get_template("services/snmp_netmiko.j2")

		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SNMP | "
						f"{communities_log} | {hosts_log} | "
						f"Location: {location} | Contact: {contact} | "
						f"Traps: {traps} | Transport: {conn.transport}"
				)
			}
		commands = template.render(
				communities=communities,
				traps=traps,
				hosts=hosts,
				contact=contact,
				location=location

			).splitlines()
		
		conn.send_config_set(commands)
		
		log.info(
			"snmp_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "message": (
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
							f"Traps: {traps} | Transport: {conn.transport}"
                	)
			}
	
	except Exception as e: 
		log.error(
            "snmp_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "error": str(e),
                "message": (f"Try/Exception Error | SNMP (Switch) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | "
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | SNMP (Switch) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: {conn.transport} | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}

def configure_snmp_netconf(session, snmp_data, log): 
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
		template_netconf = template_env.get_template("services/snmp_netconf.j2")

		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SNMP | "
						f"{communities_log} | {hosts_log} | "
						f"Location: {location} | Contact: {contact} | "
						f"Traps: {traps} | Transport: {session.transport}"
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
                "device_ip": session.device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "message": (
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
							f"Traps: {traps} | Transport: {session.transport}"
                	)
			}
	
	except Exception as e: 
		log.error(
            "snmp_config",
            extra={
                "device_ip": session.device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "error": str(e),
                "message": (f"Try/Exception Error | SNMP (Router) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} "
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | SNMP (Router) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: {session.transport} | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}