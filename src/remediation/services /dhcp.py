from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_dhcp(session, dhcp_data, log): 
	excluded_addresses = dhcp_data.get("excluded_addresses", [])
	pools = dhcp_data.get("pools", [])
	helper = dhcp_data.get("helper", {}).get("interfaces", [])

	excluded_log = " | ".join(
			f"Excluded IPs | Start IP: {e.get('start_ip')} | End IP: {e.get('end_ip', '')}"
			for e in excluded_addresses
		)
	pool_log = " | ".join(
			f"Pool: {p.get('pool_name')} | IP: {p.get('pool_ip')}/{p.get('pool_mask')} |"
			f"Default Gateway: {p.get('default_gateway')} "
			for p in pools
		)
	helper_log = " | ".join(
			f"Helper IP: {h.get('helper_ip')} | Interface: {h.get('interface_name')}"
			for h in helper
		)
	try: 
		template_excl = template_env.get_template("DHCP_EXCL_NC.j2")
		template_help = template_env.get_template("DHCP_HELP_NC.j2")
		template_pool = template_env.get_template("DHCP_POOL_NC.j2")

		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure DHCP | "
						f"{excluded_log} | {pool_log} | {helper_log}"
				)
			}
		if excluded_addresses:
			commands = template_excl.render(excluded_addresses=excluded_addresses)
			session.edit_config(
					target="running",
					config=commands
				)
		if pools:
			commands = template_pool.render(pools=pools)
			session.edit_config(
						target="running",
						config=commands
					)
		for h in helper:
			helper_ip = h.get("helper_ip")
			if not helper_ip:
				continue

			interface_name = h.get("interface_name", "")
			match = re.match(r"([A-Za-z]+)(.+)", interface_name)
			if not match: 
				continue
			interface_type = match.group(1) if match else "" 
			interface_num = match.group(2) if match else ""
			commands = template_help.render(
					interface_type=interface_type,
					interface_num=interface_num,
					helper_ip=helper_ip
				)
			session.edit_config(
					target="running",
					config=commands
				)

		log.info(
			"dhcp_config",
            extra={
                "device_ip": session.device_ip,
                "component": "dhcp_automation",
                "event_type": "dhcp_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "pool": pool_log,
                "helper": helper_log,
                "excluded_addresses": excluded_log,
                "message": (
                		f"DHCP Configuration Successful | "
                		f"{excluded_log} | {pool_log} | {helper_log}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"DHCP Configuration Successful | "
                			f"{excluded_log} | {pool_log} | {helper_log} | "
                			f"Transport: {conn.transport}"
                	)
			}
	
	except Exception as e: 
		log.info(
            "dhcp_config",
            extra={
                "device_ip": session.device_ip,
                "component": "dhcp_automation",
                "event_type": "dhcp_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "pool": pool_log,
                "helper": helper_log,
                "excluded_addresses": excluded_log,
                "error": str(e),
                "message": (f"Try/Exception Error | DHCP Configuration | "
                			f"{excluded_log} | {pool_log} | {helper_log} | "
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | DHCP Configuration | "
                			f"{excluded_log} | {pool_log} | {helper_log} | "
                			f"Transport: {conn.transport} | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}