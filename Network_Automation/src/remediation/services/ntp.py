from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_ntp(session, ntp_data, log): 
	ntp = ntp_data.get("ntp", {})
	ntp_keys = ntp.get("keys", [])
	ntp_servers = ntp.get("servers", [])

	key_log = ",".join(
		f"ID: {n.get('id', '')} | Trusted: {n.get('trusted', False)}"
		for n in ntp_keys
		)
	server_log = " | ".join(
		f"Server IP: {n['ip']} | Key ID: {n['key_id']}"
		for n in ntp_servers
		)
	try: 
		template = template_env.get_template("NTP.j2")
		commands = template.render(
				ntp_keys=ntp_keys,
				ntp_servers=ntp_servers
			)
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure NTP | "
						f"{key_log}"
						f"| {server_log}"
				)
			}
		response = session.edit_config(
				target="running",
				config=commands
			)
		if not response.ok: 
			return {
                "status": OperationalStatus.CONFIG_FAILED.value,
                "summary": (
                		f"NTP Configuration Failed | "
                		f"{key_log}"
                		f"| {server_log} | Transport: {conn.transport}"
                	),
                "error": str(response)
            }
		
		log.info(
			"ntp_config",
            extra={
                "device_ip": session.device_ip,
                "component": "ntp_automation",
                "event_type": "ntp_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "key_config": key_log,
                "server_config": server_log,
                "message": (
                		f"NTP Configuration Successful | "
                		f"{key_log} | "
                		f"{server_log}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"NTP Configuration Successful | "
                		    f"{key_log} | "
                		    f"{server_log} | Transport: {conn.transport}"
                	)
			}
	
	except Exception as e: 
		log.info(
            "ntp_config",
            extra={
                "device_ip": session.device_ip,
                "component": "ntp_automation",
                "event_type": "ntp_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "key_config": key_log,
                "server_config": server_log,
                "message": (f"Try/Exception Error | NTP Configuration | "
                			f"{key_log} | "
                		    f"{server_log} | Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | NTP Configuration | "
                			f"{key_log} | "
                		    f"{server_log} | Transport: {conn.transport}"
                	),
				"error": str(e)
			}