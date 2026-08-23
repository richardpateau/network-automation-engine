from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_dai(conn, dai_data, log): 
	enabled_vlans = dai_data.get("enabled_vlans", [])
	interfaces = dai_data.get("interfaces", {})
	log_buffer = dai_data.get("log_buffer", {})

	interface_log = " | ".join(
			f"Interface: {i} | Rate Limit: {v.get('rate_limit', None)} | "
			f"Trusted: {v.get('trusted', '')}"
			for i, v in interfaces.items()
		)
	buffer_log = f"Enabled: {log_buffer.get('enabled')} | Entries: {log_buffer.get('entries')}"
	
	try: 
		template = template_env.get_template("DAI_NET.j2")

		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure DAI | "
						f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Log Buffer: {buffer_log} | Transport: {conn.transport}"
				)
			}
		
		commands = template.render(
				enabled_vlans=enabled_vlans,
				log_buffer=log_buffer,
				interfaces=interfaces
			).splitlines()
		
		conn.send_config_set(commands)


		log.info(
			"dai_config",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "dai_automation",
	            "event_type": "dai_config",
	            "status": StepStatus.SUCCESS.value,
	            "VLANs": enabled_vlans,
	            "transport": conn.transport,
	            "interfaces": interface_log,
	            "buffer_log": buffer_log,
	            "message": (
	            		f"DAI Configuration Successful | "
	            		f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Log Buffer: {buffer_log} "
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"DAI Configuration Successful | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Log Buffer: {buffer_log} | Transport: {conn.transport}"
	            	)
			}

	except Exception as e: 
		log.error(
	        "dai_config",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "dai_automation",
	            "event_type": "dai_config",
	            "status": StepStatus.ERROR.value,
	           	"VLANs": enabled_vlans,
	            "interfaces": interface_log,
	            "buffer_log": buffer_log,
	            "transport": conn.transport,
	            "error": str(e),
	            "message": (f"Try/Exception Error | DAI Configuration | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Log Buffer: {buffer_log} | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | DAI Configuration | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Log Buffer: {buffer_log} | Transport: {conn.transport} | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
