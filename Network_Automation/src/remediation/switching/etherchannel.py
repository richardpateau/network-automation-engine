from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_etherchannel(conn, eth_data, log): 
	enabled = eth_data.get("enabled", False)
	groups = eth_data.get("groups", {})
	groups_log = " | ".join(
			f"Group #: {g} | Mode: {v.get('mode')} | Type: {v.get('type')} | "
			f"Switchport Mode: {v.get('switchport_mode')} | "
			f"Interfaces: {','.join(v.get('interfaces', []))} | Description: {v.get('description')}"
			for g, v in groups.items()
		)

	try: 
		template = template_env.get_template("switching/etherchannel.j2")
		
		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure Etherchannel | "
						f"Enabled: {enabled} | {groups_log} | "
						f"Transport: {conn.transport}"
						
				)
			}
		commands = template.render(
				enabled=enabled,
				groups=groups
			).splitlines()

		conn.send_config_set(commands)

		log.info(
			"ether_config",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "ether_automation",
	            "event_type": "ether_config",
	            "transport": conn.transport,
	            "status": StepStatus.SUCCESS.value,
	            "enabled": enabled,
	            "message": (
	            		f"Etherchannel Configuration Successful | "
	            		f"Enabled: {enabled} | {groups_log} | "
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"Etherchannel Configuration Successful | "
		            		f"Enabled: {enabled} | {groups_log} | "
							f"Transport: {conn.transport}"
	            	)
			}

	except Exception as e: 
		log.error(
	        "ether_config",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "ether_automation",
	            "event_type": "ether_config",
	            "transport": conn.transport,
	            "status": StepStatus.ERROR.value,
	           	"enabled": enabled,
	            "error": str(e),
	            "message": (f"Try/Exception Error | Etherchannel Configuration | "
	            			f"Enabled: {enabled} | {groups_log} | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Etherchannel Configuration | "
	            			f"Enabled: {enabled} | {groups_log} | "
							f"Transport: {conn.transport} | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
