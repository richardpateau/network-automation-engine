from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_snooping(conn, snoop_data, log): 
	enabled_vlans = snoop_data.get("enabled_vlans", [])
	option82 = snoop_data.get("option82", False)
	interfaces = snoop_data.get("interfaces", {})
	interface_list = [
		{	
			"interface": i,
			"rate_limit": v.get("rate_limit", ""),
			"trusted": v.get("trusted", False)

		} for i, v in interfaces.items()
	]
	interface_log = " | ".join(
			f"Interface: {i} | Rate Limit: {v.get('rate_limit')} | Trusted Interface: "
			f"{v.get('trusted')}"
		 	for i, v in interfaces.items()
		)
	try: 
		template = template_env.get_template("security/dhcp_snooping.j2")
		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure DHCP Snooping | "
						f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Option 82: {option82} | Transport: {conn.transport}"
				)
			}
		global_commands = template.render(
				enabled_vlans=enabled_vlans,
				option82=option82
			).splitlines()
		
		conn.send_config_set(global_commands)

		for intf in interface_list: 
			commands = [
				l.strip()
				for l in template.render(
						interface=intf.get("interface"),
						trusted=intf.get("trusted"),
						rate_limit=intf.get("rate_limit")
					).splitlines()
					if l.strip()
			]
			conn.send_config_set(commands)

		log.info(
			"snooping_config",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "snooping_automation",
	            "event_type": "snooping_config",
	            "transport": conn.transport,
	            "status": StepStatus.SUCCESS.value,
	            "VLANs": enabled_vlans,
	            "interfaces": interface_log,
	            "option82": option82,
	            "message": (
	            		f"DHCP Snooping Configuration Successful | "
	            		f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Option 82: {option82} "
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"DHCP Snooping Configuration Successful | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Option 82: {option82} | Transport: {conn.transport}"
	            	)
			}

	except Exception as e: 
		log.error(
	        "snooping_automation",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "snooping_automation",
	            "event_type": "snooping_config",
	            "transport": conn.transport,
	            "status": StepStatus.ERROR.value,
	           	"VLANs": enabled_vlans,
	            "interfaces": interface_log,
	            "option82": option82,
	            "error": str(e),
	            "message": (f"Try/Exception Error | DHCP Snooping Configuration | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Option 82: {option82} | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | DHCP Snooping Configuration | "
	            		    f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Option 82: {option82} | Transport: {conn.transport} | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}