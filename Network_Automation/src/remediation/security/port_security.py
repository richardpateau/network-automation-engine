from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env
def configure_psecurity(conn, ps_data, log):
	interfaces = ps_data.get("interfaces", {})
	ps_log = " | ".join(
			f"Interface: {i} | Enabled: {v.get('enabled')} | Maximum: {v.get('maximum')} | "
			f"Sticky: {v.get('sticky')} | MAC Addresses: {v.get('mac_addresses')}"
			for i, v in interfaces.items()
		)
	interface_list = [
		{  	"interface": i,
			"enabled": v.get('enabled'),
			"maximum": v.get('maximum'),
			"violation": v.get('violation'),
			"sticky": v.get('sticky'),
			"mac_addresses": v.get('mac_addresses'),
		}
		for i, v in interfaces.items()
	]

	try:
		template = template_env.get_template("security/port_security.j2")
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure Port Security | "
						f"{ps_log}"
				)
			}
		for intf in interface_list: 
			commands = [ 
					line.strip()
					for line in template.render(
					interface=intf.get("interface"),
					enabled=intf.get("enabled"),
					maximum=intf.get("maximum"),
					violation=intf.get("violation"),
					sticky=intf.get("sticky"),
					mac_addresses=intf.get("mac_addresses", [])
				).splitlines()
				if line.strip()
			]
			conn.send_config_set(commands)

		log.info(
			"ps_config",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "ps_automation",
	            "event_type": "ps_config",
	            "transport": conn.transport,
	            "status": StepStatus.SUCCESS.value,
	            "port_security_interfaces": ps_log,
	            "message": (
	            		f"Port Security Configuration Successful | "
	            		f"{ps_log} "
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"Port Security Configuration Successful | "
	            			f"{ps_log} | Transport: {conn.transport}"
	            	)
			}

	except Exception as e: 
		log.error(
	        "ps_config",
	        extra={
	            "device_ip": conn.device_ip,
	            "component": "ps_automation",
	            "event_type": "ps_config",
	            "tranport": conn.transport,
	            "status": StepStatus.ERROR.value,
	            "interfaces": ps_log,
	            "error": str(e),
	            "message": (f"Try/Exception Error | Port Security Configuration | "
	            			f"{ps_log} | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Port Security Configuration | "
	            		    f"{ps_log} | Transport: {conn.transport} | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}