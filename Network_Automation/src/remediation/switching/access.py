from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_access(conn, access_data, log): 
	access_interface = access_data.get("access_interface", "")
	access_vlan = access_data.get("access_vlan", "")

	try: 
		template = template_env.get_template("access_port.j2")
		commands = template.render(
				access_interface=access_interface,
				access_vlan=access_vlan
			).splitlines()
		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure Access Port | Interface: {access_interface} | "
						f"VLAN: {access_vlan}"
                	)
			}
		conn.send_config_set(commands)

		log.info(
            "access_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "access_port_automation",
                "event_type": "access_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "vlan_id": access_vlan,
 				"interface": access_interface,
                "message": (f"Access Port configured successfully | "
                			f"Interface: {access_interface} | VLAN: {access_vlan}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary":(f"Access Port configured successfully | "
                		   f"Interface: {access_interface} | VLAN: {access_vlan}"
                	)
			}
	except Exception as e: 
		log.error(
            "access_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "access_port_automation",
                "event_type": "access_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "vlan_id": access_vlan,
 				"interface": access_interface,
                "message": (f"Try/Exception Error | Access Port Configuration | "
                			f"Interface: {access_interface} | VLAN: {access_vlan}"
                			f" | Error: {e}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(f"Try/Exception Error | Access Port Configuration | "
                			f"Interface: {access_interface} | VLAN: {access_vlan}"
                			f" | Error: {e}"
                	),
				"error": str(e)
			}