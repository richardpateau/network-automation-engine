from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_trunk(conn, trunk_data, log): 
	trunk_interface = trunk_data.get("trunk_interface", "")
	allowed_vlans = trunk_data.get("allowed_vlans", "")

	try: 
		template = template_env.get_template("trunk_ports.j2")
		commands = template.render(
				trunk_interface=trunk_interface,
				allowed_vlans=allowed_vlans
			).splitlines()

		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (f"[DRY_RUN] Would Configure Trunk Interface | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans}"
                	)
			}

		conn.send_config_set(commands)

		log.info(
            "trunk_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "trunk_automation",
                "event_type": "trunk_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "trunk_interface": trunk_interface,
                "allowed_vlans": allowed_vlans,
                "message": (f"Trunk Interface configured successfully | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (f"Trunk Interface configured successfully | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans}"
                	)
			}
	except Exception as e: 
		log.error(
            "trunk_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "trunk_automation",
                "event_type": "trunk_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "trunk_interface": trunk_interface,
                "allowed_vlans": allowed_vlans,
                "message": (f"Try/Exception Error | Trunk Interface Configuration | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans} | Error: {e}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(f"Try/Exception Error | Trunk Interface Configuration | "
                		   f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans} | Error: {e}"
                	),
				"error": str(e)
			}