from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_vlan(conn, vlan_data, log): 
	vlan_id = vlan_data.get("vlan_id", "")
	name = vlan_data.get("name", "")

	try: 
		template = template_env.get_template("vlan.j2")
		commands = template.render(
				vlan_id=vlan_id,
				name=name
			).splitlines()

		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (f"[DRY_RUN] Would Configure VLANs | "
                			f"VLAN: {vlan_id} | Name: {name}"
                	)
			}

		conn.send_config_set(commands)

		log.info(
            "vlan_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "vlan_id": vlan_id,
                "name": name,
                "message": (f"VLAN configured successfully | "
                			f"VLAN: {vlan_id} | Name: {name}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (f"VLAN configured successfully | "
                			f"VLAN: {vlan_id} | Name: {name}"
                	)
			}
	except Exception as e: 
		log.info(
            "vlan_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "vlan_id": vlan_id,
                "name": name,
                "message": (f"Try/Exception Error | VLAN Configuration | "
                			f"VLAN: {vlan_id} | Name: {name} | Error: {e}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(f"Try/Exception Error | VLAN Configuration | "
                		   f"VLAN: {vlan_id} | Name: {name} | Error: {e}"
                	),
				"error": str(e)
			}