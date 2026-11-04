from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_vlan(conn, vlan_data, log, device_ip, transport):
	vlan_id = vlan_data.get("vlan_id", "")
	vlan_name = vlan_data.get("name", "")

	try: 
		template = template_env.get_template("vlan.j2")
		commands = template.render(
				vlans=[vlan_data]
			).splitlines()

		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (f"[DRY_RUN] Would Configure VLANs | "
                			f"VLAN: {vlan_id} | Name: {vlan_name}"
                	)
			}

		conn.send_config_set(commands)

		log.info(
            "vlan_config",
            extra={
                "device_ip": device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "transport": transport,
                "status": StepStatus.SUCCESS.value,
                "vlan_id": vlan_id,
                "vlan_name": vlan_name,
                "detail": (f"VLAN configured successfully | "
                			f"VLAN: {vlan_id} | Name: {vlan_name}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (f"VLAN configured successfully | "
                			f"VLAN: {vlan_id} | Name: {vlan_name}"
                	)
			}
	except Exception as e: 
		log.info(
            "vlan_config",
            extra={
                "device_ip": device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "transport": transport,
                "status": StepStatus.ERROR.value,
                "vlan_id": vlan_id,
                "vlan_name": vlan_name,
                "detail": (f"Try/Exception Error | VLAN Configuration | "
                			f"VLAN: {vlan_id} | Name: {vlan_name} | Error: {e}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(f"Try/Exception Error | VLAN Configuration | "
                		   f"VLAN: {vlan_id} | Name: {vlan_name} | Error: {e}"
                	),
				"error": str(e)
			}