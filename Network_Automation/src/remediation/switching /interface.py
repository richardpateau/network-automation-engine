from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_interface(conn, interface_data, log): 
	interface = interface_data.get("interface", "")
	description = interface_data.get("description", "")
	should_be_up = interface_data.get("should_be_up", False)
	if should_be_up: 
		state = "no shutdown"
	else: 
		state = "shutdown"
	try: 
		template = template_env.get_template("interface.j2")
		commands = template.render(
				interface=interface,
				description=description,
				state=state
			).splitlines()
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (f"[DRY_RUN] Would Change Interface Status | Interface: {interface} "
							f"| Should Be Up/Up: {should_be_up}" 
                	)
			}

		conn.send_config_set(commands)

		log.info(
            "interface_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "interface_automation",
                "event_type": "interface_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "should_be_up": should_be_up,
                "message": (f"Interface Status Successfully changed | Interface: {interface} "
						    f"| Should Be Up/Up: {should_be_up}" 
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (f"Interface Status Successfully Changed | Interface: {interface} "
						    f"| Should Be Up/Up: {should_be_up}" 
                	)
			}
	except Exception as e: 
		log.info(
            "interface_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "interface_automation",
                "event_type": "interface_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "should_be_up": should_be_up,
                "message": (f"Try/Exception Error | Interface Status Configuration | "
                			f"Interface: {interface} | "
                			f"Should Be Up/Up: {should_be_up} | Error: {e}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(f"Try/Exception Error | Interface Status Configuration | "
                		   f"Interface: {interface} | "
                			f"Should Be Up/Up: {should_be_up} | Error: {e}"
                	),
				"error": str(e)
			}