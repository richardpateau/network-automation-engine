from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env
import re
def configure_qos(session, qos_data, log):
	policy_name = qos_data.get("policy_name", "")
	attachments = qos_data.get("attachments", [])
	class_maps = qos_data.get("class_maps", [])
	attachment_log = " | ".join(
			f"{a.get('interface')} {a.get('direction')}"
			for a in attachments
		)
	class_map_log = " | ".join(
			f"{c.get('name')} {c.get('protocol')} {c.get('action_type')} {c.get('bandwidth')}"
			for c in class_maps
		)
	try:
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure QOS | "
						f"Policy: {policy_name} | "
						f"Class Map: {class_map_log} | Config: {attachment_log} | "
						f"Transport: {session.transport}"
				)
			}
		policy_template = template_env.get_template("services/qos_netconf.j2")
		policy_commands = policy_template.render(
				class_maps=class_maps,
				policy_name=policy_name
			)

		session.edit_config(
					target="running",
					config=policy_commands
				)

		interface_template = template_env.get_template("services/qos_interface_netconf.j2")
		for a in attachments:
			interface = a.get("interface", "")
			direction = a.get("direction", "")

			match = re.match(r"([A-Za-z]+)([\d.]+)$", interface)

			interface_type = match.group(1)
			interface_num = match.group(2)

			attachment_commands = interface_template.render(
				interface_type=interface_type,
				interface_num=interface_num,
				direction=direction,
				policy_name=policy_name
			)
			session.edit_config(
				target="running",
				config=attachment_commands
			)
		log.info(
			"qos_config",
            extra={
                "device_ip": session.device_ip,
                "component": "qos_automation",
                "event_type": "qos_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "policy_name": policy_name,
                "class_maps": class_map_log,
                "attachments": attachment_log,
                "message": (
		                		f"QOS Configuration Successful | "
		                		f"Policy: {policy_name} | "
								f"Class Map: {class_map_log} | Config: {attachment_log} "
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
						 		f"QOS Configuration Successful | "
	                		    f"Policy: {policy_name} | "
								f"Class Map: {class_map_log} | Config: {attachment_log} | "
								f"Transport: {session.transport}"
                	)
			}

	except Exception as e:
		log.error(
            "qos_config",
            extra={
                "device_ip": session.device_ip,
                "component": "qos_automation",
                "event_type": "qos_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "policy_name": policy_name,
                "class_maps": class_map_log,
                "attachments": attachment_log,
                "error": str(e),
                "message": (f"Try/Exception Error | QOS Configuration | "
                			f"Policy: {policy_name} | "
							f"Class Map: {class_map_log} | Config: {attachment_log}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | QOS Configuration | "
                			f"Policy: {policy_name} | "
							f"Class Map: {class_map_log} | Transport: {session.transport}"
                	),
				"error": str(e)
			}
