def configure_cdp_netconf(session, cdp_data, log): 
	enabled = cdp_data.get("enabled", False)
	timer = cdp_data.get("timer", None)
	holdtime = cdp_data.get("holdtime", None)
	interfaces = cdp_data.get("interfaces", {})
	int_log = " | ".join(
	     f"Interface/Enabled: {i}/{v.get('enabled')}" 
		 for i, v in interfaces.items()
		)
	try: 
		template_global = template_env.get_template("CDP_NC.j2")
		template_int = template_env.get_template("CDP_INT_NC.j2")
		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure CDP | "
						f"Enabled: {enabled} | Timer: {timer} | "
						f"HoldTime: {holdtime} | {int_log} | "
						f"Transport: {session.transport}"
				)
			}
		global_commands = template_global.render(
				holdtime=holdtime, 
				timer=timer,
				enabled=enabled
			)
		session.edit_config(
				target="running",
				config=global_commands
			)
		for interface, int_value in interfaces.items():
			match = re.match(r"([A-Za-z]+)(.+)", interface)
			interface_type = match.group(1) if match else ""
			interface_num = match.group(2) if match else ""
			int_enabled = int_value.get("enabled", False)

			int_commands = template_int.render(
					interface_type=interface_type,
					interface_num=interface_num,
					enabled=int_enabled
				)
			session.edit_config(target="running", config=int_commands)

		log.error(
			"cdp_config",
	        extra={
	            "device_ip": session.device_ip,
	            "component": "cdp_automation",
	            "event_type": "cdp_config",
	            "transport": session.transport,
	            "status": StepStatus.SUCCESS.value,
	            "globally_enabled": enabled,
	            "timer/holdtime": f"{timer}/{holdtime}",
	            "interfaces": int_log,
	            "message": (
	            		f"CDP Configuration Successful | "
	            		f"Enabled: {enabled} | Timer: {timer} | "
						f"HoldTime: {holdtime} | {int_log} "
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"CDP Configuration Successful | "
		            		f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: {session.transport}"
	            	)
			}

	except Exception as e: 
		log.info(
	        "cdp_config",
	        extra={
	            "device_ip": session.device_ip,
	            "component": "cdp_automation",
	            "event_type": "cdp_config",
	            "transport": session.transport,
	            "status": StepStatus.ERROR.value,
	           	"globally_enabled": enabled,
	            "timer/holdtime": f"{timer}/{holdtime}",
	            "interfaces": int_log,
	            "error": str(e),
	            "message": (f"Try/Exception Error | CDP Configuration | "
	            			f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | CDP Configuration | "
	            			f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: {session.transport} | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}