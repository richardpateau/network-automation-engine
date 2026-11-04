from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def cofnigure_syslog_netmiko(conn, syslog_data, log): 
	facility = syslog_data.get("facility", "")
	hosts = syslog_data.get("hosts", [])
	source_interface = syslog_data.get("source_interface", "")
	timestamps = syslog_data.get("timestamps", False)
	trap_level = syslog_data.get("trap_level", "")

	hosts_log = " | ".join(
			f"IP: {h}"
			for h in hosts
		)

	try: 
		template_syslog = template_env.get_template("SYSLOG_NETMIKO.j2")

		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SYSLOG | "
						f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level} | Transport: NEMIKO"
				)
			}

		commands_syslog = template_syslog.render(
				facility=facility,
				trap_level=trap_level,
				hosts=hosts,
				source_interface=source_interface,
				timestamps=timestamps
			).splitlines()

		conn.send_command(commands_syslog)
		
		log.info(
			"syslog_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "transport": conn.transport,
                "status": StepStatus.SUCCESS.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "message": (
                		f"Syslog Configuration Successful | "
                		f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"Syslog Configuration Successful | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: {conn.transport}"
                	)
			}
	
	except Exception as e: 
		log.info(
            "syslog_config",
            extra={
                "device_ip": conn.device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "transport": conn.transport,
                "status": StepStatus.ERROR.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "error": str(e),
                "message": (f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: {conn.transport}"
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: {conn.transport} | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}

def configure_syslog_netconf(session, syslog_data, log): 
	facility = syslog_data.get("facility", "")
	hosts = syslog_data.get("hosts", [])
	source_interface = syslog_data.get("source_interface", "")
	timestamps = syslog_data.get("timestamps", False)
	trap_level = syslog_data.get("trap_level", "")

	hosts_log = " | ".join(
			f"IP: {h}"
			for h in hosts
		)

	try: 
		template_timestamps = template_env.get_template("SYS_Time_NC.j2")
		template_syslog = template_env.get_template("SYSLOG_NC.j2")

		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SYSLOG | "
						f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level} | Transport: {conn.transport}"
				)
			}

		commands_syslog = template_syslog.render(
				facility=facility,
				trap_level=trap_level,
				hosts=hosts,
				source_interface=source_interface,
			)
		commands_timestamps = template_timestamps.render()
		session.edit_config(
				target="running", 
				config=commands_syslog
			)
		if timestamps: 
			session.edit_config(
					target="running",
					config=commands_timestamps
				)

		log.info(
			"syslog_config",
            extra={
                "device_ip": session.device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "message": (
                		f"Syslog Configuration Successful | "
                		f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"Syslog Configuration Successful | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: {conn.transport}"
                	)
			}
	
	except Exception as e: 
		log.info(
            "syslog_config",
            extra={
                "device_ip": session.device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "error": str(e),
                "message": (f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: {conn.transport} | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}