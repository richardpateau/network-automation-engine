import re 
from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_hsrp(session, hsrp_data, log): 
	interface = hsrp_data.get("interface", "")
	match = re.match(r"([A-Za-z]+)(.+)", interface)
	interface_type = match.group(1) if match else ""
	int_num = match.group(2) if match else ""
	version = hsrp_data.get("version", "")
	group = hsrp_data.get("group", "")
	vip = hsrp_data.get("vip", "")
	priority = hsrp_data.get("priority", "")
	preempt = hsrp_data.get("preempt", "")
	router_vlan = hsrp_data.get("router_vlan", "")
	try: 
		template = template_env.get_template("routing/hsrp_netconf.j2")
		commands = template.render(
				interface_type=interface_type,
				int_num=int_num,
				version=version,
				group=group,
				vip=vip,
				preempt=preempt,
				priority=priority
			)
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure HSRP | "
						f"Interface: {interface} | Version: {version} | "
						f"Group: {group} | VLAN: {router_vlan} | "
						f"VIP: {vip} | Preempt: {preempt} | Transport: {session.transport}"
				)
			}

		
		session.edit_config(
			target="running",
			config=commands
		)
		
		log.info(
			"hsrp_automation",
            extra={
                "device_ip": session.device_ip,
                "component": "hsrp_config",
                "event_type": "hsrp_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "group": group,
                "vlan_id": router_vlan,
                "vip": vip,
                "version": version,
                "message": (
                		f"HSRP Configuration Successful | "
                		f"Interface: {interface} | Version: {version} | "
						f"Group: {group} | VLAN: {router_vlan} | "
						f"VIP: {vip} | Preempt: {preempt} "
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"HSRP Configuration Successful | "
	                		f"Interface: {interface} | Version: {version} | "
							f"Group: {group} | VLAN: {router_vlan} | "
							f"VIP: {vip} | Preempt: {preempt} | Transport: {session.transport}"
                	)
			}
	
	except Exception as e: 
		log.error(
            "hsrp_config",
            extra={
                "device_ip": session.device_ip,
                "component": "hsrp_automation",
                "event_type": "hsrp_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "group": group,
                "vlan_id": router_vlan,
                "vip": vip,
                "version": version,
                "error": str(e),
                "message": (f"Try/Exception Error | HSRP Configuration | "
                			f"Interface: {interface} | Version: {version} | "
							f"Group: {group} | VLAN: {router_vlan} | "
							f"VIP: {vip} | Preempt: {preempt} | "
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | HSRP Configuration | "
                			f"Interface: {interface} | Version: {version} | "
							f"Group: {group} | VLAN: {router_vlan} | "
							f"VIP: {vip} | Preempt: {preempt} | Transport: {session.transport} | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}