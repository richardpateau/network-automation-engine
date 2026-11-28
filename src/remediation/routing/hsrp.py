import re 
from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_hsrp(session, hsrp_data, device_ip, transport, log): 
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
	ip = hsrp_data.get("ip")
	mask = hsrp_data.get("mask")
	try: 
		template = template_env.get_template("hsrp.j2")
		commands = template.render(
				interface_type=interface_type,
				int_num=int_num,
				version=version,
				group=group,
				vip=vip,
				preempt=preempt,
				priority=priority,
				router_vlan=router_vlan,
				ip=ip,
				mask=mask
			)
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure HSRP | "
						f"Interface: {interface} | Version: {version} | "
						f"Group: {group} | VLAN: {router_vlan} | "
						f"VIP: {vip} | Preempt: {preempt} | Transport: {transport}"
				)
			}

		
		session.session.edit_config(
			target="running",
			config=commands
		)
		
		log.info(
			"hsrp_automation",
            extra={
                "device_ip": device_ip,
                "component": "hsrp_config",
                "event_type": "hsrp_config",
                "transport": transport,
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "group": group,
                "vlan_id": router_vlan,
                "vip": vip,
                "version": version,
                "detail": (
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
							f"VIP: {vip} | Preempt: {preempt} | Transport: {transport}"
                	)
			}
	
	except Exception as e: 
		log.exception(
            "hsrp_config",
            extra={
                "device_ip": device_ip,
                "component": "hsrp_automation",
                "event_type": "hsrp_config",
                "transport": transport,
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "group": group,
                "vlan_id": router_vlan,
                "vip": vip,
                "version": version,
                "error": str(e),
                "detail": (f"Try/Exception Error | HSRP Configuration | "
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
							f"VIP: {vip} | Preempt: {preempt} | Transport: {transport} | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}