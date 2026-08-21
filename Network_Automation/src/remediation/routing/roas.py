import re 
from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_roas(session, roas_data, log): 
	interface = roas_data.get("interface", "")
	router_vlan = roas_data.get("router_vlan", "")
	ip = roas_data.get("ip", "")
	mask = roas_data.get("mask", "")
	new_int = re.search(r'[\d./]+$', interface).group()

	try: 
		template = template_env.get_template("restconf_roas.j2")
		commands = template.render(
				new_interface=new_int,
				router_vlan=router_vlan,
				ip=ip,
				mask=mask
			)
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure ROAS | "
						f"Interface: {interface} | VLAN: {router_vlan} | "
						f"IP: {ip}/{mask} | Transport: {session.transport}"
				)
			}
		response = session.patch(
				url=f"{session.base_url}/Cisco-IOS-XE-native:native/interface",
				data=commands
			)
		if response.status_code not in [200,201,204]: 
			return {
                "status": OperationalStatus.CONFIG_FAILED.value,
                "summary": (f"ROAS config failed {response.text}"
                		    f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask}"
                	),
                "error": response.text
            }

		log.info(
            "roas_config",
            extra={
                "device_ip": session.device_ip,
                "component": "roas_automation",
                "event_type": "roas_config",
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "vlan_id": router_vlan,
                "ip": f"{ip}/{mask}",
                "message": (f"ROAS Successfully Configured | "
						    f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (f"ROAS Successfully Configured | "
						    f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask} | Transport: {session.transport}"
                	)
			}
	except Exception as e: 
		log.error(
            "roas_config",
            extra={
                "device_ip": sessiondevice_ip,
                "component": "roas_automation",
                "event_type": "roas_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "vlan_id": router_vlan,
                "ip": f"{ip}/{mask}",
                "message": (f"Try/Exception Error | ROAS Configuration | "
                			f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(f"Try/Exception Error | ROAS Configuration | "
                			f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask} | Transport: {session.transport}"
                	),
				"error": str(e)
			}