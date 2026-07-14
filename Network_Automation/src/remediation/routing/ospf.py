import re 
from src.core.settings import DRY_RUN
from src.core.enums import StepStatus, OperationalStatus
from src.remediation.template_env import template_env

def configure_ospf(session, ospf_data, log): 
	process_id = ospf_data.get("process_id", "")
	router_id = ospf_data.get("router_id", "")
	network_list = ospf_data.get("network_list", [])
	network = ",".join(
			f"{n['subnet']}/{n['wildcard']} area {n['area']}"
			for n in network_list
		)
	try: 
		template = template_env.get_template("OSPF.j2")
		commands = template.render(
				process_id=process_id,
				router_id=router_id,
				network_list=network_list
			)
		if DRY_RUN:
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure OSPF | "
						f"Process ID: {process_id} | "
						f"RID: {router_id} | Networks: {network} | Transport: {session.transport}"
				)
			}
		response = session.patch( 
				url = f"{session.base_url}/Cisco-IOS-XE-native:native/router",
				data=commands
			)
		if response.status_code not in [200,201,204]: 
			return {
                "status": OperationalStatus.CONFIG_FAILED.value,
                "summary": (
                			f"OSPF config failed {response.text}"
                		    f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: {session.transport}"
                	),
                "error": response.text
            }

		log.info(
            "ospf_config",
            extra={
                "device_ip": session.device_ip,
                "component": "ospf_automation",
                "event_type": "ospf_config",
                "transport": session.transport,
                "status": StepStatus.SUCCESS.value,
                "process_id": process_id,
                "RID": router_id,
                "networks": network,
                "message": (
                			f"OSPF Successfully Configured | "
						    f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network}"
                	)
            }

        )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"OSPF Successfully Configured | "
						    f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: {session.transport}"
                	)
			}
	except Exception as e: 
		log.info(
            "ospf_config",
            extra={
                "device_ip": session.device_ip,
                "component": "ospf_automation",
                "event_type": "ospf_config",
                "transport": session.transport,
                "status": StepStatus.ERROR.value,
                "process_id": process_id,
                "RID": router_id,
                "networks": network,
                "message": (f"Try/Exception Error | OSPF Configuration | "
                			f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network}"
                	)
            }

        )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | OSPF Configuration | "
                			f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: {session.transport}"
                	),
				"error": str(e)
			}