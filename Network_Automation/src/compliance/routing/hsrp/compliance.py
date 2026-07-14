from src.core.enums import StepStatus, OperationalStatus
from src.collectors.netconf import collect_netconf_state
from src.compliance.routing.hsrp_helpers import (build_hsrp, check_hsrp,)
from src.remediation.routing.hsrp import configure_hsrp
from config import DRY_RUN

def compliance_hsrp(sesh, device_ip, context, device_state, device_result, log):
	exp_hsrp = context.get("hsrp", [])
	act_hsrp = build_hsrp(device_state)
	hsrp_updated = False

	for hsrp_data in exp_hsrp:
	    group_num = hsrp_data.get("group", None)
	    interface = hsrp_data.get("interface", "")
	    priority = hsrp_data.get("priority", None)
	    vlan_id = hsrp_data.get("router_vlan", None)
	    version = hsrp_data.get("version", None)
	    vip = hsrp_data.get("vip", "")

	    ok, failures = check_hsrp(hsrp_data, act_hsrp)

	    log_extra = {
	        "device_ip": device_ip,
	        "component": "main_process",
	        "protocol": "hsrp",
	        "transport": sesh.transport,
	        "group": group_num,
	        "interface": interface,
	        "priority": priority,
	        "vlan_id": vlan_id,
	        "version": version,
	        "vip": vip,
	        "failures_count": len(failures) if failures else 0,
	        "failures": failures
	    }

	    if ok:
	        log.info(
	            "hsrp_compliant",
	            extra={
	                **log_extra,
	                "status": StepStatus.SUCCESS.value,
	                "message": "HSRP Configuration Already Compliant"
	            }
	        )
	        device_result["actions_taken"].append(
	            "HSRP Configuration Already Compliant | "
	            f"Group: {group_num} | Interface: {interface} | "
	            f"Priority: {priority} | VLAN: {vlan_id} | "
	            f"Version: {version} | VIP: {vip}"
	        )
	        continue

	    device_result["initial_issues"].extend(failures)

	    log.warning(
	        "hsrp_non_compliant",
	        extra={
	            **log_extra,
	            "status": StepStatus.FAILED.value,
	            "message": "HSRP Configuration Non-Compliant"
	        }
	    )
	    result = configure_hsrp(sesh, device_ip, hsrp_data, log)
	    summary = result.get("summary")

	    if summary:
	        device_result["actions_taken"].append(summary)
	    if result.get("status") == OperationalStatus.SUCCESS.value:
	        hsrp_updated = True
	    else:
	        device_result["status"] = OperationalStatus.FAILED_CONFIG.value

	if hsrp_updated and not DRY_RUN:
	    new_state = collect_netconf_state(sesh, log)
	    new_hsrp = build_hsrp(new_state)

	    for hsrp_data in exp_hsrp:
	        group_num = hsrp_data.get("group", None)
	        interface = hsrp_data.get("interface", "")
	        priority = hsrp_data.get("priority", None)
	        vlan_id = hsrp_data.get("router_vlan", None)
	        version = hsrp_data.get("version", None)
	        vip = hsrp_data.get("vip", "")

	        ok, failures = check_hsrp(hsrp_data, new_hsrp)

	        log_extra = {
	            "device_ip": device_ip,
	            "component": "main_process",
	            "protocol": "hsrp",
	            "transport": sesh.transport,
	            "group": group_num,
	            "interface": interface,
	            "priority": priority,
	            "vlan_id": vlan_id,
	            "version": version,
	            "vip": vip,
	            "failures_count": len(failures) if failures else 0,
	            "failures": failures
	        }

	        if not ok:
	            log.error(
	                "hsrp_post_validation_failed",
	                extra={
	                    **log_extra,
	                    "status": StepStatus.FAILED.value,
	                    "message": "HSRP Configuration Post Validation Failed"
	                }
	            )
	            device_result["critical_issues"].extend(failures)
	            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value

	        else:
	            device_result["actions_taken"].append(
	                "HSRP Configuration Post Validation Successful | "
	                f"Group: {group_num} | Interface: {interface} | "
	                f"Priority: {priority} | VLAN: {vlan_id} | "
	                f"Version: {version} | VIP: {vip}"
	            )
	            log.info(
	                "hsrp_post_validation_success",
	                extra={
	                    **log_extra,
	                    "status": StepStatus.SUCCESS.value,
	                    "message": "HSRP Configuration Post Validation Successful"
	                }
	            )
	return device_result