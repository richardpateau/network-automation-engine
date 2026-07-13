from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli import collect_device_state
from src.remediation.switching.trunk import configure_trunk
from src.compliance.switching.trunk_helpers import (build_trunk,check_trunk,)
from config import DRY_RUN

def compliance_trunk(sesh, device_ip, context, device_state, device_result, log):
	exp_trunk = context.get("trunk_ports", [])
	act_trunk = build_trunk(device_state)
	trunk_updated = False

	for trunk_data in exp_trunk:
	    trunk_interface = trunk_data.get("trunk_interface", "")
	    allowed_vlans = trunk_data.get("allowed_vlans", "")

	    ok, failures = check_trunk(trunk_data, act_trunk)

	    log_extra = {
	        "device_ip": device_ip,
	        "component": "main_process",
	        "protocol": "trunk",
	        "transport": sesh.transport,
	        "trunk_interface": trunk_interface,
	        "allowed_vlans": allowed_vlans,
	        "compliant": ok,
	        "failure_count": len(failures) if failures else 0,
	        "failures": failures
	    }
	    if ok:
	        log.info(
	            "trunk_interface_compliant",
	            extra={
	                **log_extra,
	                "status": StepStatus.SUCCESS.value,
	                "message": f"Trunk Interface Already Compliant"
	            }
	        )
	        device_result["actions_taken"].append(
	            f"Trunk Interface Already Compliant | "
	            f"Interface: {trunk_interface} | "
	            f"Allowed VLAN(s): {allowed_vlans}"
	        )
	        continue

	    device_result["initial_issues"].extend(failures)

	    log.warning(
	        "trunk_interface_drift",
	        extra={
	            **log_extra,
	            "status": StepStatus.FAILED.value,
	            "message": (
	                f"Trunk Interface Non-Compliant"
	            )
	        }
	    )

	    result = configure_trunk(sesh, trunk_data, log)
	    summary = result.get("summary")
	    if summary:
	        device_result["actions_taken"].append(summary)
	    if result.get("status") == OperationalStatus.SUCCESS.value:
	        trunk_updated = True
	    else:
	        device_result["status"] = OperationalStatus.FAILED_CONFIG.value 

	if trunk_updated and not DRY_RUN:
	    new_state = collect_device_state(sesh, log)
	    new_trunk = build_trunk(new_state)

	    for trunk_data in exp_trunk:
	        trunk_interface = trunk_data.get("trunk_interface", "")
	        allowed_vlans = trunk_data.get("allowed_vlans", "")

	        ok, failures = check_trunk(trunk_data, new_trunk)

	        log_extra = {
	        "device_ip": device_ip,
	        "component": "main_process",
	        "protocol": "trunk",
	        "transport": sesh.transport,
	        "trunk_interface": trunk_interface,
	        "allowed_vlans": allowed_vlans,
	        "compliant": ok,
	        "failure_count": len(failures) if failures else 0,
	        "failures": failures
	    		}

	        if not ok:
	            device_result["critical_issues"].extend(failures)
	            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value 
	            log.error(
	                "trunk_interface_post_validation_failed",
	                extra={
	                    **log_extra,
	                    "status": StepStatus.FAILED.value,
	                    "message": (
	                        f"Trunk Interface Configuration Post Validation Failed"
	                    )
	                }
	            )
	        else:
	            device_result["actions_taken"].append(
	                f"Trunk Interface Post Validation Successful | "
	                f"Interface: {trunk_interface} | "
	                f"Allowed VLAN(s): {allowed_vlans}"
	            )
	            log.info(
	                "trunk_interface_post_validation_success",
	                extra={
	                    **log_extra,
	                    "status": StepStatus.SUCCESS.value,
	                    "message": "Trunk Interface Configuration Post Validation Successful"
	                }
	            )
	return device_result