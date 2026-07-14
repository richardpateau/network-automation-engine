from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli import collect_device_state
from src.remediation.switching.vlan import configure_vlan
from src.compliance.switching.vlan_helpers import (build_vlan,check_vlan,)
from config import DRY_RUN

def compliance_vlans(sesh, device_ip, context, device_state, device_result, log):
	exp_vlans = context.get("vlans", [])
    act_vlans = build_vlan(device_state)
    vlan_updated = False
    for vlan_data in exp_vlans:
        ok, failures = check_vlan(vlan_data, act_vlans)
        name = vlan_data.get("name", "")
        vlan_id = vlan_data.get("vlan_id", None)
    
        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "vlan",
            "transport": sesh.transport,
            "name": name,
            "vlan_id": vlan_id,
            "compliant": ok,
            "failure_count": len(failures) if failures else 0,
            "failures": failures
        }
        if ok:
            log.info(
                "vlan_check",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "VLAN Configuration Already Compliant"
    
                }
            )
            device_result["actions_taken"].append(
                f"VLAN Already Compliant | "
                f"VLAN: {vlan_id} | Name: {name}"
            )
            continue
    
        device_result["initial_issues"].extend(failures)
    
        log.warning(
            "vlan_drift",
            extra={
                **log_extra,
                "status": StepStatus.FAILED.value,
                "message": "VLAN Configuration Non-Compliant"
            }
        )
    
        result = configure_vlan(sesh, vlan_data, log)
        summary = result.get("summary")
        if summary:
            device_result["actions_taken"].append(summary)
        if result.get("status") == OperationalStatus.SUCCESS.value:
            vlan_updated = True
        else:
            device_result["status"] = OperationalStatus.FAILED_CONFIG.value 
    
    if vlan_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_vlan = build_vlan(new_state)
    
        for vlan_data in exp_vlans:
            name = vlan_data.get("name", "")
            vlan_id = vlan_data.get("vlan_id", None)
            ok, failures = check_vlan(vlan_data, new_vlan)
    
            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "vlan",
                "transport": sesh.transport,
                "name": name,
                "vlan_id": vlan_id,
                "compliant": ok,
                "failure_count": len(failures) if failures else 0,
                "failures": failures
            }
    
            if not ok:
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
                log.error(
                    "vlan_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "VLAN Configuration Post Validation Failed"
                    }
                )
            else:
                device_result["actions_taken"].append(
                    f"VLAN Configuration Post Validation Successful | "
                    f"VLAN: {vlan_id} | Name: {name}"
                )
                log.info(
                    "vlan_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "VLAN Configuration Post Validation Successful"
                    }
                )
    return device_result