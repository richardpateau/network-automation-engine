from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli.collector import collect_device_state
from src.remediation.switching.vlan import configure_vlan
from src.collectors.cli.builders import build_vlan
from src.compliance.switching.vlan.check import check_vlan
from src.core.settings import DRY_RUN

def compliance_vlans(sesh, device_ip, context, device_state, device_result, log, transport):
    exp_vlans = context.get("vlans", [])
    act_vlans = build_vlan(device_state)
    vlan_updated = False
    for vlan_data in exp_vlans:
        ok, failures = check_vlan(vlan_data, act_vlans)
        vlan_name = vlan_data.get("name", "")
        vlan_id = vlan_data.get("vlan_id", None)
        log_extra = {
            "device_ip": device_ip,
            "event_type": "compliance_vlan",
            "component": "main_process",
            "protocol": "vlan",
            "transport": transport,
            "vlan_name": vlan_name,
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
                    "detail": "VLAN Configuration Already Compliant"
    
                }
            )
            device_result["actions_taken"].append(
                f"VLAN Already Compliant | "
                f"VLAN: {vlan_id} | Name: {vlan_name}"
            )
            continue
    
        device_result["initial_issues"].extend(failures)
    
        log.warning(
            "vlan_drift",
            extra={
                **log_extra,
                "status": StepStatus.FAILED.value,
                "detail": "VLAN Configuration Non-Compliant"
            }
        )
        if DRY_RUN: 
            device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure VLANs | VLAN: {vlan_id} | Name: {vlan_name}"
                )
            continue
        result = configure_vlan(sesh, vlan_data, log, device_ip, transport)
        summary = result.get("summary")
        if summary:
            device_result["actions_taken"].append(summary)
        if result.get("status") == OperationalStatus.SUCCESS.value:
            vlan_updated = True
        else:
            device_result["status"] = OperationalStatus.FAILED_CONFIG.value 
            device_result["critical_issues"].append(
                    f"Failed To Remediate VLAN | VLAN: {vlan_id} | Name: {vlan_name}"
                )
    
    if vlan_updated and not DRY_RUN:
        new_state = collect_device_state(sesh)
        new_vlan = build_vlan(new_state)
        for vlan_data in exp_vlans:
            vlan_name = vlan_data.get("name", "")
            vlan_id = vlan_data.get("vlan_id", None)
            ok, failures = check_vlan(vlan_data, new_vlan)
            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "vlan",
                "event_type": "compliance_vlan",
                "transport": transport,
                "vlan_name": vlan_name,
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
                        "detail": "VLAN Configuration Post Validation Failed"
                    }
                )
            else:
                device_result["actions_taken"].append(
                    f"VLAN Configuration Post Validation Successful | "
                    f"VLAN: {vlan_id} | Name: {vlan_name}"
                )
                log.info(
                    "vlan_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "detail": "VLAN Configuration Post Validation Successful"
                    }
                )
    return device_result