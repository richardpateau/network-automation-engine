from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_access
from src.compliance.switching.access.check import check_access
from src.remediation.switching.access import configure_access
from src.core.settings import DRY_RUN

def compliance_access(sesh, device_ip, context, device_state, device_result, log):
    exp_access = context.get("access_ports", [])
    act_access = build_access(device_state)
    access_updated = False
    for access_data in exp_access:
        access_interface = access_data.get("access_interface", None)
        access_vlan = access_data.get("access_vlan", None)

        ok, failures = check_access(access_data, act_access)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "access_interface",
            "transport": sesh.transport,
            "interface": access_interface,
            "vlan_id": access_vlan,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures
        }
        if ok:
            log.info(
                "access_interface_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "Access Interface Already Compliant"
                }
            )
            device_result["actions_taken"].append(
                f"Access Interface Already Compliant | "
                f"Interface: {access_interface} | "
                f"VLAN: {access_vlan}"
            )
            continue

        device_result["initial_issues"].extend(failures)

        log.warning(
            "access_interface_drift",
            extra={
                **log_extra,
                "status": StepStatus.FAILED.value,
                "message": "Access Port Configuration Non-Compliant "

            }
        )
        if DRY_RUN: 
            device_result["actions_taken"].append(
                    "[DRY_RUN] Would Configure Access Port | "
                    f"Interface: {access_interface} | "
                    f"VLAN: {access_vlan}"
                )
        else: 
            result = configure_access(sesh, access_data, log)
            summary = result.get("summary")
            if summary:
                device_result["actions_taken"].append(summary)
            if result.get("status") == OperationalStatus.SUCCESS.value:
                access_updated = True
            else:
                device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                device_result["critical_issues"].append(
                        "Failed To Remediate Access Port | "
                        f"Interface: {access_interface} | "
                        f"VLAN: {access_vlan}"
                    )

    if access_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_access = build_access(new_state)

        for access_data in exp_access:
            access_interface = access_data.get("access_interface", None)
            access_vlan = access_data.get("access_vlan", None)

            ok, failures = check_access(access_data, new_access)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "access_interface",
                "transport": sesh.transport,
                "interface": access_interface,
                "vlan_id": access_vlan,
                "compliant": ok,
                "failures_count": len(failures) if failures else 0,
                "failures": failures
            }
            if not ok:
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
                log.error(
                    "access_interface_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "Access Port Configuration Post Validation Failed"
                    }
                )
            else:
                device_result["actions_taken"].append(
                    f"Access Interface Post Validation Successful | "
                    f"Interface: {access_interface} | "
                    f"VLAN: {access_vlan}"
                )
                log.info(
                    "access_interface_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "Access Interface Post Validation Successful"
                    }
                )
    return device_result