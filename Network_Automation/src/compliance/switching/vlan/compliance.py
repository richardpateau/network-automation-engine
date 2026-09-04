from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_vlan
from src.compliance.switching.vlan.check import check_vlan, check_rogue_vlan
from src.remediation.switching.vlan import configure_vlan
from src.core.settings import DRY_RUN

def compliance_vlan(sesh, device_ip, context, device_state, device_result, log):
    exp_vlans = context.get("vlans", [])
    act_vlans = build_vlan(device_state)
    vlan_updated = False
    for vlan_data in exp_vlans:

        vlan_id = vlan_data.get("vlan_id")
        name = vlan_data.get("name")
        ok, failures = check_vlan([vlan_data], act_vlans)

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
        if DRY_RUN:
            device_result["actions_taken"].append(
                f"[DRY_RUN] Would Configure VLAN | VLAN: {vlan_id} | "
                f"Name: {name}"
            )
            continue

        result = configure_vlan(sesh, vlan_data, log)
        summary = result.get("summary")
        if summary:
            device_result["actions_taken"].append(summary)
        if result.get("status") == OperationalStatus.SUCCESS.value:
            vlan_updated = True
        else:
            device_result["status"] = OperationalStatus.FAILED_CONFIG.value
            device_result["critical_issues"].append(
                f"Failed To Remediate VLAN | VLAN: {vlan_id} | "
                f"Name: {name}"
            )
    rogue_ok, rogue_failures = check_rogue_vlan(
        exp_vlans,
        act_vlans
    )

    if not rogue_ok:
        device_result["initial_issues"].extend(rogue_failures)

        log.warning(
            "vlan_rogue",
            extra={
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "vlan",
                "transport": sesh.transport,
                "name": "",
                "vlan_id": "",
                "compliant": False,
                "failure_count": len(rogue_failures),
                "failures": rogue_failures,
                "status": StepStatus.FAILED.value,
                "message": "Rogue VLAN Detected"
            }
        )

    if vlan_updated and not DRY_RUN:
        new_state = collect_device_state(sesh)
        new_vlan = build_vlan(new_state)

        for vlan_data in exp_vlans:
            vlan_id = vlan_data.get("vlan_id")
            name = vlan_data.get("name")

            ok, failures = check_vlan([vlan_data], new_vlan)

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