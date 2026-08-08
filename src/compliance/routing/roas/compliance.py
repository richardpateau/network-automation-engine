from src.core.enums import StepStatus, OperationalStatus
from src.collectors.restconf import collect_restconf_state
from src.remediation.routing.roas import configure_roas
from src.compliance.routing.roas_helpers import (
    build_roas,
    check_roas,
)
from config import DRY_RUN


def compliance_roas(sesh, device_ip, context, device_state, device_result, log):
    actual_roas = build_roas(device_state)
    expected_roas = context.get("roas", [])
    roas_updated = False
    for roas_data in expected_roas:
        ok, failures = check_roas(roas_data, actual_roas)
        interface = roas_data.get("interface", "")
        vlan = roas_data.get("router_vlan", None)
        ip = roas_data.get("ip", "")
        mask = roas_data.get("mask", "")

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "roas",
            "transport": sesh.transport,
            "interface": interface,
            "vlan_id": vlan,
            "ip/mask": f"{ip}/{mask}",
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }
        if ok:
            log.info(
                "roas_check",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "ROAS Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                f"ROAS Configuration Already Compliant | {interface} | "
                f"VLAN: {vlan} | IP/Mask: {ip}/{mask}"
            )
            continue

        device_result["initial_issues"].extend(failures)

        log.warning(
            "roas_drift",
            extra={
                **log_extra,
                "status": StepStatus.FAILED.value,
                "message": "ROAS Configuration Non-Compliant",
            },
        )
        if DRY_RUN:
            device_result["actions_taken"].append(
                f"[DRY_RUN] Would Configure ROAS | Interface: {interface} | "
                f"VLAN: {vlan} | IP/Mask: {ip}/{mask}"
            )
            continue

        result = configure_roas(sesh, roas_data, log)

        summary = result.get("summary")
        if summary:
            device_result["actions_taken"].append(summary)

        if result.get("status") == OperationalStatus.SUCCESS.value:
            roas_updated = True
        else:
            device_result["status"] = OperationalStatus.FAILD_CONFIG.value
            device_result["critical_issues"] = (
                f"Failed to Remediate ROAS | Interface: {interface} | "
                f"VLAN: {vlan} | IP/Mask: {ip}/{mask}"
            )

    if roas_updated and not DRY_RUN:
        new_roas = collect_restconf_state(sesh, log)
        new_state = build_roas(new_roas)

        for roas_data in expected_roas:
            ok, failures = check_roas(roas_data, new_state)
            interface = roas_data.get("interface", "")
            vlan = roas_data.get("router_vlan", None)
            ip = roas_data.get("ip", "")
            mask = roas_data.get("mask", "")

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "roas",
                "transport": sesh.transport,
                "interface": interface,
                "vlan_id": vlan,
                "ip/mask": f"{ip}/{mask}",
                "compliant": ok,
                "failures_count": len(failures) if failures else 0,
                "failures": failures,
            }
            if not ok:
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
                log.error(
                    "roas_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "ROAS Configuration Post Validation Failed",
                    },
                )
            else:
                device_result["actions_taken"].append(
                    f"ROAS Configuration Validation Successful | Interface: {interface} | "
                    f"VLAN: {vlan} | IP/Mask: {ip}/{mask}"
                )
                log.info(
                    "roas_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "ROAS Configuration Post Validation Successful",
                    },
                )
    return device_result
