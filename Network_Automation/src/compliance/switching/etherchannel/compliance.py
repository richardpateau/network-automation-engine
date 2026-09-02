from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli.collector import collect_device_state
from src.collectors.cli.builders import build_etherchannel
from src.compliance.switching.etherchannel.check import check_etherchannel
from src.remediation.switching.etherchannel import configure_etherchannel
from src.core.settings import DRY_RUN

def compliance_etherchannel(sesh, device_ip, context, device_state, device_result, log):
    exp_ether = context.get("etherchannel", {})
    act_ether = build_etherchannel(device_state)
    ether_updated = False
    ether_log = []
    groups = exp_ether.get("groups", {})
    if "enabled" in exp_ether:
        ether_log.append(
            f"Etherchannel Enabled: {exp_ether.get('enabled')}"
        )
    if groups:
        for g,v in groups.items():
            ether_log.append(
                f"Group Number: {g} | Interfaces: {', '.join(v.get('interfaces', []))} | "
                f"Type/Mode: {v.get('type')} - {v.get('mode')} | "
                f"Switchport Mode: {v.get('switchport_mode')}"
            )
    ether_str = " | ".join(ether_log) or "No Etherchannel Configuration"

    if exp_ether:
        ok, failures = check_etherchannel(exp_ether, act_ether)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "etherchannel",
            "transport": sesh.transport,
            "group_numbers": list((groups or {}).keys()),
            "group_modes": [g.get('mode') for g in (groups or {}).values()],
            "group_types": [g.get('type') for g in (groups or {}).values()],
            "summary": ether_str,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures

        }

        if ok:
            log.info(
                "etherchannel_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "Etherchannel Configuration Already Compliant"
                }
            )
            device_result["actions_taken"].append(
                "Etherchannel Configuration Already Compliant | "
                f"{ether_str}"
            )
        else:
            log.warning(
                "etherchannel_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "Etherchannel Configuration Non-Compliant"
                }
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN: 
                device_result["actions_taken"].append(
                        f"[DRY_RUN] Would Configure Etherchannel | {ether_str}"
                    )
            else: 
                result = configure_etherchannel(sesh, exp_ether, log)
                summary = result.get("summary")
                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    ether_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                           "Etherchannel Configuration Remediation Failed | "
                           f"{ether_str}"
                        )

    if ether_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_ether = build_etherchannel(new_state)

        if exp_ether:
            ok, failures = check_etherchannel(exp_ether, new_ether)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "etherchannel",
                "transport": sesh.transport,
                "group_numbers": list((groups or {}).keys()),
                "group_modes": [g.get('mode') for g in (groups or {}).values()],
                "group_types": [g.get('type') for g in (groups or {}).values()],
                "summary": ether_str,
                "compliant": ok,
                "failures_count": len(failures) if failures else 0,
                "failures": failures

            }

            if not ok:
                log.error(
                    "etherchannel_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "Etherchannel Configuration Post Validation Failed"
                    }
                )
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
            else:
                log.info(
                    "etherchannel_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "Etherchannel Configuration Post Validation Successful"
                    }
                )
                device_result["actions_taken"].append(
                    "Etherchannel Configuration Post Validation Successful | "
                    f"{ether_str}"
                )
    return device_result