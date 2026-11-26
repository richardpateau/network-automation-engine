from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli.collector import collect_device_state
from src.remediation.switching.stp import configure_stp_global
from src.compliance.switching.stp.check import check_stp_global, check_stp_interfaces
from src.collectors.cli.builders import build_stp_global, build_stp_interfaces
from src.remediation.switching.stp import configure_stp_interfaces
from src.core.settings import DRY_RUN

def compliance_stp_global(sesh, device_ip, context, device_state, device_result, log, transport):
    exp_stp = context.get("stp", {})
    act_stp = build_stp_global(device_state)
    stp_updated = False
    mode = exp_stp.get("mode", "")
    vlan_priorities = exp_stp.get("vlan_priorities", {})
    priorities_log = " | ".join(
        f"VLAN: {v} Priority: {p}" for v, p in vlan_priorities.items()
    )
    if exp_stp:
        ok, failures = check_stp_global(exp_stp, act_stp)
        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "event_type": "compliance_stp_global",
            "protocol": "stp",
            "transport": transport,
            "stp_mode": mode,
            "vlan_priorities": vlan_priorities,
            "vlan_count": len(vlan_priorities),
            "compliant": ok,
            "failure_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "stp_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "detail": "STP Global Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                f"STP Global Configuration Already Compliant | "
                f"Mode: {mode} | VLAN Priorities: {priorities_log}"
            )
        else:
            log.warning(
                "stp_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "detail": (
                        f"STP Global Configuration Non-Compliant | "
                        f"({len(failures)}) failures"
                    ),
                },
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    "[DRY_RUN] Would Configure Global STP | "
                    f"Mode: {mode} | VLAN Priorities: {priorities_log}"
                )
            else:
                result = configure_stp_global(sesh, exp_stp,device_ip, transport, act_stp, log)
                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    stp_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        "STP Global Remediation Failed | "
                        f"Mode: {mode} | VLAN Priorities: {priorities_log}"
                    )

    if stp_updated and not DRY_RUN:
        new_state = collect_device_state(sesh)
        new_stp = build_stp_global(new_state)

        ok, failures = check_stp_global(exp_stp, new_stp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "event_type": "compliance_stp_global",
            "protocol": "stp",
            "transport": transport,
            "stp_mode": mode,
            "vlan_priorities": vlan_priorities,
            "vlan_count": len(vlan_priorities),
            "compliant": ok,
            "failure_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if not ok:
            log.error(
                "stp_global_post_validation_failed",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "detail": f"STP Global Configuration Post Validation Failed",
                },
            )
            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        else:
            device_result["actions_taken"].append(
                f"STP Global Configuration Post Validation Successful | "
                f"Mode: {mode} | VLAN Priorities: {priorities_log}"
            )
            log.info(
                "stp_global_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "detail": "STP Global Configuration Post Validation Successful",
                },
            )
    return device_result


def compliance_stp_interfaces(
    sesh, device_ip, context, device_state, device_result, log, transport
):
    exp_stp_int = [
        {
            "interface": interface["interface"],
            "stp": interface["stp"],
        }
        for interface in context.get("interfaces", [])
        if interface.get("stp")
    ]
    act_stp_int = build_stp_interfaces(device_state)
    stp_int_updated = False

    stp_expected = [
    {
        "interface": i["interface"],
        **i["stp"]
    }
    for i in exp_stp_int
        ]


    if exp_stp_int:
        ok, failures = check_stp_interfaces(exp_stp_int, act_stp_int)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "stp_interfaces",
            "event_type": "compliance_stp_interface",
            "transport": transport,
            "expected_interfaces": stp_expected,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "stp_interfaces_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "detail": "STP Interface Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                "STP Interface Configuration Already Compliant | "
                f"Configuration: {stp_expected}")
        else:
            device_result["initial_issues"].extend(failures)

            log.warning(
                "stp_interfaces_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "detail": "STP Interface Configuration Non-Compliant",
                },
            )
            if DRY_RUN: 
                device_result["actions_taken"].append(
                        f"[DRY_RUN] Would Configure STP Features Interfaces | "
                        f"Expected Configuration: {stp_expected}"
                    )
            else: 
                result = configure_stp_interfaces(sesh, exp_stp_int, device_ip, transport, log)
                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    stp_int_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        f"STP Interface Remediation Failed | Expected Configuration: {stp_expected}"
                    )

    if stp_int_updated and not DRY_RUN:
        new_state = collect_device_state(sesh)
        new_stp = build_stp_interfaces(new_state)

        ok, failures = check_stp_interfaces(exp_stp_int, new_stp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "stp_interfaces",
            "event_type": "compliance_stp_interface",
            "transport": transport,
            "expected_interfaces": stp_expected,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if not ok:
            log.error(
                "stp_interfaces_post_validation_failed",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "detail": "STP Interfaces Post Validation Failed",
                },
            )
            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        else:
            device_result["actions_taken"].append(
                "STP Interface Configuration Post Validation Successful | "
                f"Expected Configuration: {stp_expected}"
            )
            log.info(
                "stp_interfaces_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "detail": "STP Interface Configuration Post Validation Successful",
                },
            )
    return device_result
