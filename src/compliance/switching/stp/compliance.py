from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli import collect_device_state
from src.remediation.switching.stp.global_config import configure_stp_global
from src.compliance.switching.stp.helpers import build_stp_global, check_stp_global
from src.remediation.switching.stp.interfaces import configure_stp_interfaces
from src.compliance.switching.stp.helpers import (
    build_stp_interfaces,
    check_stp_interfaces,
)
from config import DRY_RUN


def compliance_stp_global(sesh, device_ip, context, device_state, device_result, log):
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
            "protocol": "stp",
            "transport": sesh.transport,
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
                    "message": "STP Global Configuration Already Compliant",
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
                    "message": (
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
                result = configure_stp_global(sesh, exp_stp, log)
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
        new_state = collect_device_state(sesh, log)
        new_stp = build_stp_global(new_state)

        ok, failures = check_stp_global(exp_stp, new_stp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "stp",
            "transport": sesh.transport,
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
                    "message": f"STP Global Configuration Post Validation Failed",
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
                    "message": "STP Global Configuration Post Validation Successful",
                },
            )
    return device_result


def compliance_stp_interfaces(
    sesh, device_ip, context, device_state, device_result, log
):
    exp_stp_int = context.get("interfaces", {}).get("stp", {})
    act_stp_int = build_stp_interfaces(device_state)
    stp_int_updated = False
    portfast = exp_stp_int.get("portfast", False)
    bpdu_guard = exp_stp_int.get("bpdu_guard", False)
    root_guard = exp_stp_int.get("root_guard", False)
    loop_guard = exp_stp_int.get("loop_guard", False)
    bpdu_filter = exp_stp_int.get("bpdu_filter", False)

    if exp_stp_int:
        ok, failures = check_stp_interfaces(exp_stp_int, act_stp_int)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "stp_interfaces",
            "transport": sesh.transport,
            "portfast": portfast,
            "root_guard": root_guard,
            "loop_guard": loop_guard,
            "bpdu_guard": bpdu_guard,
            "bpdu_filter": bpdu_filter,
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
                    "message": "STP Interface Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                "STP Interface Configuration Already Compliant | "
                f"BPDU Guard: {bpdu_guard} | Portfast: {portfast} | "
                f"Root Guard: {root_guard} | Loop Guard: {loop_guard} | "
                f"BPDU Filter: {bpdu_filter}"
            )
        else:
            device_result["initial_issues"].extend(failures)

            log.warning(
                "stp_interfaces_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "STP Interface Configuration Non-Compliant",
                },
            )
            if DRY_RUN: 
                device_result["actions_taken"].append(
                        f"[DRY_RUN] Would Configure STP Interfaces | "
                        f"BPDU Guard: {bpdu_guard} | Portfast: {portfast} | "
                        f"Root Guard: {root_guard} | Loop Guard: {loop_guard} | "
                        f"BPDU Filter: {bpdu_filter}"
                    )
            else: 
                result = configure_stp_interfaces(sesh, exp_stp_int, log)
                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    stp_int_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        "STP Interface Remediation Failed | "
                        f"BPDU Guard: {bpdu_guard} | Portfast: {portfast} | "
                        f"Root Guard: {root_guard} | Loop Guard: {loop_guard} | "
                        f"BPDU Filter: {bpdu_filter}"
                    )

    if stp_int_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_stp = build_stp_interfaces(new_state)

        ok, failures = check_stp_interfaces(exp_stp_int, new_stp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "stp_interfaces",
            "transport": sesh.transport,
            "portfast": portfast,
            "root_guard": root_guard,
            "loop_guard": loop_guard,
            "bpdu_guard": bpdu_guard,
            "bpdu_filter": bpdu_filter,
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
                    "message": "STP Interfaces Post Validation Failed",
                },
            )
            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        else:
            device_result["actions_taken"].append(
                "STP Interface Configuration Post Validation Successful | "
                f"BPDU Guard: {bpdu_guard} | Portfast: {portfast} | "
                f"Root Guard: {root_guard} | Loop Guard: {loop_guard} | "
                f"BPDU Filter: {bpdu_filter}"
            )
            log.info(
                "stp_interfaces_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "STP Interface Configuration Post Validation Successful",
                },
            )
    return device_result
