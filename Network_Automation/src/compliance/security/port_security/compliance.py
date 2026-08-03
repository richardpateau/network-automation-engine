from src.core.enums import StepStatus, OperationalStatus
from src.collectors.port_security import build_port_security
from src.collectors.cli import collect_device_state
from src.compliance.port_security_checks import check_port_security
from src.remediation.port_security import configure_port_security
from src.core.settings import DRY_RUN


def compliance_port_security(
    sesh, device_ip, context, device_state, device_result, log
):
    exp_ps = context.get("port_security", {})
    act_ps = build_port_security(device_state)
    ps_updated = False
    interfaces = exp_ps.get("interfaces", {})
    ps_log = []
    if interfaces:
        for interface, int_value in interfaces.items():
            ps_log.append(
                f"Interface: {interface} | PS Enabled: {int_value.get('enabled')} | "
                f"MAC Addresses:  {int_value.get('mac_addresses')} | "
                f"Maximum: {int_value.get('maximum')} | "
                f"Sticky Enabled: {int_value.get('sticky')} | "
                f"Violation: {int_value.get('violation')}"
            )
    ps_str = " | ".join(ps_log)

    if exp_ps:
        ok, failures = check_port_security(exp_ps, act_ps)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "port_security",
            "transport": sesh.transport,
            "interface_count": len(interfaces or {}),
            "enabled_count": sum(
                1 for c in (interfaces or {}).values() if c.get("enabled")
            ),
            "maximum_count": [
                safe_int(i.get("maximum")) for i in (interfaces or {}).values()
            ],
            "violation_modes": [
                c.get("violation")
                for c in (interfaces or {}).values()
                if c.get("violation", "")
            ],
            "summary": ps_str,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "port_security_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "Port Security Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                "Port Security Configuration Already Compliant" f" | {ps_str}"
            )
        else:
            log.warning(
                "port_security_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "Port Security Configuration Non-Compliant",
                },
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure Port Security | {ps_str}"
                )
            else:
                result = configure_port_security(sesh, exp_ps, log)
                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)

                if result.get("status") == OperationalStatus.SUCCESS.value:
                    ps_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        "Port Security Remediation Failed | " f"{ps_str}"
                    )

    if ps_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_ps = build_port_security(new_state)

        if exp_ps:
            ok, failures = check_port_security(exp_ps, new_ps)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "port_security",
                "transport": sesh.transport,
                "interface_count": len(interfaces or {}),
                "enabled_count": sum(
                    1 for c in (interfaces or {}).values() if c.get("enabled", False)
                ),
                "maximum_count": [
                    safe_int(i.get("maximum")) for i in (interfaces or {}).values()
                ],
                "violation_modes": [
                    c.get("violation")
                    for c in (interfaces or {}).values()
                    if c.get("violation", "")
                ],
                "summary": ps_str,
                "failures_count": len(failures) if failures else 0,
                "failures": failures,
            }

            if not ok:
                log.error(
                    "port_security_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "Port Security Configuration Post Validation Failed",
                    },
                )
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
            else:
                log.info(
                    "port_security_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "Port Security Configuration Post Validation Successful",
                    },
                )
                device_result["actions_taken"].append(
                    "Port Security Configuration Post Validation Successful"
                    f" | {ps_str}"
                )
    return device_result
