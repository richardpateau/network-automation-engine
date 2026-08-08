from src.core.enums import StepStatus, OperationalStatus
from src.collectors.snooping import build_snooping
from src.collectors.cli import collect_device_state
from src.compliance.snooping_checks import check_snooping
from src.remediation.snooping import configure_snooping
from src.core.settings import DRY_RUN


def compliance_snooping(sesh, device_ip, context, device_state, device_result, log):
    exp_snooping = context.get("dhcp_snooping", {})
    act_snooping = build_snooping(device_state)
    snooping_updated = False
    s_interfaces = exp_snooping.get("interfaces")
    snooping_log = []
    trusted_interfaces = sum(
        1 for i, v in (s_interfaces or {}).items() if v.get("trusted")
    )
    if exp_snooping.get("enabled_vlans"):
        vlans = ", ".join(map(str, sorted(exp_snooping.get("enabled_vlans", []))))
        snooping_log.append(f"Enabled VLANs: {vlans}")
    if s_interfaces:
        for i, v in s_interfaces.items():
            if v.get("trusted"):
                snooping_log.append(f"Trusted Interface: {i}")
    if "option82" in exp_snooping:
        snooping_log.append(
            f"Option 82: {'Enabled' if exp_snooping.get('option82') else 'Disabled'}"
        )
    snooping_str = " | ".join(snooping_log) or "No DHCP Snooping Configuration Exists"
    if exp_snooping:
        ok, failures = check_snooping(exp_snooping, act_snooping)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "dhcp_snooping",
            "transport": sesh.transport,
            "enabled_vlan_count": len(exp_snooping.get("enabled_vlans", [])),
            "trusted_interface_count": trusted_interfaces,
            "summary": snooping_str,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "snooping_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "DHCP Snooping Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                "DHCP Snooping Configuration Already Compliant" f" | {snooping_str}"
            )
        else:
            log.warning(
                "snooping_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "DHCP Snooping Configuration Non-Compliant",
                },
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure DHCP Snooping | {snooping_str}"
                )
            else:
                result = configure_snooping(sesh, exp_snooping, log)
                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    snooping_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        "DHCP Snooping Configuration Remediation Failed | "
                        f"{snooping_str}"
                    )

    if snooping_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_snooping = build_snooping(new_state)

        if exp_snooping:
            ok, failures = check_snooping(exp_snooping, new_snooping)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "dhcp_snooping",
                "transport": sesh.transport,
                "enabled_vlan_count": len(exp_snooping.get("enabled_vlans", [])),
                "trusted_interface_count": trusted_interfaces,
                "summary": snooping_str,
                "compliant": ok,
                "failures_count": len(failures) if failures else 0,
                "failures": failures,
            }

            if not ok:
                log.error(
                    "snooping_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "DHCP Snooping Configuration Post Validation Failed",
                    },
                )
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value

            else:
                log.info(
                    "snooping_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "DHCP Snooping Configuration Post Validation Successful",
                    },
                )
                device_result["actions_taken"].append(
                    "DHCP Snooping Configuration Post Validation Successful"
                    f" | {snooping_str}"
                )
    return device_result
