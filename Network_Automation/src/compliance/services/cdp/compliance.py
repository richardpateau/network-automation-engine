from src.core.enums import StepStatus, OperationalStatus
from src.collectors.netconf.builders import build_cdp_netconf
from src.collectors.cli.builders import build_cdp_netmiko
from src.collectors.netconf.collector import collect_netconf_state
from src.collectors.cli.collector import collect_device_state
from src.compliance.services.cdp.check import check_cdp
from src.remediation.services.cdp import configure_cdp_netconf, configure_cdp_netmiko
from src.core.settings import DRY_RUN

def compliance_cdp(sesh, device_ip, context, device_state, device_result, log):
    exp_cdp = context.get("cdp", {})

    if sesh.transport == "NETCONF":
        act_cdp = build_cdp_netconf(device_state)
    elif sesh.transport == "NETMIKO":
        act_cdp = build_cdp_netmiko(device_state)
    else:
        raise ValueError(f"Unsupported CDP Transport: {sesh.transport}")
    cdp_updated = False
    cdp_log = []
    int_count = 0
    if "enabled" in exp_cdp:
        cdp_log.append(f"Enabled: {exp_cdp.get('enabled', False)}")
    if "timer" in exp_cdp:
        cdp_log.append(f"Timer: {exp_cdp.get('timer', None)}")
    if "holdtime" in exp_cdp:
        cdp_log.append(f"HoldTime: {exp_cdp.get('holdtime', None)}")
    if exp_cdp.get("interfaces"):
        enabled_interfaces = []
        disabled_interfaces = []
        for i, v in exp_cdp.get("interfaces", {}).items():
            if v.get("enabled"):
                enabled_interfaces.append(i)
                int_count += 1
            else:
                disabled_interfaces.append(i)
        if enabled_interfaces:
            cdp_log.append(f"Enabled Interfaces: {', '.join(enabled_interfaces)}")
        if disabled_interfaces:
            cdp_log.append(f"Disabled Interfaces: {', '.join(disabled_interfaces)}")
    cdp_str = " | ".join(cdp_log) or "No CDP Configuration"

    if exp_cdp:
        ok, failures = check_cdp(exp_cdp, act_cdp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "cdp",
            "transport": sesh.transport,
            "cdp_enabled": exp_cdp.get("enabled"),
            "timer": exp_cdp.get("timer"),
            "holdtime": exp_cdp.get("holdtime"),
            "enabled_int_count": int_count,
            "enabled_interfaces": [
                i
                for i, v in exp_cdp.get("interfaces", {}).items()
                if v.get("enabled", False)
            ],
            "summary": cdp_str,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "cdp_netconf_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "CDP Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                f"CDP Configuration Already Compliant | {cdp_str}"
            )
        else:
            log.warning(
                "cdp_netconf_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "CDP Configuration Non-Compliant",
                },
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure CDP | {cdp_str}"
                )
            else:
                if sesh.transport == "NETCONF":
                    result = configure_cdp_netconf(sesh, exp_cdp, log)
                elif sesh.transport == "NETMIKO":
                    result = configure_cdp_netmiko(sesh, exp_cdp, log)

                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    cdp_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        "CDP Configuration Remediation Failed | " f"{cdp_str}"
                    )
    if cdp_updated and not DRY_RUN:
        if sesh.transport == "NETCONF":
            new_state = collect_netconf_state(sesh, log)
            new_cdp = build_cdp_netconf(new_state)
        if sesh.transport == "NETMIKO":
            new_state = collect_device_state(sesh)
            new_cdp = build_cdp_netmiko(new_state)

        if exp_cdp:
            ok, failures = check_cdp(exp_cdp, new_cdp)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "cdp",
                "transport": sesh.transport,
                "cdp_enabled": exp_cdp.get("enabled"),
                "timer": exp_cdp.get("timer"),
                "holdtime": exp_cdp.get("holdtime"),
                "enabled_int_count": int_count,
                "enabled_interfaces": [
                    i
                    for i, v in exp_cdp.get("interfaces", {}).items()
                    if v.get("enabled", False)
                ],
                "summary": cdp_str,
                "compliant": ok,
                "failures_count": len(failures) if failures else 0,
                "failures": failures,
            }

            if not ok:
                log.error(
                    "cdp_netconf_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "CDP Configuration Post Validation Failed",
                    },
                )
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
            else:
                log.info(
                    "cdp_netconf_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "CDP Configuration Post Validation Successful",
                    },
                )
                device_result["actions_taken"].append(
                    "CDP Configuration Post Validation Successful" f" | {cdp_str}"
                )
    return device_result
