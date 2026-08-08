from src.core.enums import StepStatus, OperationalStatus
from src.collectors.snmp import build_snmp_netconf, build_snmp_netmiko
from src.collectors.state import collect_netconf_state, collect_device_state
from src.compliance.snmp_checks import check_snmp
from src.remediation.snmp import configure_snmp_netconf, configure_snmp_netmiko
from src.core.settings import DRY_RUN


def compliance_snmp(sesh, device_ip, context, device_state, device_result, log):
    exp_snmp = context.get("snmp", {})

    if sesh.transport == "NETCONF":
        act_snmp = build_snmp_netconf(device_state)
    elif sesh.transport == "NETMIKO":
        act_snmp = build_snmp_netmiko(device_state)
    else:
        raise ValueError(f"Unsupported SNMP Transport {sesh.transport}")
    snmp_updated = False

    snmp_log = []
    if exp_snmp.get("communities"):
        for c in exp_snmp.get("communities"):
            snmp_log.append(
                f"Community Name: {c.get('snmp_name')} Permission: {c.get('permission')}"
            )
    if exp_snmp.get("hosts"):
        for h in exp_snmp.get("hosts"):
            snmp_log.append(f"SNMP IP: {h.get('snmp_ip')} ({h.get('community')}) ")
    if exp_snmp.get("traps"):
        traps = exp_snmp.get("traps", {})
        snmp_log.append(
            f"Traps: {traps.get('config')}, {traps.get('snmp')}, {traps.get('syslog')}"
        )
    community_str = " | ".join(snmp_log)

    if exp_snmp:
        ok, failures = check_snmp(exp_snmp, act_snmp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "snmp",
            "transport": sesh.transport,
            "community_count": len(exp_snmp.get("communities", [])),
            "host_count": len(exp_snmp.get("hosts", [])),
            "contact": exp_snmp.get("contact", ""),
            "location": exp_snmp.get("location", ""),
            "community_names": [
                c.get("snmp_name") for c in exp_snmp.get("communities", [])
            ],
            "snmp_hosts": [h.get("snmp_ip") for h in exp_snmp.get("hosts", [])],
            "enabled_traps": [t for t, v in exp_snmp.get("traps", {}).items() if v],
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }
        if ok:
            log.info(
                "snmp_netconf_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "SNMP Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                "SNMP Configuration Already Compliant | " f"{community_str}"
            )
        else:
            log.warning(
                "snmp_netconf_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "SNMP Configuration Non-Compliant",
                },
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure SNMP | {community_str}"
                )
            else:
                if sesh.transport == "NETCONF":
                    result = configure_snmp_netconf(sesh, exp_snmp, log)
                elif sesh.transport == "NETMIKO":
                    result = configure_snmp_netmiko(sesh, exp_snmp, log)

                summary = result.get("summary")
                if summary:
                    device_result["actions_taken"].append(summary)

                if result.get("status") == OperationalStatus.SUCCESS.value:
                    snmp_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        f"Failed To Remediate SNMP | {community_str}"
                    )

    if snmp_updated and not DRY_RUN:
        if sesh.transport == "NETCONF":
            new_state = collect_netconf_state(sesh, log)
            new_snmp = build_snmp_netconf(new_state)
        if sesh.transport == "NETMIKO":
            new_state = collect_device_state(sesh, log)
            new_snmp = build_snmp_netmiko(new_state)

        ok, failures = check_snmp(exp_snmp, new_snmp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "snmp",
            "transport": sesh.transport,
            "community_count": len(exp_snmp.get("communities", [])),
            "host_count": len(exp_snmp.get("hosts", [])),
            "contact": exp_snmp.get("contact", ""),
            "location": exp_snmp.get("location", ""),
            "community_names": [
                c.get("snmp_name") for c in exp_snmp.get("communities", [])
            ],
            "snmp_hosts": [h.get("snmp_ip") for h in exp_snmp.get("hosts", [])],
            "enabled_traps": [t for t, v in exp_snmp.get("traps", {}).items() if v],
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if not ok:
            log.error(
                "snmp_netconf_post_validation_failed",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "SNMP Configuration Post Validation Failed",
                },
            )
            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        else:
            log.info(
                "snmp_netconf_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "SNMP Configuration Post Validation Successful",
                },
            )
            device_result["actions_taken"].append(
                "SNMP Configuration Post Validation Successful | " f"{community_str}"
            )
    return device_result
