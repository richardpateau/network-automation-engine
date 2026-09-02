from src.core.enums import StepStatus, OperationalStatus
from src.collectors.netconf.builders import build_dhcp
from src.collectors.netconf.collector import collect_netconf_state
from src.compliance.services.dhcp.check import check_dhcp
from src.remediation.services.dhcp import configure_dhcp
from src.core.settings import DRY_RUN


def compliance_dhcp(sesh, device_ip, context, device_state, device_result, log):
    exp_dhcp = context.get("dhcp", {})
    act_dhcp = build_dhcp(device_state)
    dhcp_updated = False
    dhcp_log = []

    if exp_dhcp.get("excluded_addresses", []):
        for d in exp_dhcp.get("excluded_addresses", []):
            dhcp_log.append(
                f"Excluded IP Ranges: {d.get('start_ip')} - {d.get('end_ip')}"
            )

    if exp_dhcp.get("helper"):
        for i in exp_dhcp.get("helper", {}).get("interfaces", []):
            dhcp_log.append(
                f"Helper IP: {i.get('helper_ip')} | "
                f"Helper Int: {i.get('interface_name')}"
            )

    if exp_dhcp.get("pools"):
        for p in exp_dhcp.get("pools", []):
            dhcp_log.append(
                f"Pool Name: {p.get('name')} | "
                f"Default Gateway: {p.get('default_gateway')} | "
                f"IP/Mask: {p.get('network')}/{p.get('mask')}"
            )

    summary_str = " | ".join(dhcp_log) or "No DHCP Configuration"

    if exp_dhcp:
        ok, failures = check_dhcp(exp_dhcp, act_dhcp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "dhcp",
            "transport": sesh.transport,
            "pool_count": len(exp_dhcp.get("pools", [])),
            "excluded_count": len(exp_dhcp.get("excluded_addresses", [])),
            "helper_count": len(exp_dhcp.get("helper", {}).get("interfaces", [])),
            "pool_names": [p.get("name") for p in exp_dhcp.get("pools", [])],
            "excluded_ranges": [
                f"{e.get('start_ip')} - {e.get('end_ip')}"
                for e in exp_dhcp.get("excluded_addresses", [])
            ],
            "helper_interfaces": [
                h.get("interface_name")
                for h in exp_dhcp.get("helper", {}).get("interfaces", [])
            ],
            "summary": summary_str,
            "compliant": ok,
            "failure_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "dhcp_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "DHCP Configuration Compliant",
                },
            )

            device_result["actions_taken"].append(
                "DHCP Configuration Already Compliant | " f"{summary_str}"
            )

        else:
            log.warning(
                "dhcp_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "DHCP Configuration Non-Compliant",
                },
            )

            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure DHCP | {summary_str}"
                )
            else:
                result = configure_dhcp(sesh, exp_dhcp, log)

                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)

                if result.get("status") == OperationalStatus.SUCCESS.value:
                    dhcp_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        f"Failed To Remediate DHCP | {summary_str}"
                    )

    if dhcp_updated and not DRY_RUN:
        new_state = collect_netconf_state(sesh, log)
        new_dhcp = build_dhcp(new_state)

        ok, failures = check_dhcp(exp_dhcp, new_dhcp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "dhcp",
            "transport": sesh.transport,
            "pool_count": len(exp_dhcp.get("pools", [])),
            "excluded_count": len(exp_dhcp.get("excluded_addresses", [])),
            "helper_count": len(exp_dhcp.get("helper", {}).get("interfaces", [])),
            "pool_names": [p.get("name") for p in exp_dhcp.get("pools", [])],
            "excluded_ranges": [
                f"{e.get('start_ip')} - {e.get('end_ip')}"
                for e in exp_dhcp.get("excluded_addresses", [])
            ],
            "helper_interfaces": [
                h.get("interface_name")
                for h in exp_dhcp.get("helper", {}).get("interfaces", [])
            ],
            "summary": summary_str,
            "compliant": ok,
            "failure_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if not ok:
            log.error(
                "dhcp_post_validation_failed",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "DHCP Configuration Post Validation Failed",
                },
            )

            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value

        else:
            log.info(
                "dhcp_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "DHCP Configuration Post Validation Successful",
                },
            )

            device_result["actions_taken"].append(
                "DHCP Configuration Post Validation Successful | " f"{summary_str}"
            )

    return device_result
