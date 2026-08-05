from src.core.enums import StepStatus, OperationalStatus
from src.collectors.ntp import build_ntp
from src.collectors.state import collect_netconf_state
from src.compliance.ntp_checks import check_ntp
from src.remediation.ntp import configure_ntp
from src.core.settings import DRY_RUN


def compliance_ntp(sesh, device_ip, context, device_state, device_result, log):
    exp_ntp = context.get("ntp", {})
    act_ntp = build_ntp(device_state)
    ntp_updated = False
    servers = exp_ntp.get("servers", [])
    server_ip = " | ".join(f"{s.get('server_ip')}" for s in servers)
    key_id = " | ".join(f"{s.get('server_id')}" for s in servers)
    authenticated = True
    if exp_ntp:
        ok, failures = check_ntp(exp_ntp, act_ntp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "ntp",
            "transport": sesh.transport,
            "server_ip": server_ip,
            "key_id": key_id,
            "authenticated": authenticated,
            "compliant": ok,
            "failure_count": len(failures),
            "failures": failures,
        }

        if ok:
            log.info(
                "ntp_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "NTP Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                f"NTP Already Compliant | "
                f"Server IP: {server_ip} | Key ID: {key_id} | "
                f"Authenticated: {authenticated}"
            )
        else:
            device_result["initial_issues"].extend(failures)

            log.warning(
                "ntp_drift",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": f"NTP Non-Compliant",
                },
            )

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure NTP | "
                    f"Server IP: {server_ip} | Key ID: {key_id} | "
                    f"Authenticated: {authenticated}"
                )
            else:
                result = configure_ntp(sesh, exp_ntp, log)
                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    ntp_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        f"Failed To Remediate NTP | "
                        f"Server IP: {server_ip} | Key ID: {key_id} | "
                        f"Authenticated: {authenticated}"
                    )

    if ntp_updated and not DRY_RUN:
        new_state = collect_netconf_state(sesh, log)
        new_ntp = build_ntp(new_state)

        ok, failures = check_ntp(exp_ntp, new_ntp)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "ntp",
            "transport": sesh.transport,
            "server_ip": server_ip,
            "key_id": key_id,
            "authenticated": authenticated,
            "compliant": ok,
            "failure_count": len(failures),
            "failures": failures,
        }

        if not ok:
            log.error(
                "ntp_post_validation_failed",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "NTP Post Validation Failed",
                },
            )
            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        else:
            device_result["actions_taken"].append(
                f"NTP Post Validation Successful | "
                f"Server IP: {server_ip} | Key ID: {key_id} | "
                f"Authenticated: {authenticated}"
            )
            log.info(
                "ntp_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "NTP Post Validation Successful",
                },
            )
    return device_result
