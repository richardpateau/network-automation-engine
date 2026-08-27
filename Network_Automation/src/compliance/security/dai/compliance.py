from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli.collector import collect_device_state
from src.compliance.security.dai.check import check_dai
from src.collectors.cli.builders import build_dai
from src.remediation.security.dai import configure_dai
from src.core.settings import DRY_RUN


def compliance_dai(sesh, device_ip, context, device_state, device_result, log):
    exp_dai = context.get("dai", {})
    act_dai = build_dai(device_state)
    dai_updated = False
    dai_log = []
    dai_interfaces = exp_dai.get("interfaces", {})
    buffer = exp_dai.get("log_buffer", {})
    if exp_dai.get("enabled_vlans"):
        vlans = ", ".join(map(str, sorted(exp_dai.get("enabled_vlans", []))))
        dai_log.append(f"Enabled VLANs: {vlans}")
    if dai_interfaces:
        d_list = []
        for i, v in dai_interfaces.items():
            if v.get("trusted"):
                d_list.append(f"{i}")
        dai_log.append(f"Trusted Interfaces: {', '.join(d_list or 'None')}")
    if buffer:
        dai_log.append(
            f"Log Buffer: {'Enabled' if buffer.get('enabled', False) else 'Disabled'} | "
            f"Entries: {buffer.get('entries', 0)}"
        )
    dai_str = " | ".join(dai_log) or "No DAI Configuration"

    if exp_dai:
        ok, failures = check_dai(exp_dai, act_dai)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "dai",
            "transport": sesh.transport,
            "interface_count": len(dai_interfaces or {}),
            "enabled_vlan_count": len(exp_dai.get("enabled_vlans", [])),
            "log_buffer_enabled": buffer.get("enabled", False),
            "log_buffer_entries": buffer.get("entries", 0),
            "trusted_interfaces": [
                d for d, v in dai_interfaces.items() if v.get("trusted", False)
            ],
            "summary": dai_str,
            "compliant": ok,
            "failure_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "dai_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "DAI Configuration Compliant",
                },
            )
            device_result["actions_taken"].append(
                "DAI Configuration Already Compliant | " f"{dai_str}"
            )
        else:
            log.warning(
                "dai_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "DAI Configuration Non-Compliant",
                },
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure DAI | {dai_str}"
                )
            else:
                result = configure_dai(sesh, exp_dai, log)
                summary = result.get("summary")

                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    dai_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        "DAI Configuration Remediation Failed | " f"{dai_str}"
                    )

    if dai_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_dai = build_dai(new_state)

        if exp_dai:
            ok, failures = check_dai(exp_dai, new_dai)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "dai",
                "transport": sesh.transport,
                "interface_count": len(dai_interfaces or {}),
                "enabled_vlan_count": len(exp_dai.get("enabled_vlans", [])),
                "log_buffer_enabled": buffer.get("enabled", False),
                "log_buffer_entries": buffer.get("entries", 0),
                "trusted_interfaces": [
                    d for d, v in dai_interfaces.items() if v.get("trusted", False)
                ],
                "summary": dai_str,
                "compliant": ok,
                "failure_count": len(failures) if failures else 0,
                "failures": failures,
            }

            if not ok:
                log.error(
                    "dai_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "DAI Configuration Post Validation Failed",
                    },
                )
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
            else:
                log.info(
                    "dai_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "DAI Configuration Post Validation Successful",
                    },
                )
                device_result["actions_taken"].append(
                    "DAI Configuration Post Validation Successful | " f"{dai_str}"
                )
    return device_result
