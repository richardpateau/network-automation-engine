from src.core.enums import StepStatus, OperationalStatus
from src.collectors.cli import collect_device_state
from src.remediation.switching.interface import configure_interface
from src.compliance.switching.interface_helpers import (build_interface,check_interface,)
from config import DRY_RUN

def compliance_interface(sesh, device_ip, context, device_state, device_result, log):
    exp_interfaces = context.get("interfaces", [])
    act_interfaces = build_interface(device_state)
    interfaces_updated = False

    for int_data in exp_interfaces:
        interface = int_data.get("interface", "")
        description = int_data.get("description", "")
        should_be_up = int_data.get("should_be_up", False)

        ok, failures = check_interface(int_data, act_interfaces)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "interface",
            "transport": sesh.transport,
            "interface": interface,
            "description": description,
            "should_be_up": should_be_up,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures
        }
        if ok:
            log.info(
                "interface_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": (
                        f"Interface Configuration Already Compliant"
                    )
                }
            )
            device_result["actions_taken"].append(
                f"Interface Configuration Already Compliant | "
                f"Interface: {interface} | Description: {description} | "
                f"Should Be Up: {should_be_up}"
            )
            continue

        device_result["initial_issues"].extend(failures)

        log.warning(
            "interface_drift",
            extra={
                **log_extra,
                "status": StepStatus.FAILED.value,
                "message": (
                    f"Interface Configuration Non-Compliant"
                )
            }
        )
        if DRY_RUN:
            device_result["actions_taken"].append(
                    "[DRY_RUN] Would Configure Interface | "
                    f"Interface: {interface} | Description: {description} | "
                    f"Should Be Up: {should_be_up}"
                )
        else: 
            result = configure_interface(sesh, int_data, log)
            summary = result.get("summary")
            if summary:
                device_result["actions_taken"].append(summary)
            if result.get("status") == OperationalStatus.SUCCESS.value:
                interfaces_updated = True
            else:
                device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                device_result["critical_issues"].append(
                        "Failed To Remediate Interface Configuration | "
                        f"Interface: {interface} | Description: {description} | "
                        f"Should Be Up: {should_be_up}"
                    )

    if interfaces_updated and not DRY_RUN:
        new_state = collect_device_state(sesh, log)
        new_interface = build_interface(new_state)

        for int_data in exp_interfaces:
            interface = int_data.get("interface", "")
            description = int_data.get("description", "")
            should_be_up = int_data.get("should_be_up", False)

            ok, failures = check_interface(int_data, new_interface)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "interface",
                "transport": sesh.transport,
                "interface": interface,
                "description": description,
                "should_be_up": should_be_up,
                "compliant": ok,
                "failures_count": len(failures) if failures else 0,
                "failures": failures
            }

            if not ok:
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
                log.error(
                    "interface_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "Interface Configuration Post Validation Failed | "
                                   f"({len(failures)}) failures"
                    }
                )
            else:
                device_result["actions_taken"].append(
                    f"Interface Configuration Post Validation Successful | "
                    f"Interface: {interface} | Description: {description} | "
                    f"Should Be Up: {should_be_up}"
                )
                log.info(
                    "interface_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "Interface Configuration Post Validation Successful"
                    }
                )
    return device_result