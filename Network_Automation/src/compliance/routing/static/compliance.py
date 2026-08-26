from src.core.enums import StepStatus, OperationalStatus
from src.collectors.netconf import collect_netconf_state
from src.remediation.routing.static_routes import configure_static
from src.compliance.routing.static_helpers import (
    build_static,
    check_static,
)
from config import DRY_RUN


def compliance_static(sesh, device_ip, context, device_state, device_result, log):
    exp_static = context.get("static", [])
    act_static = build_static(device_state)
    static_updated = False
    static_log = []

    static_str = (
        " | ".join(
            f"{r.get('network')}/{r.get('mask')}" f"via {', '.join(r.get('next_hop'))}"
            for r in exp_static
        )
        or "No Static Routing Configuration"
    )

    for static_data in exp_static:
        ok, failures = check_static(static_data, act_static)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "static_routing",
            "transport": sesh.transport,
            "static_route_count": len(exp_static),
            "ad": static_data.get("administrative_distance", 0),
            "exit_interface": static_data.get("exit_interface", None),
            "ip_mask": f"{static_data.get('network', None)}/{static_data.get('mask', None)}",
            "name": static_data.get("name"),
            "next_hop": static_data.get("next_hop"),
            "summary": static_str,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "static_routing_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "Static Routing Configuration Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                "Static Routing Configuration Already Compliant | " f"{static_str}"
            )
        else:
            log.warning(
                "static_routing_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "Static Routing Configuration Non-Compliant",
                },
            )
            device_result["initial_issues"].extend(failures)

            if DRY_RUN:
                device_result["actions_taken"].append(
                    f"[DRY_RUN] Would Configure Static Route | {static_str}"
                )
                continue

            result = configure_static(sesh, static_data, log)
            summary = result.get("summary")

            if summary:
                device_result["actions_taken"].append(summary)
            if result.get("status") == OperationalStatus.SUCCESS.value:
                static_updated = True
            else:
                device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                device_result["critical_issues"].append(
                    "Static Routing Remediation Failed | " f"{static_str}"
                )

    if static_updated and not DRY_RUN:
        new_state = collect_netconf_state(sesh)
        new_static = build_static(new_state)
        for static_data in exp_static:
            ok, failures = check_static(static_data, new_static)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "static_routing",
                "transport": sesh.transport,
                "static_route_count": len(exp_static),
                "ad": static_data.get("administrative_distance", 0),
                "exit_interface": static_data.get("exit_interface", None),
                "ip_mask": f"{static_data.get('network', None)}/{static_data.get('mask', None)}",
                "name": static_data.get("name"),
                "next_hop": static_data.get("next_hop"),
                "summary": static_str,
                "compliant": ok,
                "failures_count": len(failures) if failures else 0,
                "failures": failures,
            }

            if not ok:
                log.error(
                    "static_routing_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "Static Routing Configuration Post Validation Failed",
                    },
                )
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
            else:
                log.info(
                    "static_routing_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "Static Routing Configuration Post Validation Successful",
                    },
                )
                device_result["actions_taken"].append(
                    "Static Routing Configuration Post Validation Successful | "
                    f"{static_str}"
                )
    return device_result
