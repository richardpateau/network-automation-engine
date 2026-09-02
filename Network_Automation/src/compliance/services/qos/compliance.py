from src.core.enums import StepStatus, OperationalStatus
from src.collectors.netconf.builders import build_qos
from src.collectors.netconf.collector import collect_netconf_state
from src.compliance.services.qos.check import check_qos
from src.remediation.services.qos import configure_qos
from src.core.settings import DRY_RUN

def compliance_qos(sesh, device_ip, context, device_state, device_result, log):
    exp_qos = context.get("qos", {})
    act_qos = build_qos(device_state)
    qos_updated = False
    policies = exp_qos.get("policies", [])
    policy_names = " , ".join(f"{p.get('policy_name', '')}" for p in policies)
    classes = [c for p in policies for c in p.get("class_maps", [])]
    class_name = [c.get("name") for c in classes]
    class_names = ", ".join(class_name)
    if exp_qos:
        ok, failures = check_qos(exp_qos, act_qos)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "qos",
            "transport": sesh.transport,
            "policy_names": policy_names,
            "class_names": class_names,
            "compliant": ok,
            "failure_count": len(failures) if failures else 0,
            "failures": failures,
        }

        if ok:
            log.info(
                "qos_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "QOS Already Compliant",
                },
            )
            device_result["actions_taken"].append(
                f"QOS Already Compliant | "
                f"Policy Name: {policy_names} | "
                f"Class Name: {class_names}"
            )
        else:
            device_result["initial_issues"].extend(failures)

            log.warning(
                "qos_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": f"QOS Non-Compliant",
                },
            )

            if DRY_RUN:
                device_result["actions_taken"].append(
                    "[DRY_RUN] Would Configure QOS | "
                    f"Policy Name: {policy_names} | "
                    f"Class Name: {class_names}"
                )
            else:
                result = configure_qos(sesh, device_ip, exp_qos, log)
                summary = result.get("summary")
                if summary:
                    device_result["actions_taken"].append(summary)
                if result.get("status") == OperationalStatus.SUCCESS.value:
                    qos_updated = True
                else:
                    device_result["status"] = OperationalStatus.FAILED_CONFIG.value
                    device_result["critical_issues"].append(
                        "Failed To Remediate QOS | "
                        f"Policy Name: {policy_names} | "
                        f"Class Name: {class_names}"
                    )

    if qos_updated and not DRY_RUN:
        new_state = collect_netconf_state(sesh, log)
        new_qos = build_qos(new_state)

        if exp_qos:
            ok, failures = check_qos(exp_qos, new_qos)

            log_extra = {
                "device_ip": device_ip,
                "component": "main_process",
                "protocol": "qos",
                "transport": sesh.transport,
                "policy_names": policy_names,
                "class_names": class_names,
                "compliant": ok,
                "failure_count": len(failures) if failures else 0,
                "failures": failures,
            }

            if not ok:
                log.error(
                    "qos_post_validation_failed",
                    extra={
                        **log_extra,
                        "status": StepStatus.FAILED.value,
                        "message": "QOS Post Validation Failed",
                    },
                )
                device_result["critical_issues"].extend(failures)
                device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
            else:
                device_result["actions_taken"].append(
                    f"QOS Post Validation Successful | "
                    f"Policy Name: {policy_names} | "
                    f"Class Name: {class_names}"
                )
                log.info(
                    "qos_post_validation_success",
                    extra={
                        **log_extra,
                        "status": StepStatus.SUCCESS.value,
                        "message": "QOS Post Validation Successful",
                    },
                )
    return device_result
