from src.core.enums import StepStatus, OperationalStatus
from src.collectors.netconf import collect_netconf_state
from src.remediation.routing.nat import configure_nat
from src.compliance.routing.nat_helpers import (build_nat,check_nat,)
from config import DRY_RUN

def compliance_nat(sesh, device_ip, context, device_state, device_result, log):
	exp_nat = context.get("nat", {})
    act_nat = build_nat(device_state)
    nat_updated = False
    
    nat_summary = []
    if exp_nat.get("interfaces"):
        inside = exp_nat.get("interfaces", {}).get("inside", [])
        outside = exp_nat.get("interfaces", {}).get("outside", [])
        nat_summary.append(
            f"NAT Inside Interfaces: {inside} | NAT Outside Interfaces: {outside}"
        )
    if exp_nat.get("static"):
        for s in exp_nat.get("static"):
            nat_summary.append(
                f"Static Inside Local/Global: {s.get('inside_ip')} > {s.get('outside_ip')}"
            )
    if exp_nat.get("dynamic"):
        for d in exp_nat.get("dynamic"):
            nat_summary.append(
                f"Dynamic Pool: {d.get('pool_name')} | "
                f"IP Range: {d.get('inside_ip')} - {d.get('outside_ip')} | "
                f"Mask: {d.get('mask')}"
            )
    if exp_nat.get("pat"):
        nat_summary.append(
            f"PAT Interface: {exp_nat.get('pat', {}).get('interfaces', '')} | "
            f"ACL: {exp_nat.get('pat', {}).get('acl', '')}"
        )
    
    summary_str = " | ".join(nat_summary)
    
    if exp_nat:
        ok, failures = check_nat(exp_nat, act_nat)
    
        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "nat",
            "transport": sesh.transport,
            "has_static": bool(exp_nat.get('static')),
            "has_dynamic": bool(exp_nat.get('dynamic')),
            "has_pat": bool(exp_nat.get('pat')),
            "static_count": len(exp_nat.get('static', [])),
            "dynamic_count": len(exp_nat.get('dynamic', [])),
            "inside_interfaces": exp_nat.get("interfaces", {}).get("inside", []),
            "outside_interfaces": exp_nat.get("interfaces", {}).get("outside", []),
            "summary": summary_str,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures
        }
    
        if ok:
            log.info(
                "nat_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "NAT Configuration Compliant"
                }
            )
            device_result["actions_taken"].append(
                "NAT Configuration Compliant | "
                f"{summary_str}"
            )
        else:
            device_result["initial_issues"].extend(failures)
    
            log.warning(
                "nat_non_compliant",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": (
                        "NAT Configuration Non-Compliant"
                    )
                }
            )
    
            result = configure_nat(sesh, exp_nat, log)
            summary = result.get("summary")
            if summary:
                device_result["actions_taken"].append(summary)
            if result.get("status") == OperationalStatus.SUCCESS.value:
                nat_updated = True
            else: 
            	device_result["status"] = OperationalStatus.FAILED_CONFIG.value
    
    if nat_updated and not DRY_RUN:
        new_state = collect_netconf_state(sesh, log)
        new_nat = build_nat(new_state)
    
        ok, failures = check_nat(exp_nat, new_nat)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "nat",
       	    "transport": sesh.transport,
            "has_static": bool(exp_nat.get('static', [])),
            "has_dynamic": bool(exp_nat.get('dynamic', [])),
            "has_pat": bool(exp_nat.get('pat')),
            "static_count": len(exp_nat.get('static')),
            "dynamic_count": len(exp_nat.get('dynamic')),
            "inside_interfaces": exp_nat.get("interfaces", {}).get("inside", []),
            "outside_interfaces": exp_nat.get("interfaces", {}).get("outside", []),
            "summary": summary_str,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures
        }

        if not ok:
            log.error(
                "nat_post_validation_failed",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "NAT Post Validation Failed"
                }
            )

            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        else:
            log.info(
                "nat_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "NAT Post Validation Successful"
                }
            )
            device_result["actions_taken"].append(
                "NAT Post Validation Successful | "
                f"{summary_str}"
            )
    return device_result