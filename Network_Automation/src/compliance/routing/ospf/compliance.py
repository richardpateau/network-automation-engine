from src.core.enums import StepStatus, OperationalStatus
from src.collectors.restconf import collect_restconf_state
from src.remediation.routing.ospf import configure_ospf
from src.compliance.routing.ospf_helpers import (build_ospf,check_ospf,)

from config import DRY_RUN
def compliance_ospf(sesh, device_ip, context, device_state, device_result, log):
	exp_ospf = context.get("ospf", [])
	act_ospf = build_ospf(device_state)
	ospf_updated = False

	for ospf_data in exp_ospf:
		process_id = ospf_data.get("process_id", "")
		router_id = ospf_data.get("router_id", "")
		interfaces = ospf_data.get("interfaces", [])
		interface = [
			i.get('name')
			for i in interfaces
		]
		ok, failures = check_ospf(ospf_data, act_ospf)

		log_extra = {
			"device_ip": device_ip,
			"component": "main_process",
			"protocol": "ospf",
			"transport": sesh.transport,
			"interfaces": interface,
			"process_id": process_id,
			"router_id": router_id,
			"compliant": ok,
			"failure_count": len(failures) if failures else 0,
			"failures": failures
		}
		if ok:
			log.info(
				"ospf_check",
				extra={
					**log_extra,
					"status": StepStatus.SUCCESS.value,
					"message": "OSPF Configuration Already Compliant"
				}
			)
			device_result["actions_taken"].append(
				f"OSPF Already Compliant | Process ID: {process_id} | "
				f"RID: {router_id} | Interfaces: {interface}"
			)
			continue

		device_result["initial_issues"].extend(failures)

		log.warning(
			"ospf_non_compliant",
			extra={
				**log_extra,
				"status": StepStatus.FAILED.value,
				"message": "OSPF Configuration Non-Compliant"
			}
		)

		result = configure_ospf(sesh, ospf_data, log)

		summary = result.get("summary")
		if summary:
			device_result["actions_taken"].append(summary)
		if result.get("status") == OperationalStatus.SUCCESS.value:
			ospf_updated = True
		else:
			device_result["status"] = OperationalStatus.FAILED_CONFIG.value

	if ospf_updated and not DRY_RUN:
		new_ospf = collect_restconf_state(sesh, log)
		new_ospf_state = build_ospf(new_ospf)

		for ospf_data in exp_ospf:
			process_id = ospf_data.get("process_id", "")
			router_id = ospf_data.get("router_id", "")
			interfaces = ospf_data.get("interfaces", [])
			interface = [
				i.get('name')
				for i in interfaces
			]
			ok, failures = check_ospf(ospf_data, new_ospf_state)

			log_extra = {
				"device_ip": device_ip,
				"component": "main_process",
				"protocol": "ospf",
				"transport": sesh.transport,
				"interfaces": interface,
				"process_id": process_id,
				"router_id": router_id,
				"compliant": ok,
				"failure_count": len(failures) if failures else 0,
				"failures": failures
			}

			if not ok:
				device_result["critical_issues"].extend(failures)
				device_result["status"] = OperationalStatus.FAILED_VALIDATION.value

				log.error(
					"ospf_post_validation_failed",
					extra={
						**log_extra,
						"status": StepStatus.FAILED.value,
						"message": (
							f"OSPF Configuration Post Validation Failed | "
							f"({len(failures)}) failures"
						)
					}
				)

			else:
				device_result["actions_taken"].append(
					f"OSPF Configuration Post Validation Successful | Process ID: {process_id} | "
					f"RID: {router_id} | Interfaces: {interface}"
				)
				log.info(
					"ospf_post_validation_success",
					extra={
						**log_extra,
						"status": StepStatus.SUCCESS.value,
						"message": "OSPF Configuration Post Validation Successful"
					}
				)
	return device_result