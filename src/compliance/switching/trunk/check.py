def check_trunk(expected_trunk, actual_config): 
	failures = []
	exp_interface = expected_trunk.get("trunk_interface", "").lower().strip()
	exp_allowed_vlans = str(expected_trunk.get("allowed_vlans", "")).strip()
	exp_mode = expected_trunk.get("operational_mode", "").lower().strip()

	actual = actual_config.get(exp_interface)
	if not actual: 
		failures.append(
				f"Missing (Unconfigured) Trunk Interface | Interface: {exp_interface} | "
				f"Expected Allowed VLANs: {exp_allowed_vlans}"
			)
		return False, failures
	actual_vlans = str(actual.get("allowed_vlans", "")).strip()
	actual_mode = actual.get("operational_mode", "").lower().strip()
	if exp_allowed_vlans != actual_vlans: 
		failures.append(
				f"(Trunk) Mismatch Found - Allowed VLANs | Interface: {exp_interface} | "
				f"Expected: {exp_allowed_vlans} | Actual: {actual_vlans}"
			)
		return False, failures
	return len(failures) == 0, failures