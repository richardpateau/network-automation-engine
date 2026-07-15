def check_access(expected_access, actual_config): 
	failures = []
	exp_interface = str(expected_access.get("access_interface", "")).lower().strip()
	exp_vlan = str(expected_access.get("access_vlan", "")).strip()

	actual = actual_config.get(exp_interface)
	if not actual:
		failures.append(
				f"Missing Access Port | Expected Interface: {exp_interface} | "
				f"Expected VLAN: {exp_vlan}"
			)
		return False, failures

	actual_vlan = str(actual.get("access_vlan", "")).strip()

	if exp_vlan != actual_vlan: 
		failures.append(
				f"Mismatch Detected Access Port | Interface: {exp_interface} | VLAN: "
				f"Expected VLAN: {exp_vlan} | Actual VLAN: {actual_vlan}"
			)
		return False, failures

	actual_mode = actual.get("operational_mode").lower().strip()
	if actual_mode != "static access":
		failures.append(
				f"Wrong Interface Operational Mode | Actual: {actual_mode}"
				f" Expected: static access"
			)
	return len(failures) == 0, failures