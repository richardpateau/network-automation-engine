def check_roas(expected_roas, actual_config): 
	failures = []
	exp_interface = expected_roas.get("interface", "").lower()
	exp_vlan = str(expected_roas.get("router_vlan", ""))
	exp_ip = expected_roas.get("ip", "")
	exp_mask = expected_roas.get("mask", "")
	exp_ip_mask = f"{exp_ip}/{exp_mask}"
	actual = actual_config.get(exp_interface)
	if not actual: 
		failures.append(
				f"Missing ROAS Interface on Device | Interface: {exp_interface} | VLAN: "
				f"{exp_vlan} | IP: {exp_ip}/{exp_mask}"
			)
		return False, failures
	actual_vlan = str(actual.get("router_vlan", ""))
	if exp_vlan != actual_vlan: 
		failures.append(
				f"ROAS VLAN Mismatch | Expected: {exp_vlan} | Actual: {actual_vlan}"
			)
		return False, failures
	actual_ip = actual.get("ip", "")
	actual_mask = actual.get("mask", "")
	actual_ip_mask = f"{actual_ip}/{actual_mask}"

	if exp_ip_mask != actual_ip_mask: 
		failures.append(
				f"ROAS IP/Mask Mismatch | Interface: {exp_interface} | "
				f"Expected IP/Mask: {exp_ip_mask} | Actual IP/Mask: {actual_ip_mask}"
			)
	return len(failures) == 0, failures