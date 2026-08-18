def check_trunk(expected_trunk, actual_config): 
	failures = []
	
	exp_by_int = {t.get("trunk_interface"): t for t in expected_trunk}

	for k,v in exp_by_int.items():
		actual = actual_config.get(k)
		if not actual: 
			failures.append(
					f"(Trunk) Missing Interface | {k}"
				)
			continue 
		if v.get("mode") != actual.get("mode"): 
			failures.append(
					f"(Trunk) Mismatched Operational Mode | "
					f"Expected: {v.get('mode')} | "
					f"Actual: {actual.get('mode')}"
				)
		if v.get("allowed_vlans") != actual.get("allowed_vlans"): 
			failures.append(
					f"(Trunk) Mismatched Allowed VLANs | "
					f"Expected: {v.get('allowed_vlans')} | "
					f"Actual: {actual.get('allowed_vlans')}"
				)
	for k,v in actual_config.items():
		expected = exp_by_int.get(k)
		if not expected: 
			failures.append(
					f"(Trunk) Rogue Interface Configured in Trunk Mode | {k}"
				)
	return len(failures) == 0, failures