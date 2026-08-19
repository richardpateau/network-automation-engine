def check_access(expected_access, actual_config): 
	failures = []

	exp_by_int = {e.get("access_interface"): e for e in expected_access}
	for k,v in exp_by_int.items():
		actual = actual_config.get(k)
		if not actual: 
			failures.append(
					f"(Access) Missing Interface | {k}"
				)
			continue 
		if v.get("access_vlan") != actual.get("access_vlan"): 
			failures.append(
					f"(Access) Mismatched VLAN | Interface: {k} | "
					f"Expected: {v.get('access_vlan')} | "
					f"Actual: {actual.get('access_vlan')}"
				)
	for k,v in actual_config.items():
		expected = exp_by_int.get(k)
		if not expected: 
			failures.append(
					f"(Access) Rogue Interface Configured | Interface: {k}"
				)
	return len(failures) == 0, failures