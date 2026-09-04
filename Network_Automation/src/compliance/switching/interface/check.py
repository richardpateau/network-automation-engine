def check_interface(expected_int, actual_config): 
	failures = []

	exp_by_int = {e.get("interface"): e for e in expected_int}
	for k, v in exp_by_int.items():
		actual = actual_config.get(k)
		if not actual: 
			failures.append(f"(Interface) Missing Interface | {k}")
			continue 
		if v.get('should_be_up') != actual.get('is_up'): 
			failures.append(
				 f"Mismatched Interface Operational State | Interface: {k} | "
				 f"Expected Should Be Up/Up: {v.get('should_be_up')} | "
				 f"Actual Should be Up/Up: {actual.get('is_up')}"
			)
	return len(failures) == 0, failures