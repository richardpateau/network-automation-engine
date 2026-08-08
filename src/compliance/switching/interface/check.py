def check_interface(expected_int, actual_config): 
	failures = []
	exp_interface = expected_int.get("interface", "").lower().strip()
	exp_is_up = expected_int.get("should_be_up", False)

	actual = actual_config.get(exp_interface)
	if not actual: 
		failures.append(
				f"Missing Interface On Device | Interface: {exp_interface}"
			)
		return False, failures
	actual_is_up = actual.get("is_up", False )
	if exp_is_up != actual_is_up:
		failures.append(
			 f"Mismatched Interface State | Interface: {exp_interface} | "
			 f"Expected Should Be Up/Up: {exp_is_up} | "
			 f"Actual Should be Up/Up: {actual_is_up}"
			)

	return len(failures) == 0, failures