def check_cdp(expected_cdp, actual_config, transport): 
	failures = []
	exp_enabled = expected_cdp.get("enabled", False) 
	act_enabled = actual_config.get("enabled", False)

	if act_enabled is not None: 
		if exp_enabled != act_enabled: 
			failures.append(
					f"(CDP) Operational State Mismatch | "
					f"Expected: {exp_enabled} | Actual: {act_enabled}"
				)
	exp_timer = expected_cdp.get("timer", None)
	act_timer = actual_config.get("timer", None)
	if exp_timer != act_timer: 
		failures.append(
				f"(CDP) Timer Mismath | Expected: {exp_timer} | "
				f"Actual: {act_timer}"
			)
	exp_hold = expected_cdp.get("holdtime", None)
	act_hold = actual_config.get("holdtime", None)
	if exp_hold != act_hold: 
		failures.append(
				f"(CDP) HoldTime Mismatch | Expected: {exp_hold} | "
				f"Actual: {act_hold}"
			)
	exp_interfaces = expected_cdp.get("interfaces", {})
	act_interfaces = actual_config.get("interfaces", {})
 
	for interface, int_value in exp_interfaces.items(): 
		actual = act_interfaces.get(interface)
		exp_enabled = int_value.get("enabled", False)
		if transport == "NETMIKO":
			if exp_enabled: 
				if not actual: 
					failures.append(
							f"(CDP) Interface Not Configured w/ CDP | Interface: {interface}"
						)
					continue
				if actual.get("enabled") != int_value.get("enabled"):
					failures.append(
							f"(CDP) Interface CDP Configuration Mismatch | "
							f"Expected: {int_value.get('enabled')} | "
							f"Actual: {actual.get('enabled')}"
						)
			else: 
				if actual: 
					failures.append(
							f"(CDP) Interface CDP Operational State Mismatch | "
							f"Expected: {int_value.get('enabled')} | "
							f"Actual: {actual.get('enabled')}"
						)
		else: 
			if not actual: 
				failures.append(
						f"(CDP) Interface Not Configured w/ CDP | Interface: {interface}"
					)
				continue
			if actual.get("enabled") != int_value.get("enabled"):
				failures.append(
						f"(CDP) Interface CDP Configuration Mismatch | "
						f"Expected: {int_value.get('enabled')} | "
						f"Actual: {actual.get('enabled')}"
					)
	return len(failures) == 0, failures