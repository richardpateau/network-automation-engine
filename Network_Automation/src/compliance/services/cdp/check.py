def check_cdp(expected_cdp, actual_config): 
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
				f"(CDP) Timer Mismatch | Expected: {exp_timer} | "
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
 	
 	extra_interfaces = act_interfaces.keys() - exp_interfaces.keys()
 	if extra_interfaces: 
 		failures.append(
 				f"(CDP) Rogue Interface Configured with CDP | {' | '.join(extra_interfaces)}"
 			)
	for interface, int_value in exp_interfaces.items(): 
		actual = act_interfaces.get(interface)
		if not actual: 
			failures.append(
				f"(CDP) Missing Interface Not Configured w/ CDP | Interface: {interface}"
					)
			continue
		if actual.get("enabled") != int_value.get("enabled"):
			failures.append(
				f"(CDP) Interface Operational State Mismatch | Interface: {interface} | "
				f"Expected: {int_value.get('enabled')} | "
				f"Actual: {actual.get('enabled')}"
			)
	return len(failures) == 0, failures