def check_static(expected_static, actual_config): 
	failures = []
	exp_network = {(e.get("network_address"), e.get("mask")): e for e in expected_static}
	act_network = {(a.get("network_address"), a.get("mask")): a for a in actual_config}

	extra_net = act_network.keys() - exp_network.keys()

	if extra_net: 
		for (add, mask) in extra_net: 
			failures.append(
					f"(Static Routing) Drift: Unexpected Static IP | "
					f"IP: {add} | Mask: {mask}"
				)
	for (add, mask), exp_value in exp_network.items(): 
		actual = act_network.get((add, mask))
		if not actual: 
			failures.append(
					f"(Static Routing) Missing Static Route | "
					f"IP: {add} | Mask: {mask}"
				)
			continue 
		if actual.get("AD") != exp_value.get("AD"): 
			failures.append(
					f"(Static Routing) AD Mismatch | Expected: {exp_value.get('AD')} | "
					f"Actual: {actual.get('AD')}"
				)
		if actual.get("exit_interface") != exp_value.get("exit_interface"): 
			failures.append(
					f"(Static Routing) Exit Interface Mismatch | Expected: "
					f"{exp_value.get('exit_interface')} | Actual: {actual.get('exit_interface')}"
				)
		exp_next = set(exp_value.get("next_hop") or [])
		act_next = set(actual.get("next_hop") or [])
		missing_next = exp_next - act_next 
		extra_next = act_next - exp_next 

		if missing_next: 
			failures.append(
					f"(Static Routing) Missing Next Hop | "
					f"Missing: {', '.join(missing_next)}"
				)
		if extra_next: 
			failures.append(
					f"(Static Routing) Drift: Unexpected Next Hop | "
					f"Extra: {', '.join(extra_next)}"
				)
	return len(failures) == 0, failures