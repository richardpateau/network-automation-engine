def check_etherchannel(expected_ether, actual_config): 
	failures = []
	exp_enabled = expected_ether.get("enabled", False)
	act_enabled = actual_config.get("enabled", False)

	if exp_enabled != act_enabled: 
		failures.append(
				f"(Etherchannel) Misconfigured Operation Mode | "
				f"Expected: {exp_enabled} | Actual: {act_enabled}"
			)
	exp_groups = expected_ether.get("groups", {})
	act_groups = actual_config.get("groups", {})

	extra_groups = act_groups.keys() - exp_groups.keys()

	if extra_groups: 
		failures.append(
				f"(Etherchannel) Drift: Unexpected Port Channels | "
				f"{sorted(extra_groups)}"
			)
	for group, g_value in exp_groups.items(): 
		actual = act_groups.get(group)
		if not actual: 
			failures.append(
				f"(Etherchannel) Missing Port Channel Group | "
				f"{group}"
			)
			continue
		exp_set = set(g_value.get("interfaces", []))
		act_set = set(actual.get("interfaces", []))

		missing_int = exp_set - act_set
		extra_int = act_set - exp_set

		if missing_int:
			for m in missing_int: 
				failures.append(
						f"(Etherchannel) Missing Interface | "
						f"Group: {group} | Interface: {m}"
					)
		if extra_int: 
			for e in extra_int: 
				failures.append(
						f"(Etherchannel) Drift: Unexpected Interface | "
						f"Group: {group} | Interface: {e}"
					)
		if actual.get("mode") !=  g_value.get("mode"):
			failures.append(
					f"(Etherchannel) Mode Mismatch | Expected: {g_value.get('mode')} | "
					f"Actual: {actual.get('mode')}"
				)
		if actual.get("switchport_mode") != g_value.get("switchport_mode"): 
			failures.append(
					f"(Etherchannel) Mismatched Switchport Mode | Expected:"
					f" {g_value.get('switchport_mode')} | Actual: {actual.get('switchport_mode')}"

				)
		if actual.get("type") != g_value.get("type"): 
			failures.append(
					f"(Etherchannel) Mismatched Etherchannel Type | "
					f"Expected: {g_value.get('type')} | Actual: {actual.get('type')}"
				)
		if actual.get("description") != g_value.get("description"): 
			failures.append(
					f"(Etherchannel) Mismatched Description | Expected: "
					f"{g_value.get('description')} | Actual: {actual.get('description')}"
				)
	return len(failures) == 0, failures