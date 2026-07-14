def check_snooping(expected_snooping, actual_config): 
	failures = []
	exp_vlans = set(expected_snooping.get("enabled_vlans", []))
	act_vlans = set(actual_config.get("enabled_vlans", []))
	missing_vlans = exp_vlans - act_vlans
	extra_vlans = act_vlans - exp_vlans

	if missing_vlans: 
		failures.append(
				f"(DHCP Snooping) Missing VLAN(s) On Device | VLAN(s): {sorted(missing_vlans)}"
			)
	if extra_vlans: 
		failures.append(
				f"(DHCP Snooping) Drift: Extra VLAN on Device | VLAN(s): {sorted(extra_vlans)}"
			)
	exp_interfaces = expected_snooping.get("interfaces", {})
	act_interfaces = actual_config.get("interfaces", {})

	exp_int = set(exp_interfaces.keys())
	act_int = set(act_interfaces.keys())

	extra_int = act_int - exp_int
	if extra_int:
		for e in extra_int:  
			failures.append(
					f"(DHCP Snooping) Extra Interface Configured with DHCP Snooping | "
					f"Interface: {e}"
				)
	for interface, int_value in exp_interfaces.items():
		actual = act_interfaces.get(interface)
		if not actual: 
			failures.append(
					f"(DHCP Snooping) Missing Interface Configured w DHCP Snooping | "
					f"Interface: {interface}"
				)
			continue
		if actual.get("rate_limit") != int_value.get("rate_limit"): 
			failures.append(
					f"(DCHP Snooping) Rate Limit Mismatch | "
					f"Expected: {int_value.get('rate_limit')} | "
					f"Actual: {actual.get('rate_limit')}"
				)
		if actual.get("trusted") != int_value.get("trusted"): 
			failures.append(
					f"(DHCP Snooping) Trusted Interface Config Mismatched | "
					f"Expected: {int_value.get('trusted')} | "
					f"Actual: {actual.get('trusted')}"
				)
	if actual_config.get("option82") != expected_snooping.get("option82"):
		failures.append(
				f"(DHCP Snooping) Mismatched Option 82 Config | "
				f"Expected: {int_value.get('option82')} | "
				f"Actual: {actual.get('option82')}"
			)
	return len(failures) == 0, failures