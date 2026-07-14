def check_hsrp(expected_hsrp, actual_config): 
	failures = []
	actual_hsrp = {
		(a.get("interface"), a.get("router_vlan"), a.get("group")): a 
		for a in actual_config
	}
	exp_keys = {
		(	e.get("interface", ""),
			e.get("router_vlan", ""),
			e.get("group", "")

			) for e in expected_hsrp
	}
	act_keys = set(actual_hsrp.keys())
	extra = act_keys - exp_keys
	if extra:
		for interface, vlan, group in extra:
			failures.append(
	        f"(HSRP) Unexpected Configuration | "
	        f"Interface: {interface} | VLAN: {vlan} | Group: {group}"
    	)

	for exp in expected_hsrp:
		exp_key = (
				exp.get("interface", ""),
				exp.get("router_vlan", ""),
				exp.get("group", "")
			)
		actual = actual_hsrp.get(exp_key)

		if not actual: 	
			failures.append(	
					f"(HSRP) Missing Configuration | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
				)
			continue 
		if exp.get("vip") != actual.get("vip"):
			failures.append(
					f"(HSRP) Mismatched Virtual IP | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
					f"Expected: {exp.get('vip')} | Actual: {actual.get('vip')}"
				)
		if exp.get("priority") != actual.get("priority"):
			failures.append(
					f"(HSRP) Mismatched Priority | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
					f"Expected: {exp.get('priority')} | Actual: {actual.get('priority')}" 
				)
		if exp.get("preempt") != actual.get("preempt"):
		    failures.append(
		        f"(HSRP) Mismatched Preempt | Interface: {exp_key[0]} | "
		        f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
		        f"Expected: {exp.get('preempt')} | Actual: {actual.get('preempt')}"
		    )
		if exp.get("version") != actual.get("version"):
			failures.append(
					f"(HSRP) Mismatched Version | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
					f"Expected: {exp.get('version')} | Actual: {actual.get('version')}" 
				)
	return len(failures) == 0, failures