def check_qos(expected_qos, actual_config): 
	failures = []
	exp_policies = normalize_to_list(expected_qos.get("policies", []))
	act_policies =normalize_to_list(actual_config.get("policies", []))

	act_lookup = {
		p.get("policy_name"): p
		for p in act_policies
	}
	for exp_policy in exp_policies: 
		name = exp_policy.get("policy_name", "")
		act_policy = act_lookup.get(name)

		if not act_policy: 
			failures.append(
					f"Missing QOS Policy | Expected: {name}"
				)
			continue 
		exp_classes = exp_policy.get("class_maps", [])
		act_classes = act_policy.get("class_maps", [])
		for exp_class in exp_classes: 
			matched = False
			for act_class in act_classes:
				if (
					exp_class.get("name", "") == act_class.get("name", "") and 
					exp_class.get("action_type", "") == act_class.get("action_type", "") and 
					exp_class.get("match_type", "") == act_class.get("match_type", "") and 
					exp_class.get("bandwidth", "") == act_class.get("bandwidth", "") and 
					exp_class.get("protocol", "") == act_class.get("protocol", "")
					):
					matched = True 
			if not matched: 
				failures.append(
						f"Expected Class Map Missing From Policy | Policy: {name} | "
						f"Class Config: {exp_class}"
					)
			exp_attached = normalize_to_list(exp_policy.get("attachments", []))
			act_attached = normalize_to_list(act_policy.get("attachments", []))
			for exp_attach in exp_attached: 
				matched = False 
				for act_attach in act_attached: 
					if (
						exp_attach.get("interface") == act_attach.get("interface") and 
						exp_attach.get("direction") == act_attach.get("direction")
						):
						matched = True 
				if not matched: 
					failures.append(
							f"Expected Policy Not Assigned to Interface | Policy: {name} | "
							f"Interface: {exp_attach.get("interface")} | "
							f"Direction: {exp_attach.get("direction")}"
						)
	return len(failures) == 0, failures 