from src.utils.helpers import normalize_to_list
def check_qos(expected_qos, actual_config): 
	failures = []
	exp_policies = normalize_to_list(expected_qos.get("policies", []))
	act_policies = normalize_to_list(actual_config.get("policies", []))

	act_lookup = {
		p.get("policy_name"): p
		for p in act_policies
	}
	exp_lookup = {p.get("policy_name"): p for p in exp_policies}
	for a in act_policies:
		name = a.get("policy_name", "")
		expected = exp_lookup.get(name)
		if not expected:
			failures.append(
					f"(QOS) Rogue Policy Found | {name}"
				)
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
		actual_by_name = {a.get("name"): a for a in act_classes}
		expected_by_name = {e.get("name"): e for e in exp_classes}
		for act in act_classes: 
			act_name = act.get("name", "")
			expected = expected_by_name.get(act_name)
			if not expected:
				failures.append(
						f"(QOS) Extra Class Map Found | {act_name}"
					)
		for exp_class in exp_classes: 
			exp_name = exp_class.get("name", "")
			actual = actual_by_name.get(exp_name)
			if not actual:
				failures.append(
						f"(QOS) Missing Class Map | {exp_name}"
					)
				continue
			if exp_class.get("name", "") != actual.get("name", ""): 
				failures.append(
						f"(QOS) Mismatched Class Name | Policy: {name} | "
						f"Expected: {exp_class.get("name", "")} | "
						f"Actual: {actual.get("name", "")}"
					)
			if exp_class.get("action_type", "") != actual.get("action_type", ""):
				failures.append(
						f"(QOS) Mismatched Action Type Configuration | Policy: {name} | "
						f"Expected: {exp_class.get("action_type", "")} | "
						f"Actual: {actual.get("action_type", "")}"
					)
			if exp_class.get("match_type", "") != actual.get("match_type", ""):
				failures.append(
						f"(QOS) Mismatched Match Type Configuration | Policy: {name} | "
						f"Expected: {exp_class.get("match_type", "")} | "
						f"Actual: {actual.get("match_type", "")}"
					)
			if exp_class.get("bandwidth", "") != actual.get("bandwidth", ""):
				failures.append(
						f"(QOS) Mismatched Bandwidth Configuration | Policy: {name} | "
						f"Expected: {exp_class.get("bandwidth", "")} | "
						f"Actual: {actual.get("bandwidth", "")}"
					)
			if exp_class.get("protocol", "") != actual.get("protocol", ""):
				failures.append(
						f"(QOS) Mismatched Protocol Configuration | Policy: {name} | "
						f"Expected: {exp_class.get("protocol", "")} | "
						f"Actual: {actual.get("protocol", "")}" 
					)
			if exp_class.get("priority", "") != actual.get("priority", ""): 
				failures.append(
						f"(QOS) Mismatched Priority Configuration | Policy: {name} | "
						f"Expected: {exp_class.get("priority", "")} | "
						f"Actual: {actual.get("priority", "")}" 
					)
			exp_attached = normalize_to_list(exp_policy.get("attachments", []))
			act_attached = normalize_to_list(act_policy.get("attachments", []))
			exp_by_int = {e.get("interface"): e for e in exp_attached}
			act_by_int = {a.get("interface"): a for a in act_attached}
			for exp_attach in exp_attached: 
				interface = exp_attach.get("interface")
				actual = act_by_int.get(interface)
				if not actual:
					failures.append(
							f"(QOS) Policy Not Applied on Interface | {interface}"
						)
					continue
				if exp_attach.get("direction") != actual.get("direction"): 
					failures.append(
							f"(QOS) Mismatched Direction | Interface: {interface} | "
							f"Expected: {exp_attach.get("direction")} | "
							f"Actual: {actual.get("direction")}"
						)
			for a in act_attached:
				interface = a.get("interface")
				expected = exp_by_int.get(interface)
				if not expected: 
					failures.append(
							f"(QOS) Rogue Policy Configured On Interface | "
							f"{interface}"
						)

	return len(failures) == 0, failures 