def check_vlan(expected_vlans, actual_vlans):
	failures = []

	exp_by_id = {v.get("vlan_id"): v for v in expected_vlans}
	for vid, actual in actual_vlans.items(): 
		expected = exp_by_id.get(vid)
		if not expected:
			failures.append(
					f"Rogue VLAN Detected | ID: {vid} | Name: {actual.get('name')}"
				)
	for vid, exp in exp_by_id.items():
        actual = actual_vlans.get(vid)
        if not actual:
            failures.append(
                f"Missing VLAN {vid} | Name: {exp.get('name')}"
            )
            continue
        exp_name = str(exp.get("name") or "").strip()
        act_name = str(actual.get("name") or "").strip()
        if exp_name.lower() != act_name.lower():
            failures.append(
                f"VLAN Name Mismatch | VLAN: {vid} "
                f"| Expected: {exp_name} | Actual: {act_name}"
            )
	return len(failures) == 0, failures
