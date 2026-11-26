from src.utils.helpers import normalize_to_list
def check_snmp(expected_snmp, actual_config): 
	failures = []
	exp_communities = expected_snmp.get("communities", [])
	act_communities = actual_config.get("communities", [])
	exp_tuple = {(e.get("snmp_name").lower()):(e.get("permission").lower()) for e in exp_communities}
	act_tuple = {(a.get("snmp_name").lower()): (a.get("permission").lower()) for a in act_communities}
	extra_c = act_tuple.keys() - exp_tuple.keys()
	for name in extra_c: 
		failures.append(
				f"(SNMP) Drift Detected: Unexpected SNMP Community Found | "
				f"Name: {name} | Permission: {act_tuple.get(name)}"
			)
	for name in exp_tuple: 
		actual = act_tuple.get(name)
		if actual is None: 
			failures.append(
					f"(SNMP) Missing SNMP Community | Name: {name}"
				)
			continue
		exp_permission = exp_tuple.get(name)

		if exp_permission != actual: 
			failures.append(
					f"(SNMP) Mismatched Community Permission | Name: {name} | "
					f"Expected: {exp_permission} | Actual: {actual}"
				)
	if expected_snmp.get("contact") != actual_config.get("contact"):
		failures.append(
				f"(SNMP) Mismatched Contact | Expected: {expected_snmp.get('contact')} | "
				f"Actual: {actual_config.get('contact')}"
			)
	exp_hosts = normalize_to_list(expected_snmp.get("hosts"))
	act_hosts = normalize_to_list(actual_config.get("hosts"))

	exp_tuple = {
			(h.get("snmp_name", "").lower(), h.get("snmp_ip", ""), h.get("snmp_version", ""))
			for h in exp_hosts
	}
	act_tuple = {
				(h.get("snmp_name", "").lower(), h.get("snmp_ip", ""), h.get("snmp_version", ""))
				for h in act_hosts
		}
	extra = act_tuple - exp_tuple 

	for name, ip, version in extra: 
		failures.append(
				f"(SNMP) Extra SNMP Host Found | Name: {name} | IP: {ip} | "
				f"Version: {version}"
			)
	act_lookup = {(a.get("snmp_name").lower()): a for a in act_hosts}
	for e in exp_hosts: 
		actual = act_lookup.get(e.get("snmp_name").lower())
		if not actual: 
			failures.append(
					f"(SNMP) Host Configuration | Community Name Not Found | Name: {e.get('snmp_name')}"
				)
			continue
		if actual.get("snmp_ip") != e.get("snmp_ip"): 
			failures.append(
					f"(SNMP) Mismatched SNMP IP Found | Name: {e.get('snmp_name')} | "
					f"Expected IP: {e.get('snmp_ip')} | Actual: {actual.get('snmp_ip')}"
				)
		if actual.get("snmp_version") != e.get("snmp_version"): 
			failures.append(
					f"(SNMP) Mismatched SNMP Version | Name: {e.get('snmp_name')} | "
					f"Expected: {e.get('snmp_version')} | Actual: {actual.get('snmp_version')}"
				)
	if expected_snmp.get("location") != actual_config.get("location"): 
		failures.append(
				f"(SNMP) SNMP Location Mismatch | Expected: {expected_snmp.get('location')} | "
				f"Actual: {actual_config.get('location')}" 
			)
	exp_traps = expected_snmp.get("traps", {})
	act_traps = actual_config.get("traps", {})
	if exp_traps.get("authentication"): 
		if exp_traps.get("authentication") != act_traps.get("authentication"):
			failures.append(
					f"(SNMP) Mismatched Traps | Authentication | Expected: {exp_traps.get('authentication')} | "
					f"Actual: {act_traps.get('authentication')}"
			)
	if exp_traps.get("linkup"):
		if exp_traps.get('linkup') != act_traps.get('linkup'):
			failures.append(
					f"(SNMP) Mismatched Traps | linkup | Expected: {exp_traps.get('linkup')} | "
					f"Actual: {act_traps.get('linkup')}"
				)
	if exp_traps.get("linkdown"):
		if exp_traps.get('linkdown') != act_traps.get('linkdown'): 
			failures.append(
					f"(SNMP) Mismatched Traps | linkdown | Expected: {exp_traps.get('linkdown')} | "
					f"Actual: {act_traps.get('linkdown')}"
				)
	if exp_traps.get("coldstart"):
		if exp_traps.get('coldstart') != act_traps.get('coldstart'): 
			failures.append(
					f"(SNMP) Mismatched Traps | coldstart | Expected: {exp_traps.get('coldstart')} | "
					f"Actual: {act_traps.get('coldstart')}"
				)
	if exp_traps.get("warmstart"):
		if exp_traps.get('warmstart') != act_traps.get('warmstart'): 
			failures.append(
					f"(SNMP) Mismatched Traps | warmstart | Expected: {exp_traps.get('syslog')} | "
					f"Actual: {act_traps.get('syslog')}"
				)
	return len(failures) == 0, failures