from collections import defaultdict
def check_dhcp(expected_dhcp, actual_config):
	failures = []
	exp_pools = expected_dhcp.get("pools", [])
	act_pools = actual_config.get("pools", [])
	exp_key = {
		(e.get("pool_name")): e
		for e in exp_pools
	}
	act_key = {
		(a.get("pool_name", "")): a
		for a in act_pools
	}
	extra = act_key.keys() - exp_key.keys()
	if extra:
		for e in extra:
			failures.append(
					f"(DHCP) Rogue DHCP Pool | Name: {e}"
				)
	for e in exp_pools:
		actual = act_key.get(e.get("pool_name", ""))
		if not actual:
			failures.append(
					f"(DHCP) Missing DHCP Pool | Name: {e.get('pool_name', '')}"
				)
			continue
		if e.get("default_gateway") != actual.get("default_gateway"):
			failures.append(
					f"(DHCP) Default Gateway Mismatch | Pool: {e.get('pool_name', '')} | "
					f"Expected: {e.get('default_gateway', '')} | Actual: "
					f"{actual.get('default_gateway', '')}"
				)
		if e.get("dns_ip") != actual.get("dns_ip"):
			failures.append(
					f"(DHCP) DNS Server IP Mismatch | Pool: {e.get('pool_name', '')} | "
					f"Expected: {e.get('dns_ip', [])} | Actual: {actual.get('dns_ip', [])}"
				)
		if (
				e.get("lease_days") != actual.get("lease_days")
				or e.get("lease_hours") != actual.get("lease_hours")
				or e.get("lease_minutes") != actual.get("lease_minutes")
			):
			failures.append(
					f"(DHCP) Mismatched Lease Duration | Pool: {e.get('pool_name', '')} | "
					f"Expected(Days/Hours/Min): {e.get('lease_days')}/{e.get('lease_hours')}/"
					f"{e.get('lease_minutes')} | Actual(Days/Hours/Min): {actual.get('lease_days')}/"
					f"{actual.get("lease_hours")}/{actual.get('lease_minutes')}"
				)
		if (
				e.get("pool_ip") != actual.get("pool_ip")
				or e.get("pool_mask") != actual.get("pool_mask")
			):
			failures.append(
					f"(DHCP) Mismatched IP or Mask | Pool: {e.get('pool_name', '')} | "
					f"Expected: {e.get("pool_ip")}/{e.get("pool_mask")} | "
					f"Actual: {actual.get("pool_ip")}/{actual.get("pool_mask")}"
				)
		if e.get("domain_name") != actual.get("domain_name"):
			failures.append(
					f"(DHCP) Mismatched Domain Name | Pool: {e.get('pool_name')} | "
					f"Expected: {e.get('domain_name')} | Actual: {actual.get('domain_name')}"
				)
	exp_excluded = expected_dhcp.get("excluded_addresses", [])
	act_excluded = actual_config.get("excluded_addresses", [])

	act_lookup = {a.get("start_ip"): a.get("end_ip") for a in act_excluded}
	exp_lookup = {e.get("start_ip"): e.get("end_ip") for e in exp_excluded}
	for e in exp_excluded:
		exp_start = e.get("start_ip", "")
		exp_end = e.get("end_ip", "")
		actual = act_lookup.get(exp_start)
		if actual is None:
			failures.append(f"(DHCP) Missing Excluded IP: {exp_start} - {exp_end}")
		elif actual != exp_end:
			failures.append(
					f"(DHCP) Wrong Excluded End IP | Start: {exp_start} "
					f"Expected End: {exp_end} | Actual: {actual}"
				)
	extra = act_lookup.keys() - exp_lookup.keys()
	for start in extra: 
		act_entry = next((a for a in act_excluded if a.get('start_ip') == start), {})
		failures.append(
				f"(DHCP) Unexpected Excluded IP addresses | "
				f"Start IP: {start} | End IP: {act_entry.get('end_ip', '')}"
			)
	exp_helpers = expected_dhcp.get("helper", {}).get("interfaces", [])
	act_helpers = actual_config.get("helper", {}).get("interfaces", [])

	exp_lookup = defaultdict(list)
	for e in exp_helpers:
		exp_lookup[e.get("interface_name")].append(e.get("helper_ip"))
	act_lookup = defaultdict(list)
	for a in act_helpers: 
		act_lookup[a.get("interface_name")].append(a.get("helper_ip"))
	all_interfaces = set(exp_lookup.keys()) | set(act_lookup.keys())

	for interface_name in all_interfaces:
		exp_ips = set(exp_lookup.get(interface_name, []))
		act_ips = set(act_lookup.get(interface_name, []))

		missing = exp_ips - act_ips 
		extra = act_ips - exp_ips 

		for ip in missing: 
			failures.append(
					f"(DHCP) Missing Helper IP | Interface: {interface_name} | "
					f"Helper IP: {ip}"
				)
		for e in extra: 
			failures.append(
					f"(DHCP) Drift Detected: Unexpected Helper IP | "
					f"Interface: {interface_name} | Helper IP: {e}"
				)
	return len(failures) == 0, failures  