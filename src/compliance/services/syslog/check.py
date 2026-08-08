def check_syslog(expected_syslog, actual_config, transport): 
	failures = []
	exp_hosts = set(expected_syslog.get("hosts", []))
	act_hosts = set(actual_config.get("hosts", []))

	missing_hosts = exp_hosts - act_hosts
	extra_hosts = act_hosts - exp_hosts

	if missing_hosts:
		for ip in missing_hosts: 
			failures.append(
					f"(SYSLOG) Missing Syslog Host | IP: {ip}"
				)
	if extra_hosts: 
		for ip in extra_hosts: 
			failures.append(
					f"(SYSLOG) Drift: Extra Syslog Host | IP: {ip}"
				)
	if transport == "NETCONF": 
		if expected_syslog.get("facility") != actual_config.get("facility"): 
			failures.append(
					f"(SYSLOG) Mismatched Facility | Expected: {expected_syslog.get('facility')} | "
					f"Actual: {actual_config.get('facility')}"
				)
	if expected_syslog.get("source_interface"): 
		if expected_syslog.get("source_interface") != actual_config.get("source_interface"):
			failures.append(
					f"(SYSLOG) Mismatched Source Interface | "
					f"Expected: {expected_syslog.get('source_interface')} | "
					f"Actual: {actual_config.get('source_interface')}"
				)
	if expected_syslog.get("timestamps") is True: 
		if not actual_config.get("timestamps"):
			failures.append(
					f"(SYSLOG) Mismatched Timestamps Configuration | service timestamps log datetime msec "
					f"Expected: {expected_syslog.get('timestamps')} | "
					f"Actual: {actual_config.get('timestamps')}"
				)
	if expected_syslog.get("trap_level") != actual_config.get("trap_level"): 
		failures.append(
				f"(SYSLOG) Mismatched Trap Level | "
				f"Expected: {expected_syslog.get('trap_level')} | "
				f"Actual: {actual_config.get('trap_level')}"
			)
	return len(failures) == 0, failures