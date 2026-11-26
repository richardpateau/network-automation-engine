def check_syslog(expected_syslog, actual_config, transport): 
	failures = []
	exp_hosts = {
		(
			h.get("host"),
			h.get("port", 514),
			h.get("transport", "udp")
		)
		for h in expected_syslog.get("hosts", [])
	}
	act_hosts = {
		(
			h.get("host"),
			h.get("port", 514),
			h.get("transport", "udp")
		)
		for h in actual_config.get("hosts", [])
	}

	if exp_hosts != act_hosts:
		failures.append(
				f"(SYSLOG) Mismatched Syslog Host Configuration | "
				f"Expected: {','.join(map(str,exp_hosts))} | Actual: {','.join(map(str,act_hosts))}"
			)
	if transport == "NETCONF": 
		if expected_syslog.get("facility") != actual_config.get("facility"): 
			failures.append(
					f"(SYSLOG) Mismatched Facility | Expected: {expected_syslog.get('facility')} | "
					f"Actual: {actual_config.get('facility')}"
				)
	if expected_syslog.get("source_interface"): 
		if expected_syslog.get("source_interface").lower() != actual_config.get("source_interface").lower():
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