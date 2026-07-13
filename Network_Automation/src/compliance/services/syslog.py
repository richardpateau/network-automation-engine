def compliance_syslog(sesh, device_ip, context, device_state, device_result, log):
	exp_syslog = context.get("syslog", {})

	if sesh.transport == "NETCONF": 
		act_syslog = build_syslog_netconf(device_state)
	elif sesh.transport == "NETMIKO": 
		act_syslog = build_syslog_netmiko(device_state)
	else: 
		raise ValueError(
				f"Unsupported Transport Method: {sesh.transport}"
			)
	syslog_updated = False

	syslog_log = []

	if exp_syslog.get("facility"):
	    syslog_log.append(
	        f"Facility: {exp_syslog.get('facility', '')}"
	    )
	if exp_syslog.get("hosts"):
	    for h in exp_syslog.get("hosts", []):
	        syslog_log.append(
	            f"SYSLOG HOST IP: {h}"
	        )
	if exp_syslog.get("source_interface"):
	    syslog_log.append(
	        f"Source Interface: {exp_syslog.get('source_interface', '')}"
	    )
	if "timestamps" in exp_syslog:
	    syslog_log.append(
	        f"Service Timestamps (msec): {exp_syslog.get('timestamps', False)}"
	    )
	if exp_syslog.get("trap_level"):
	    syslog_log.append(
	        f"Severity: {exp_syslog.get('trap_level', '')}"
	    )
	syslog_str = " | ".join(syslog_log) or "Syslog (NETCONF) Configuration Empty"

	if exp_syslog:
	    ok, failures = check_syslog(exp_syslog, act_syslog)

	    log_extra = {
	        "device_ip": device_ip,
	        "component": "main_process",
	        "protocol": "syslog",
	        "transport": sesh.transport,
	        "host_count": len(exp_syslog.get('hosts', [])),
	        "hosts": [h for h in exp_syslog.get('hosts', [])],
	        "facility": exp_syslog.get("facility", ""),
	        "source_interface": exp_syslog.get("source_interface", ""),
	        "service_timestamps": exp_syslog.get("timestamps", False),
	        "severity": exp_syslog.get("trap_level", ""),
	        "summary": syslog_str,
	        "compliant": ok,
	        "failures_count": len(failures) if failures else 0,
	        "failures": failures
	    }

	    if ok:
	        log.info(
	            "syslog_netconf_compliant",
	            extra={
	                **log_extra,
	                "status": StepStatus.SUCCESS.value,
	                "message": "Syslog (NETCONF) Configuration Already Compliant"
	            }
	        )
	        device_result["actions_taken"].append(
	            "Syslog (NETCONF) Configuration Already Compliant | "
	            f"{syslog_str}"
	        )
	    else:
	        log.warning(
	            "syslog_netconf_non_compliant",
	            extra={
	                **log_extra,
	                "status": StepStatus.FAILED.value,
	                "message": "Syslog (NETCONF) Configuration Non-Compliant"
	            }
	        )
	        device_result["initial_issues"].extend(failures)

	        if sesh.transport == "NETCONF": 
	        	result = configure_syslog_netconf(sesh, exp_syslog, log)
	        elif sesh.transport == "NETMIKO": 
	        	result = configure_syslog_netmiko(sesh, exp_syslog, log)

	        summary = result.get("summary")

	        if summary:
	            device_result["actions_taken"].append(summary)
	        if result.get("status") == OperationalStatus.SUCCESS.value:
	            syslog_updated = True
	        else: 
	        	device_result["status"] = OperationalStatus.FAILED_CONFIG.value

	if syslog_updated and not DRY_RUN:
		if sesh.transport == "NETCONF": 
		    new_state = collect_netconf_state(sesh)
		    new_syslog = build_syslog_netconf(new_state)
		elif sesh.transport == "NETMIKO": 
			new_state = collect_device_state(sesh)
			new_syslog = build_syslog_netmiko(new_state)
        
        ok, failures = check_syslog(exp_syslog, new_syslog)

        log_extra = {
            "device_ip": device_ip,
            "component": "main_process",
            "protocol": "syslog",
            "transport": sesh.transport,
            "host_count": len(exp_syslog.get('hosts', [])),
            "hosts": [h for h in exp_syslog.get('hosts', [])],
            "facility": exp_syslog.get("facility", ""),
            "source_interface": exp_syslog.get("source_interface", ""),
            "service_timestamps": exp_syslog.get("timestamps", False),
            "severity": exp_syslog.get("trap_level", ""),
            "summary": syslog_str,
            "compliant": ok,
            "failures_count": len(failures) if failures else 0,
            "failures": failures
        }

        if not ok:
            log.error(
                "syslog_netconf_post_validation_failed",
                extra={
                    **log_extra,
                    "status": StepStatus.FAILED.value,
                    "message": "Syslog (NETCONF) Configuration Post Validation Failed"
                }
            )
            device_result["critical_issues"].extend(failures)
            device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
        else:
            log.info(
                "syslog_netconf_post_validation_success",
                extra={
                    **log_extra,
                    "status": StepStatus.SUCCESS.value,
                    "message": "Syslog (NETCONF) Configuration Post Validation Successful"
                }
            )
            device_result["actions_taken"].append(
                "Syslog (NETCONF) Configuration Post Validation Successful | "
                f"{syslog_str}"
            )
	return device_result
