def check_ntp(expected_ntp, actual_config):
    failures = []
    exp_keys = exp_ntp.get("keys", [])
    exp_servers = exp_ntp.get("servers", [])
    act_keys = actual_config.get("keys", [])
    act_servers = actual_config.get("servers", [])
    act_by_id = {i.get("id"): i for i in act_keys}

    for exp_key in exp_keys:
        exp_id = exp_key.get("id", "")
        exp_trusted = exp_key.get("trusted", False)
        matched = False
        actual = act_by_id.get(exp_id)
        if not actual:
            failures.append(f"Missing Key ID | Key ID(s): {exp_id}")
            continue
     
        if exp_trusted != actual.get("trusted"):
            failures.append(
                f"NTP Trusted (Bool) Key Mismatch | Key: {exp_id} | "
                f"Expected: {exp_trusted} | Actual: {actual.get('trusted')}"
                    )
    
    exp_by_id = {i.get("id"): i for i in exp_keys}
    for act_key in act_keys:
        act_id = act_key.get("id", "")
        expected = exp_by_id.get(act_id)
        if not expected: 
            failures.append(
                    f"(NTP) Rogue Key ID | Key ID: {act_id}" 
                )
            continue

    actual_by_ip = {i.get("server_ip"): i for i in act_servers}
    for exp_server in exp_servers:
        exp_ip = exp_server.get("server_ip", "")
        exp_id = exp_server.get("server_id", "")
        actual = actual_by_ip.get(exp_ip)
        if not actual:
            failures.append(
                     f"Missing NTP Server on Device | Expected IP: {exp_ip} | "
                )
            continue
            if exp_id != actual.get("server_id"):
                failures.append(
                    f"(NTP) Mismatched Server Key ID | Server IP: {exp_ip} | "
                    f"Expected ID: {exp_id} | Actual ID: {actual.get('server_id')}"
                )
    
    expected_by_ip = {i.get("server_ip"): i for i in exp_servers}
    for act in act_servers:
        act_ip = exp.get("server_ip")
        expected = expected_by_ip.get(act_ip)
        if not expected: 
            failures.append(
                    f"(NTP) Rogue NTP Server IP | IP: {act_ip}"
                )
            
            
    return len(failures) == 0, failures
