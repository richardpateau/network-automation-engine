def check_ntp(expected_ntp, actual_config):
    failures = []
    exp_ntp = expected_ntp.get("ntp", {})
    exp_keys = exp_ntp.get("keys", [])
    exp_servers = exp_ntp.get("servers", [])
    act_keys = actual_config.get("keys", [])
    act_servers = actual_config.get("servers", [])

    for exp_key in exp_keys:
        exp_id = exp_key.get("id", "")
        exp_trusted = exp_key.get("trusted", False)
        matched = False
        for act_key in act_keys:
            act_id = act_key.get("id", "")
            act_trusted = act_key.get("trusted", "")

            if exp_id == act_id:
                matched = True

                if exp_trusted != act_trusted:
                    failures.append(
                        f"NTP Trusted (BOOL) Key Mismatch | Key: {exp_id} | "
                        f"Expected: {exp_trusted} | Actual: {act_trusted}"
                    )
        if not matched:
            failures.append("Missing Key ID | Key ID: {exp_id}")
    for exp_server in exp_servers:
        exp_ip = exp_server.get("ip", "")
        exp_id = exp_server.get("key_id", "")
        for act_server in act_servers:
            act_ip = act_server.get("server_ip", "")
            act_id = act_server.get("server_id", "")
            matched = False

            if exp_key == act_ip:
                matched = True

                if exp_id != act_id:
                    failures.append(
                        f"(NTP) Mismatched Server Key ID | Server IP: {exp_ip} | "
                        f"Expected ID: {exp_id} | Actual ID: {act_id}"
                    )
        if not matched:
            failures.append(
                f"Missing NTP Server on Device | Expected IP: {exp_ip} | "
                f"Actual: {act_ip}"
            )
    return len(failures) == 0, failures
