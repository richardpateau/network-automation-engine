def check_ospf(expected_ospf, actual_config): 
    failures = []
    exp_proc = expected_ospf.get("process_id", "")
    exp_router_id = expected_ospf.get("router_id", "")
    exp_net_list = expected_ospf.get("network_list", [])
    actual = actual_config.get(exp_proc)
    if not actual:
        failures.append(
                f"Missing Process ID (OSPF) | ID: {exp_proc}"
            )
        return False, failures
    actual_router_id = actual.get("router_id", "")
    if exp_router_id != actual_router_id:
        failures.append(
                f"(OSPF) Mismatched Router ID | Process: {exp_proc} | "
                f"Expected RID: {exp_router_id} | Actual RID: {actual_router_id}"
            )
        return False, failures
    actual_net_list = actual.get("network_list", [])
    for exp_net in exp_net_list:
        matched = False
        exp_subnet = str(exp_net.get("subnet", ""))
        exp_wildcard = str(exp_net.get("wildcard", ""))
        exp_area = str(exp_net.get("area", ""))
        for act_net in actual_net_list:
            act_subnet = str(act_net.get("subnet", ""))
            act_wildcard = str(act_net.get("wildcard", ""))
            act_area = str(act_net.get("area", ""))

            if (
                exp_subnet == act_subnet and
                exp_wildcard == act_wildcard and
                exp_area == act_area
                ):
                matched = True
            if not matched:
                failures.append(
                    f"Expected OSPF Network Not Found | "
                    f"Nework Address: {exp_subnet} | "
                    f"Wildcard: {exp_wildcard} | "
                    f"Area: {exp_area}"
                )
    return len(failures) == 0, failures