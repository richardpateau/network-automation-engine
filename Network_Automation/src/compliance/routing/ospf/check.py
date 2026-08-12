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
    act_by_subnet = {
        str(a.get("subnet", "")): a
        for a in actual_net_list
    }
    for exp_net in exp_net_list:
        exp_subnet = str(exp_net.get("subnet", ""))
        exp_wildcard = str(exp_net.get("wildcard", ""))
        exp_area = safe_int(exp_net.get("area", ""))

        actual = act_by_subnet.get(exp_subnet)

        if not actual: 
            failures.append(
                   f"(OSPF) Expected Network Not Found on Device | "
                   f"Expected: {exp_subnet} | Wildcard: {exp_wildcard} | Area: {exp_area}"
                )
            continue
        if safe_int(actual.get("area", "")) != exp_area:
            failures.append(
                  f"(OSPF) Area Mismatch | Network: {exp_subnet} | "
                  f"Expected: {exp_area} | Actual: {actual.get('area', '')}"
                )
        if actual.get("wildcard") != exp_wildcard: 
            failures.append(
                    f"(OSPF) Mismatched Wildcard | Network: {exp_subnet} | "
                    f"Expected: {exp_wildcard} | Actual: {actual.get('wildcard')}"
                )
    exp_by_subnet = {
        str(e.get("subnet", "")): e
        for e in exp_net_list
    }
    for act_net in actual_net_list: 
        act_subnet = str(act_net.get("subnet", ""))

        expected = exp_by_subnet.get(act_subnet)
        if not expected: 
            failures.append(
                    f"(OSPF) Rogue Network Found | Network: {act_subnet} | "
                    f"Wildcard: {act_net.get('wildcard', '')} | Area: {act_net.get('area', '')}"
                )
    return len(failures) == 0, failures