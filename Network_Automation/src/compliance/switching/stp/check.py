def check_stp_global(expected_stp, actual_config):
    failures = []

    exp_mode = expected_stp.get("mode", "").lower().strip()
    act_mode = actual_config.get("mode", "").lower().strip()

    if exp_mode and exp_mode != act_mode:
        failures.append(
            f"Mismatched STP Mode | Expected: {exp_mode} | Actual: {act_mode}"
        )
    exp_vlans = expected_stp.get("vlan_priorities", {})
    act_vlans = actual_config.get("vlan_priorities", {})

    exp_keys = set(exp_vlans.keys())
    act_keys = set(act_vlans.keys())

    if exp_keys != act_keys:
        missing = exp_keys - act_keys
        extra = act_keys - exp_keys

        if missing:
            failures.append(
                f"(STP) Missing VLANs | {sorted(missing)} "
            )
        if extra:
            failures.append(
                f"(STP) Rogue VLANs | {sorted(extra)}"
            )
    for vlan in exp_keys:
        exp_priority = exp_vlans.get(vlan)
        act_priority = act_vlans.get(vlan)
        if act_priority is None:
            continue 
        if exp_priority != act_priority:
            failures.append(
                f"(STP) Mismatched Bridge Priority | "
                f"VLAN: {vlan} | "
                f"Expected: {exp_priority} | "
                f"Actual: {act_priority}"
            )
    return len(failures) == 0, failures


def check_stp_interfaces(expected_int, actual_config):
    failures = []
    exp_by_int = {e.get("interface"): e for e in expected_int}
    for interface, value in exp_by_int.items(): 
        actual = actual_config.get(interface)
        if not actual: 
            failures.append(f"(STP) Missing Interface | {interface}")
            continue 
        portfast = value.get("stp", {}).get("portfast")
        if portfast != actual.get("portfast"):
            failures.append(
                    "(STP Interface) Mismatched PortFast | "
                    f"Should Be Configured? | Expected: {portfast} | "
                    f"Actual: {actual.get('portfast')}"
                )
        bpdu_guard = value.get("stp", {}).get("bpdu_guard")
        if bpdu_guard != actual.get("bpdu_guard"):
            failures.append(
                    "(STP Interface) Mismatched BPDU Guard | Should Be Configured? | "
                    f"Expected: {bpdu_guard} | Actual: {actual.get('bpdu_guard')}"
                    )
        root_guard = value.get("stp", {}).get("root_guard")
        if root_guard != actual.get("root_guard"): 
            failures.append(
                    "(STP Interface) Mismatched Root Guard | Should Be Configured? | "
                    f"Expected: {root_guard} | Actual: {actual.get('root_guard')}"
                )
        loop_guard = value.get("stp", {}).get("loop_guard")
        if loop_guard != actual.get("loop_guard"):
            failures.append(
                    "(STP Interface) Mismatched Loop Guard | Should Be Configured? | "
                    f"Expected: {loop_guard} | Actual: {actual.get('loop_guard')}" 
                )
        bpdu_filter = value.get("stp", {}).get("bpdu_filter")
        if bpdu_filter != actual.get('bpdu_filter'): 
            failures.append(
                    "(STP Interface) Mismatched BPDU Filter | Should Be Configured? | "
                    f"Expected: {bpdu_filter} | Actual: {actual.get('bpdu_filter')}"
                )
    return len(failures) == 0, failures
