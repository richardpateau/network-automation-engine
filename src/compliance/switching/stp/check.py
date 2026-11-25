def check_stp_global(expected_stp, actual_config):
    failures = []

    exp_mode = expected_stp.get("mode", "").lower().strip()
    act_mode = actual_config.get("mode", "").lower().strip()

    if exp_mode and exp_mode != act_mode:
        failures.append(
            f"Mismatched STP Mode | Expected: {exp_mode} | Actual: {act_mode}"
        )
        return False, failures
    exp_vlans = {
        str(vlan): str(prio).strip()
        for vlan, prio in expected_stp.get("vlan_priorities", {}).items()
        }
    act_vlans = {
        str(vlan): str(prio).strip()
        for vlan, prio in actual_config.get("vlan_priorities", {}).items()
        }

    if exp_vlans.keys() != act_vlans.keys():
        failures.append(
            f"(STP) Mismatched VLANs | Expected: {exp_vlans.keys()} | Actual: {act_vlans.keys()}"
        )
        return False, failures
    for vlan in exp_vlans.keys():
        exp_priority = exp_vlans.get(vlan)
        act_priority = act_vlans.get(vlan)
        if exp_priority != act_priority:
            failures.append(
                f"(STP) Mismatched Bridge Priority | "
                f"VLAN: {vlan} | "
                f"Expected: {exp_priority} | "
                f"Actual: {act_priority}"
            )
    return len(failures) == 0, failures


def check_stp_interfaces(expected_interfaces, actual_config):
    failures = []
    
    for interface in expected_interfaces:
        exp_int = interface.get("interface", "").lower()
        exp_stp = interface.get("stp", {})

        actual = actual_config.get(exp_int)

        if not actual:
            failures.append(
                f"(STP) No Features are configured | Interface: {exp_int}"
            )
            continue

        for mode, exp_value in exp_stp.items():
            act_value = actual.get(mode, False)

            if exp_value != act_value:
                failures.append(
                    f"(STP) Mismatched STP Mode | Interface: {exp_int} | "
                    f"Feature: {mode} | Expected: {exp_value} | "
                    f"Actual: {act_value}"
                )

    return len(failures) == 0, failures

