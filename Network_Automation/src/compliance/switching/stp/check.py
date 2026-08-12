def check_stp_global(expected_stp, actual_config):
    failures = []

    exp_mode = expected_stp.get("mode", "").lower().strip()
    act_mode = actual_config.get("mode", "").lower().strip()

    if exp_mode and exp_mode != act_mode:
        failures.append(
            f"Mismatched STP Mode | Expected: {exp_mode} | Actual: {act_mode}"
        )
        return False, failures
    exp_vlans = expected_stp.get("vlan_priorities", {})
    act_vlans = actual_config.get("vlan_priorities", {})

    exp_keys = set(exp_vlans.keys())
    act_keys = set(act_vlans.keys())

    if exp_keys != act_keys:
        missing = exp_keys - act_keys
        extra = act_keys - exp_keys

        if missing:
            failures.append(
                f"(STP) Missing VLANs | Expected: {exp_keys} | Actual: {act_keys}"
            )
        if extra:
            failures.append(
                f"(STP) Unexpected VLANs | Expected: {exp_keys} | Actual: {act_keys}"
            )
        return False, failures
    for vlan in exp_keys:
        exp_priority = exp_vlans.get(vlan)
        act_priority = act_vlans.get(vlan)
        if exp_priority != act_priority:
            failures.append(
                f"(STP) Mismatched Bridge Priority | "
                f"VLAN: {vlan_id} | "
                f"Expected: {exp_priority} | "
                f"Actual: {act_priority}"
            )
    return len(failures) == 0, failures


def check_stp_interfaces(expected_int, actual_config):
    failures = []
    exp_int = expected_int.get("interfaces", "")
    exp_stp = expected_int.get("stp", {})
    actual = actual_config.get(exp_int)
    if not actual:
        failures.append(f"(STP) Missing Interface | Interface: {exp_int}")
        return False, failures
    for mode, exp_values in exp_stp.items():
        act_values = actual.get(mode, False)

        if exp_values != act_values:
            failures.append(
                f"(STP) Mismatched STP Mode | Interface: {exp_int} | "
                f"Feature: {mode} | Expected: {exp_values} | Actual: {act_values}"
            )
    return len(failures) == 0, failures
