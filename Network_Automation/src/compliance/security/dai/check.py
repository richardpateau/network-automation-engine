def check_dai(expected_dai, actual_config):
    failures = []
    exp_arp = expected_dai.get("arp_inspection")
    if exp_arp is not None:
        if exp_arp != actual_config.get("arp_inspection"):
            failures.append(
                "(DAI) Operational State Mismatch"
                f" | Expected: {exp_arp} | Actual: {actual_config.get('arp_inspection')}"
            )
    exp_vlans = set(expected_dai.get("enabled_vlans", []))
    act_vlans = set(actual_config.get("enabled_vlans", []))
    missing_vlans = exp_vlans - act_vlans
    extra_vlans = act_vlans - exp_vlans

    if missing_vlans:
        failures.append(
            f"(DAI) Missing VLAN(s) | VLAN(s): {sorted(missing_vlans)}"
        )
    if extra_vlans:
        failures.append(
            f"(DAI) Drift: Extra VLAN(s) Found | VLAN: {sorted(extra_vlans)}"
        )

    exp_buffer = expected_dai.get("log_buffer", {})
    act_buffer = actual_config.get("log_buffer", {})

    if exp_buffer.get("enabled") != act_buffer.get("enabled"):
        failures.append(
            f"(DAI) Log Buffer State Mismatch | "
            f"Expected: {exp_buffer.get('enabled')} | "
            f"Actual: {act_buffer.get('enabled')}"
        )
    if exp_buffer.get("enabled") and act_buffer.get("enabled"):
        if exp_buffer.get("entries") != act_buffer.get("entries"):
            failures.append(
                f"(DAI) Log Buffer Entries Mismatch | "
                f"Expected: {exp_buffer.get('entries')} | "
                f"Actual: {act_buffer.get('entries')}"
            )
    exp_interfaces = expected_dai.get("interfaces", {})
    act_interfaces = actual_config.get("interfaces", {})

    extra_int = act_interfaces.keys() - exp_interfaces.keys()

    if extra_int:
        for e in extra_int:
            failures.append(
                f"(DAI) Drift: Extra Interface Configured with DAI | "
                f"Interface: {e}"
            )
    for interface_name, int_value in exp_interfaces.items():
        actual = act_interfaces.get(interface_name)
        if not actual:
            failures.append(
                f"(DAI) Missing Interface Not Configured with DAI | "
                f"Interface: {interface_name}"
            )
            continue
        if actual.get("rate_limit") != int_value.get("rate_limit"):
            failures.append(
                f"(DAI) Misatched Rate Limit Configuration | "
                f"Expected: {int_value.get('rate_limit')} | "
                f"Actual: {actual.get('rate_limit')}"
            )
        if actual.get("trusted") != int_value.get("trusted"):
            failures.append(
                f"(DAI) Mismatched Trusted Interface Configuration | "
                f"Expected: {int_value.get('trusted')} | "
                f"Actual: {actual.get('trusted')}"
            )
    return len(failures) == 0, failures
