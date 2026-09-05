def check_trunk(expected_trunk, actual_config):
    failures = []

    exp_by_int = {t.get("trunk_interface"): t for t in expected_trunk}

    for k, v in exp_by_int.items():
        actual = actual_config.get(k)
        if not actual:
            failures.append(
                f"(Trunk) Missing Interface | {k}"
            )
            continue
        if v.get("mode") != actual.get("mode"):
            failures.append(
                f"(Trunk) Mismatched Operational Mode | "
                f"Expected: {v.get('mode')} | "
                f"Actual: {actual.get('mode')}"
            )
        if v.get("allowed_vlans") != actual.get("allowed_vlans"):
            failures.append(
                f"(Trunk) Mismatched Allowed VLANs | "
                f"Expected: {v.get('allowed_vlans')} | "
                f"Actual: {actual.get('allowed_vlans')}"
            )
    return len(failures) == 0, failures


def check_rogue_trunk(expected_trunk, actual_config):
    failures = []

    expected_interfaces = {
        trunk.get("trunk_interface")
        for trunk in expected_trunk
    }

    for interface in actual_config:
        if interface not in expected_interfaces:
            failures.append(
                f"(Trunk) Rogue Interface Configured in Trunk Mode | "
                f"{interface}"
            )

    return len(failures) == 0, failures
