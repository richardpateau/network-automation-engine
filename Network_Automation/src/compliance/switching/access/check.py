def check_access(expected_access, actual_config):
    failures = []
    exp_by_int = {e.get("access_interface"): e for e in expected_access}
    for k, v in exp_by_int.items():
        actual = actual_config.get(k)
        if not actual:
            failures.append(
                f"(Access) Missing Interface | {k}"
            )
            continue
        if v.get("access_vlan") != actual.get("access_vlan"):
            failures.append(
                f"(Access) Mismatched VLAN | Interface: {k} | "
                f"Expected: {v.get('access_vlan')} | "
                f"Actual: {actual.get('access_vlan')}"
            )

    return len(failures) == 0, failures


def check_rogue_access(expected_access, actual_config):
    failures = []

    expected_interfaces = {
        access.get("access_interface")
        for access in expected_access
    }

    for interface in actual_config:
        if interface not in expected_interfaces:
            failures.append(
                f"(Access) Rogue Interface Configured | "
                f"Interface: {interface}"
            )

    return len(failures) == 0, failures
