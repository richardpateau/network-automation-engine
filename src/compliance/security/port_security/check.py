def check_port_security(expected_psecurity, actual_config):
    failures = []
    exp_psecurity = expected_psecurity.get("interfaces", {})
    act_psecurity = actual_config.get("interfaces", {})

    extra_int = act_psecurity.keys() - exp_psecurity.keys()
    if extra_int:
        for e_int in extra_int:
            failures.append(
                f"(Port Security) Drift: Extra Interface Configured with PS | "
                f"Interface: {e_int}"
            )
    for interface, int_value in exp_psecurity.items():
        actual = act_psecurity.get(interface)
        if not actual:
            failures.append(
                f"(Port Security) Interface Not Configured with Port Security | "
                f"Interface: {interface}"
            )
            continue
        if actual.get("enabled") != int_value.get("enabled"):
            failures.append(
                f"(Port Security) Port Security Should Be Enabled Mismatch | "
                f"Expected: {int_value.get('enabled')} | Actual: {actual.get('enabled')}"
            )
        if actual.get("maximum") != int_value.get("maximum"):
            failures.append(
                f"(Port Security) Mismatched Maximum Allowed | "
                f"Expected: {int_value.get('maximum')} | "
                f"Actual: {actual.get('maximum')}"
            )
        if actual.get("sticky") != int_value.get("sticky"):
            failures.append(
                f"(Port Security) Mismatched Sticky Configuration | "
                f"Expected: {int_value.get('sticky')} | "
                f"Actual: {actual.get('sticky')}"
            )
        if actual.get("violation") != int_value.get("violation"):
            failures.append(
                f"(Port Security) Mismatched Violation Configuration | "
                f"Expected: {int_value.get('violation')} | "
                f"Actual: {actual.get('violation')}"
            )
        exp_mac = set(int_value.get("mac_addresses", []))
        act_mac = set(actual.get("mac_addresses", []))
        missing_mac = exp_mac - act_mac
        extra_mac = act_mac - exp_mac

        if missing_mac:
            for m in missing_mac:
                failures.append(f"(Port Security) Missing MAC Address | " f"MAC: {m}")
        if extra_mac:
            for e in extra_mac:
                failures.append(
                    f"(Port Security) Drift: Extra MAC Address Found | " f"MAC: {e}"
                )
    return len(failures) == 0, failures
