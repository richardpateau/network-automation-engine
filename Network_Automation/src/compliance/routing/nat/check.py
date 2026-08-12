def check_nat(expected_nat, actual_config):
    failures = []
    if expected_nat.get("pat"):
        if not actual_config.get("pat"):
            failures.append(f"(NAT) Configuration Drift: Missing PAT")
        else:
            exp_pat = expected_nat.get("pat", {})
            act_pat = actual_config.get("pat", {})

            if exp_pat.get("acl", "") != act_pat.get("acl", ""):
                failures.append(
                    f"(PAT) Mismatched ACL Found | Expected: {exp_pat.get('acl')} | "
                    f"Actual: {act_pat.get('acl')}"
                )
            if exp_pat.get("interface", "") != act_pat.get("interface", ""):
                failures.append(
                    f"(PAT) Mismatched Interfaces Found | "
                    f"Expected: {exp_pat.get('interface', '')} | "
                    f"Actual: {act_pat.get('interface', '')}"
                )
            if exp_pat.get("overload") != act_pat.get("overload"):
                failures.append(
                    f"(PAT) Mismatched Overload Configuration | "
                    f"Expected: {exp_pat.get('overload')} | "
                    f"Actual: {act_pat.get('overload')}"
                )
    else:
        if actual_config.get("pat"):
            failures.append(f"(PAT) Configuration Drift | Unexpected PAT Configuration")
    if expected_nat.get("static"):
        if not actual_config.get("static"):
            failures.append(f"(NAT) Configuration Drift: Missing Static Mapping")
        exp_static = expected_nat.get("static", [])
        act_static = actual_config.get("static", [])

        exp_set = {(s["inside_ip"], s["outside_ip"]) for s in exp_static}
        act_set = {(s["inside_ip"], s["outside_ip"]) for s in act_static}

        missing = exp_set - act_set
        extra = act_set - exp_set

        for inside, outside in missing:
            failures.append(
                f"(NAT STATIC) Missing Static Mapping | "
                f"Inside Local: {inside} | Outside Global: {outside}"
            )
        for inside, outside in extra:
            failures.append(
                "(NAT STATIC) Extra (Drift) Static Configuration | "
                f"Inside Local: {inside} | Outside Global: {outside}"
            )
    else:
        if actual_config.get("static"):
            failures.append(
                f"(NAT) Configuration Drift: Unexpected Static Configuration Found"
            )
    if expected_nat.get("dynamic"):
        if not actual_config.get("dynamic"):
            failures.append(
                f"(NAT) Configuration Drift: Missing Dynamic NAT Configuration"
            )
            return False, failures
        else:
            exp_dynamic = expected_nat.get("dynamic", [])
            act_dynamic = actual_config.get("dynamic", [])

            exp_set = {e["pool_name"]: e for e in exp_dynamic}
            act_set = {a["pool_name"]: a for a in act_dynamic}
            for p_name, p_values in exp_set.items():
                actual = act_set.get(p_name)
                if not actual:
                    failures.append(
                        f"(Dynamic NAT) Expected Pool Not Found on Device | "
                        f"Expected: {p_name}"
                    )
                    continue
                if actual.get("acl") != p_values.get("acl"):
                    failures.append(
                        f"(Dynamic NAT) ACL Mismatch | Pool: {p_name} | "
                        f"Expected: {p_values.get('acl', '')} | "
                        f"Actual: {actual.get('acl', '')}"
                    )
                if actual.get("start_ip") != p_values.get("start_ip"):
                    failures.append(
                        f"(Dynamic NAT) Mismatched Pool Start IP | Pool: {p_name} |"
                        f"Expected: {p_values.get('start_ip')} | "
                        f"Actual: {actual.get('start_ip')}"
                    )
                if actual.get("end_ip") != p_values.get("end_ip"):
                    failures.append(
                        f"(Dynamic NAT) Mismatched End IP | Pool: {p_name} |"
                        f"Expected: {p_values.get('end_ip', '')} | "
                        f"Actual: {actual.get('end_ip', '')}"
                    )
                if actual.get("mask") != p_values.get("mask"):
                    failures.append(
                        f"(Dynamic NAT) Mismatched Mask | Pool: {p_name} |"
                        f" Expected: {p_values.get('mask')} | "
                        f"Actual: {actual.get('mask')}"
                    )
            extra_pools = set(act_set.keys()) - set(exp_set.keys())
            for e in extra_pools:
                failures.append(
                    f"(Dynamic NAT) (Drift) Unexpected Pool Found on Device | "
                    f"Pool: {e}"
                )
    else:
        if actual_config.get("dynamic"):
            failures.append(
                f"(Dynamic NAT) Configuration Drift: Unexpected Dynamic NAT Configuration Found"
            )
    exp_inside = expected_nat.get("interfaces", {}).get("inside", [])
    exp_outside = expected_nat.get("interfaces", {}).get("outside", [])
    if exp_inside:
        act_inside = actual_config.get("interfaces", {}).get("inside", [])
        exp_set = set(exp_inside)
        act_set = set(act_inside)

        extra = act_set - exp_set
        missing = exp_set - act_set

        if missing:
            failures.append(f"(NAT) Missing Inside Interface: {', '.join(missing)}")
        if extra:
            failures.append(f"(NAT) Extra Inside Interface: {', '.join(extra)} ")
    if exp_outside:
        act_outside = actual_config.get("interfaces", {}).get("outside", [])
        exp_set = set(exp_outside)
        act_set = set(act_outside)

        extra = act_set - exp_set
        missing = exp_set - act_set

        if missing:
            failures.append(f"(NAT) Missing Outside Interface: {','.join(missing)} ")
        if extra:
            failures.append(f"(NAT) Extra Outside Interface: {','.join(extra)} ")

    return len(failures) == 0, failures
