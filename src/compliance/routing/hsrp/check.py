from src.utils.helpers import safe_int
def check_hsrp(expected_hsrp, actual_config):
        failures = []
        actual_hsrp = {
            (a.get("interface").lower(), a.get("router_vlan"), a.get("group")): a
            for a in actual_config
        }

        if expected_hsrp:
            expected_hsrp_key = (
                expected_hsrp.get("interface", "").lower(),
                expected_hsrp.get("router_vlan", ""),
                expected_hsrp.get("group", "")
            )
            actual = actual_hsrp.get(expected_hsrp_key)

            if not actual:
                failures.append(
                    f"(HSRP) Missing Configuration | Interface: {expected_hsrp_key[0]} | "
                    f"VLAN: {expected_hsrp_key[1]} | Group: {expected_hsrp_key[2]}"
                )
                return False, failures
            if expected_hsrp.get("vip") != actual.get("vip"):
                failures.append(
                    f"(HSRP) Mismatched Virtual IP | Interface: {expected_hsrp_key[0]} | "
                    f"VLAN: {expected_hsrp_key[1]} | Group: {expected_hsrp_key[2]} | "
                    f"Expected: {expected_hsrp.get('vip')} | Actual: {actual.get('vip')}"
                )
            if safe_int(expected_hsrp.get("priority")) != safe_int(actual.get("priority")):
                failures.append(
                    f"(HSRP) Mismatched Priority | Interface: {expected_hsrp_key[0]} | "
                    f"VLAN: {expected_hsrp_key[1]} | Group: {expected_hsrp_key[2]} | "
                    f"Expected: {expected_hsrp.get('priority')} | Actual: {actual.get('priority')}"
                )
            if expected_hsrp.get("preempt") != actual.get("preempt"):
                failures.append(
                    f"(HSRP) Mismatched Preempt | Interface: {expected_hsrp_key[0]} | "
                    f"VLAN: {expected_hsrp_key[1]} | Group: {expected_hsrp_key[2]} | "
                    f"Expected: {expected_hsrp.get('preempt')} | Actual: {actual.get('preempt')}"
                )
            if expected_hsrp.get("version") != actual.get("version"):
                failures.append(
                    f"(HSRP) Mismatched Version | Interface: {expected_hsrp_key[0]} | "
                    f"VLAN: {expected_hsrp_key[1]} | Group: {expected_hsrp_key[2]} | "
                    f"Expected: {expected_hsrp.get('version')} | Actual: {actual.get('version')}"
                )
        return len(failures) == 0, failures


def check_extra_hsrp(expected_list, actual_config):
    failures = []
    actual_keys = {
        (
            str(a.get("interface", "")).lower(),
            a.get("router_vlan") or None,
            a.get("group"),
        )
        for a in actual_config
    }
    expected_keys = {
        (
            str(e.get("interface", "")).lower(),
            e.get("router_vlan") or None,
            e.get("group"),
        )
        for e in (expected_list or [])
    }

    extra = set(actual_keys) - set(expected_keys)
    if extra:
        for interface, vlan, group in extra:
            failures.append(
                f"(HSRP) Unexpected HSRP Configuration | "
                f"Interface: {interface} | VLAN: {vlan} | Group: {group}"
            )

    return len(failures) == 0, failures
