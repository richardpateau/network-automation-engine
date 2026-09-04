def check_vlan(expected_vlans, actual_vlans):
    failures = []
    exp_by_id = {int(v.get("vlan_id")): v for v in expected_vlans}
    for vid, exp in exp_by_id.items():
        actual = actual_vlans.get(vid)
        if not actual:
            failures.append(
                f"Missing VLAN {vid} | Name: {exp.get('name')}"
            )
            continue
        exp_name = str(exp.get("name") or "").strip()
        act_name = str(actual.get("name") or "").strip()
        if exp_name.lower() != act_name.lower():
            failures.append(
                f"VLAN Name Mismatch | VLAN: {vid} "
                f"| Expected: {exp_name} | Actual: {act_name}"
            )
    return len(failures) == 0, failures

def check_rogue_vlan(expected_vlans, actual_vlans):
    failures = []
    reserved = {1002, 1003, 1004, 1005}
    expected_ids = {
        vlan.get("vlan_id")
        for vlan in expected_vlans
    }

    for vlan_id, actual in actual_vlans.items():
        if vlan_id in reserved:
            continue
        if vlan_id not in expected_ids:
            failures.append(
                f"Rogue VLAN Detected | "
                f"VLAN: {vlan_id} | "
                f"Name: {actual.get('name')}"
            )

    return len(failures) == 0, failures