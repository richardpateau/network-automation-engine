from src.utils.helpers import normalize_to_list, safe_int
import json

# ROAS
def build_roas(restconf_state):
    if not restconf_state:
        return {}
    restconf_state_roas = restconf_state.get("interface_restconf") or {}
    actual_roas = {}
    interfaces = restconf_state_roas.get("Cisco-IOS-XE-native:interface", {})
    for gigabit, gigabit_value in interfaces.items():
        gigabit_values = normalize_to_list(gigabit_value)
        for g in gigabit_values:
            name = str(g.get("name", ""))

            if "." not in name:
                continue
            full_interface = f"{gigabit}{name}".lower().strip()
            vlan_id = g.get("encapsulation", {}).get("dot1Q", {}).get("vlan-id", "")
            ip_address = (
                g.get("ip", {}).get("address", {}).get("primary", {}).get("address", "")
            )
            mask = g.get("ip", {}).get("address", {}).get("primary", {}).get("mask", "")
            if not vlan_id or not ip_address or not mask:
                continue
            actual_roas[full_interface.lower()] = {
                "interface": full_interface,
                "router_vlan": safe_int(vlan_id),
                "ip": ip_address,
                "mask": mask,
            }
    return actual_roas


# OSPF
def build_ospf(restconf_state):
    if not restconf_state:
        return {}
    actual_ospf = {}
    restconf_state_ospf = restconf_state.get("ospf_restconf") or {}
    get_ospf = restconf_state_ospf.get("Cisco-IOS-XE-native:router", {}).get(
        "Cisco-IOS-XE-ospf:ospf", []
    )
    ospf_list = normalize_to_list(get_ospf)
    for o in ospf_list:
        process_id = o.get("id", "")
        if not process_id: 
            return {}
        router_id = o.get("router-id", "")
        network_list = o.get("network", [])
        if process_id is not None:
            actual_ospf[process_id] = {
                "process_id": process_id,
                "router_id": router_id,
                "network_list": []
            }
            for n in network_list: 
                actual_ospf[process_id]["network_list"].append({
                        "subnet": n.get("ip", ""),
                        "wildcard": n.get("mask", ""),
                        "area": n.get("area", "")
                    })
    return actual_ospf

