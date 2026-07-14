from src.utils import normalize_to_list

#ROAS 
def build_roas(restconf_state): 
	restconf_state_roas = restconf_state.get("interface_restconf", {})
	actual_roas = {}
	interfaces = restconf_state_roas.get("Cisco-IOS-XE-native:interface", {})
	for gigabit, gigabit_value in interfaces.items():
		gigabit_values = normalize_to_list(gigabit_value)
		for g in gigabit_values:
			name = str(g.get("name", ""))

			if "." not in name: 
				continue
			full_interface = f"{gigabit}{name}".lower().strip()
			vlan_id = (g.get("encapsulation", {})
						.get("dot1Q", {})
						.get("vlan-id", {}))
			ip_address = g.get("ip", {}).get("address", {}).get("primary", {}).get("address", "")
			mask = g.get("ip", {}).get("address", {}).get("primary", {}).get("mask", "")
			actual_roas[full_interface] = {
				"interface": full_interface,
				"router_vlan": vlan_id,
				"ip": ip_address,
				"mask": mask
			}
	return actual_roas
#OSPF 
def build_ospf(restconf_state): 
	restconf_state_ospf = restconf_state.get("ospf_restconf")
	get_ospf = (restconf_state_ospf.get("Cisco-IOS-XE-native:router", {})
				.get("Cisco-IOS-XE-ospf:router-ospf", {})
				)
	ospf = get_ospf.get("ospf", {})
	process_id = ospf.get("process-id", [])
	process = normalize_to_list(process_id)
	actual_ospf = {}
	for proc in process: 
		proc_id = proc.get("id", "")
		router_id = proc.get("router-id", "")
		networks = proc.get("network", [])
		network = normalize_to_list(networks)
		actual_ospf[proc_id] = {
            "process_id": proc_id,
            "router_id": router_id,
            "network_list": []
        	}
		for net in network:
			actual_ospf[proc_id]["network_list"].append({
                "subnet": net.get("ip", ""),
                "wildcard": net.get("wildcard", ""),
                "area": net.get("area", "")
            })
	return actual_ospf