from src.utils import (safe_int, normalize_to_list, is_ip_address)

#NTP
def build_ntp(netconf_state):
	native = netconf_state.get("native_netconf", {})
	ntp = native.get("ntp", {})
	if not ntp:
		return {"keys": [], "servers": []}
	actual_ntp = {
		"keys": [],
		"servers": []
	}
	server_lists = ntp.get("server", {}).get("server-list", {})
	server_list = normalize_to_list(server_lists)
	ntp_key_id = ntp.get("authentication-key", {}).get("number", "")
	ntp_trusted = ntp.get("trusted-key", {}).get("number", "")
	for s in server_list:
		ntp_ip = s.get("ip-address")
		server_id = s.get("key", "")
		actual_ntp["servers"].append({
				"server_ip":ntp_ip,
				"server_id": server_id
			})
	actual_ntp["keys"].append({
			"id": ntp_key_id,
			"trusted": str(ntp_key_id) == str(ntp_trusted)
		})
	return actual_ntp
#QOS
def build_qos(netconf_state): 
	native = netconf_state.get("native_netconf", {})
	qos = native.get("policy", {})
	actual_qos = {
		"policies": []
	}
	class_maps = qos.get("class-map", [])
	class_map_list = normalize_to_list(class_maps)
	class_map_lookup = {}
	policy_map = qos.get("policy-map", {})
	policy_map_list = normalize_to_list(policy_map)
	interfaces = native.get("interface", {})
	attachments_lookup = {}
	for c in class_map_list: 
		class_name = c.get("name", "")
		class_map_lookup[class_name] = {
			"match_type": c.get("prematch", ""),
			"name": class_name,
			"protocol": (
					c.get("match", {})
					.get("protocol", {})
					.get("protocols-list", {})
					.get("protocols", "")
				)
		}
	for int_type, int_value in interfaces.items():
		for i_value in normalize_to_list(int_value):
			service_policy = i_value.get("service-policy", {})
			if not service_policy: 
				continue
			interface_name = f"{int_type}{i_value.get('name', '')}"
			input_policy = service_policy.get("input")
			output_policy = service_policy.get("output")
			if input_policy:
				attachments_lookup.setdefault(input_policy, []).append({
						"interface": interface_name,
						"direction": "input"
					})
			if output_policy:
				attachments_lookup.setdefault(output_policy,  []).append({
						"interface": interface_name,
						"direction": "output"
					})
	for p in policy_map_list:
		policy_name = p.get("name", "")
		qos_classes = p.get("class", [])
		qos_class_list = normalize_to_list(qos_classes)

		policy = {
			"policy_name": policy_name,
			"class_maps": [],
			"attachments": attachments_lookup.get(policy_name, [])
		}
		for q in qos_class_list: 
			class_name = q.get("name", "")
			action_list = q.get("action-list", {})
			cm = class_map_lookup.get(class_name, {})
			policy["class_maps"].append({
					"name": class_name,
					"match_type": cm.get("match_type", ""),
					"protocol": cm.get("protocol", ""),
					"action_type": action_list.get("action-type", ""),
					"bandwidth": action_list.get("priority", {}).get("kilo-bits", "")
				})
		if policy["class_maps"] or policy["attachments"]: 
			actual_qos["policies"].append(policy)
	return actual_qos
#HSRP
def build_hsrp(netconf_state): 
	actual_hsrp = []
	native = netconf_state.get("native_netconf", {})
	interfaces = normalize_to_list(native.get("interface", {}))

	for int_type, int_list in interfaces.items():
		interface_type = str(int_type)
		for value in int_list: 
			interface_num = str(value.get("name", "")).strip()
			full_int = f"{interface_type}{interface_num}"
			standby_list = value.get("standby", {}).get("standby-list") or {}
			actual_hsrp.append({
				"interface": full_int,
				"version": value.get("standby", {}).get("version", ""),
				"group": standby_list.get("group-number", ""),
				"vip": standby_list.get("ip", {}).get("address", ""),
				"preempt": "preempt" in standby_list,
				"priority": standby_list.get("priority", 100),
				"router_vlan": (
						value.get("encapsulation", {})
						.get("dot1Q", {})
						.get("vlan-id", "")
					)
			})
	return actual_hsrp
#NAT 
def build_nat(netconf_state):
	actual_nat = []
	nat_interfaces = {
		"inside": [],
		"outside": []
	}
	native = netconf_state.get("native_netconf", {})
	
	nat = native.get("ip", {}).get("nat", {})
	inside = nat.get("inside", {})
	source = inside.get("source", {})
	nat_list = source.get("list", {})
	
	interface_block = nat_list.get("interface", {})
	pat = "overload" in interface_block

	if pat: 
		actual_nat.append({
				"acl": nat_list.get("id", ""),
				"interface": interface_block.get("name", ""),
				"overload": True 
			})
	static = source.get("static", {})
	nat_static = normalize_to_list(static.get("nat-static-transport-list", []))
	if nat_static:
		for n in nat_static:
			actual_nat.append({
					"inside_local": n.get("local-ip", ""),
					"inside_global": n.get("global-ip", "")
				})
	pool = normalize_to_list(nat.get("pool", {}))
	temp_pool = {}
	for p in pool: 
		pool_name = p.get("id", "")
		temp_pool[pool_name] = {
			"pool_name": pool_name,
			"start_ip": p.get("start-address", ""),
			"end_ip": p.get("end-address", ""),
			"mask": p.get("netmask", "")
		}
	nat_pool = (
			nat_list.get("pool-with-vrf", {})
			.get("pool", {})
		)
	if nat_pool:
		name_of_pool = nat_pool.get("name", "")
		pn = temp_pool.get(name_of_pool, {})
		if pn:
			actual_nat.append({
					"acl": nat_list.get("id", ""),
					"pool_name": pn.get("pool_name", ""),
					"start_ip": pn.get("start_ip", ""),
					"end_ip": pn.get("end_ip", ""),
					"mask": pn.get("netmask", "")
				})

	# PT2 NAT INTERFACES
	interfaces = native.get("interface", {})
	for int_type, int_values in interfaces.items():
		for i_value in normalize_to_list(int_values):
			full_interface = f"{int_type}{i_value.get('name', '')}"
			nat = i_value.get("ip", {}).get("nat", {})
			if nat.get("outside") is not None:
				nat_interfaces["outside"].append(full_interface)
			if nat.get("inside") is not None: 
				nat_interfaces["inside"].append(full_interface)
	return actual_nat, nat_interfaces
#DHCP 
def build_dhcp(netconf_state): 
	actual_dhcp = {
		"excluded_addresses": [],
	    "pools": [],
	    "helper": {
	    	"interfaces": []
	    }
	}
	native = netconf_state.get("native_netconf", {})
	dhcp = native.get("ip",  {}).get("dhcp", {})
	excl = dhcp.get("excluded-address", {}).get("low-high-address-list", [])
	for e in normalize_to_list(excl):
		actual_dhcp["excluded_addresses"].append({
				"start_ip": e.get("low-address", ""),
				"end_ip": e.get("high-address", "")
			})
	dhcp_pool = dhcp.get("pool", [])
	for d in normalize_to_list(dhcp_pool):
		lease = d.get("lease", {}).get("lease-value", {})
		dns_list = normalize_to_list(d.get("dns-server", {}).get("dns-server-list", []))
		actual_dhcp["pools"].append({
				"pool_name": d.get("id", ""),
				"lease_days": safe_int(lease.get("days", 1)),
				"lease_hours": safe_int(lease.get("hours", 1)),
				"lease_minutes": safe_int(lease.get("minutes", 10)),
				"default_router": (
						d.get("default-router", {})
						.get("default-router-list", "")
					),
				"dns_ip": dns_list,
				"domain_name": d.get("domain-name", ""),
				"pool_ip": d.get("network", {}).get("primary-network", {}).get("number", ""),
				"pool_mask": d.get("network", {}).get("primary-network", {}).get("mask", ""),
			})
	interfaces = native.get("interface", {})
	for gigabit, gig_values in interfaces.items():
		for g in normalize_to_list(gig_values): 
			full_interface = f"{gigabit}{g.get('name', '')}"
			helper = g.get('ip', {}).get('helper-address', {}).get("address", [])
			for h in normalize_to_list(helper): 
				actual_dhcp["helper"]["interfaces"].append({
						"helper_ip": h,
						"interface_name": full_interface
				})	
	return actual_dhcp 
#SNMP 
def build_snmp_netconf(netconf_state): 
	actual_snmp = {
			"communities": [],
	    	"hosts": [],
	    	"traps": {},
	    	"location": "",
	    	"contact": ""
		}
	native = netconf_state.get("native_netconf", {})
	snmp = native.get("snmp-server", {})
	community = snmp.get("community-config", [])
	if community: 
		for c in normalize_to_list(community): 
			actual_snmp["communities"].append({
					"snmp_name": c.get("name", ""),
					"permission": c.get("permission", "")
				})
	contact = snmp.get("contact", {}).get("#text", "")
	if contact: 
		actual_snmp["contact"] = contact 
	traps = snmp.get("enable", {}).get("enable-choice", {}).get("traps", {})
	if traps: 
		actual_snmp["traps"] = {
				"snmp": bool(traps.get("snmp", {})),
				"syslog": bool(traps.get("syslog", "")),
				"config": bool(traps.get("config", ""))
		}

	hosts = snmp.get("host-config", {}).get("ip-community", {})
	if hosts: 
		for h in normalize_to_list(hosts): 
			actual_snmp["hosts"].append({
					"community_name": h.get("community-or-user", ""),
					"snmp_ip": h.get("ip-address", ""),
					"snmp_version": h.get("version", "")

				})
	location = snmp.get("location", {}).get("#text", "")
	if location: 
		actual_snmp["location"] = location
	return actual_snmp
#SYSLOG
def build_syslog_netconf(netconf_state): 
	actual_syslog = {
			"hosts": [],
			"facility": "",
			"trap_level": "",
			"source_interface": "",
			"timestamps": False
		}
	native = netconf_state.get("native_netconf", {})
	logging = native.get("logging", {})
	facility = logging.get("facility", "")
	if facility: 
		actual_syslog["facility"] = facility
	hosts = logging.get("host", {}).get("ipv4-host-list", [])
	if hosts: 
		for h in normalize_to_list(hosts): 
			actual_syslog["hosts"].append(h.get("ipv4-host", ""))
	source_interface = logging.get("source-interface", {}).get("interface-name", "")
	if source_interface: 
		actual_syslog["source_interface"] = source_interface
	trap_level = logging.get("trap", {}).get("severity", "")
	if trap_level: 
		actual_syslog["trap_level"] = trap_level
	timestamps = (
			native.get("service", {})
			.get("timestamps", {})
			.get("log", {})
			.get("datetime", {})
		)
	if timestamps:
		actual_syslog["timestamps"] = "msec" in timestamps
	return actual_syslog
#CDP
def build_cdp_netconf(netconf_state): 
	actual_cdp = {
		"enabled": False,
		"timer": None,
		"holdtime": None,
		"interfaces": {}
	}
	native = netconf_state.get("native_netconf", {})
	cdp_run = native.get("cdp", {}).get("run", {})
	if cdp_run: 
		actual_cdp["enabled"] = True
	cdp_timer = native.get("cdp", {}).get("timer", {}).get("#text", "")
	if cdp_timer: 
		actual_cdp["timer"] = safe_int(cdp_timer)
	cdp_holdtime = native.get("cdp", {}).get("holdtime", {}).get("#text", "")
	if cdp_holdtime:
		actual_cdp["holdtime"] = safe_int(cdp_holdtime)
	interface = native.get("interface", {})
	for interface_type, int_value in interface.items(): 
		full_interface = f"{interface_type}{int_value.get('name')}"
		cdp_enable = int_value.get("cdp", {}).get("enable", False)
		
		actual_cdp["interfaces"][full_interface] = {
				"enabled": cdp_enable
			}
	return actual_cdp
#STATIC
def build_static(netconf_state): 
	actual_static = []
	native = netconf_state.get("native_netconf", {})
	route = native.get("ip", {}).get("route", {}).get("ip-route-interface-forwarding-list", [])

	for r in normalize_to_list(route): 
		AD = None 
		name = None  
		next_hop = [] 
		exit_interface = None  

		network_address = r.get("prefix", "")
		mask = r.get("mask", {})
		fwd_list = r.get("fwd-list", {})
		fwd = fwd_list.get("fwd", "")

		if is_ip_address(fwd): 
			next_hop = fwd
			AD = safe_int(fwd_list.get("metric", None))
			name = fwd_list.get("name", None)
		else: 
			exit_interface = fwd

		fully_specified = fwd_list.get("interface-next-hop", [])
		if fully_specified: 
			for f in normalize_to_list(fully_specified): 
				next_hop.append(f.get("ip-address"))
				AD = safe_int(f.get("metric")) if f.get("metric") is not None else AD 
				name = f.get("name")

		actual_static.append({
			"AD": AD,
			"network_address": network_address,
			"mask": mask,
			"next_hop": next_hop,
			"exit_interface": exit_interface,
			"name": name 
		})
	return actual_static