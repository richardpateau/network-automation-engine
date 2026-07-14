from src.sot.client import get_netbox
from src.sot.builders import build_index
from src.core.settings import normalize_to_list
def get_netbox():
	nb = get_netbox()
	inventory = []
	config_data = {}

	all_devices = list(nb.dcim.devices.filter(status="active"))
	all_interfaces = list(nb.dcim.interfaces.all())
	all_ip_addresses = list(nb.ipam.ip_addresses.all())
	all_vlans = list(nb.ipam.vlans.all())

	(device_interfaces, 
	interface_ip, 
	subnet_ip, 
	ospf_config_by_interface, 
	vlan_by_id) = build_index(all_interfaces, all_ip_addresses, all_vlans)
	for device_name in all_devices: 
		if not device_name.platform.slug or not device_name.primary_ip:
			continue 
		host_ip = str(device_name.primary_ip.address.split("/")[0])
		inventory.append({
				"device_ip": host_ip,
				"username": "sysadmin",
				"password": "ccna",
				"secret": "ccna",
				"device_type": device_name.platform.slug,
				"name": device_name.name,
				"transport": ""
			})

		config_data[host_ip] = {
	    "vlans": [],
	    "access_ports": [],
	    "trunk_ports": [],
	    "interfaces": [],
	    "roas": [],
	    "ospf": [],
	    "acl": [],
	    "acl_binding": [],
	    "ntp": {
	        "keys": [],
	        "servers": [],
	        "trusted": []
	    },
	    "qos": {
	    	"policies": []
	    },
	    "stp": {
	    	"mode": "",
	    	"vlan_priorities": {}
	    },
	    "hsrp": [],

	    "nat": {
	    	"dynamic": [],
	    	"static": [],
	    	"pat": {},
	    	"interfaces": {
	    		"inside": [],
	    		"outside": []
	    	}
	    }, 
	    "dhcp": {
	    	"excluded_addresses": [],
	    	"pools": [],
	    	"helper": {
	    		"interfaces": []
	    	}
	    },
	    "snmp": {
	    	"communitiess": [],
	    	"hosts": [],
	    	"traps": [],
	    	"location": "",
	    	"contact": ""
		}, 
		"syslog": {
			"hosts": [],
			"facility": "",
			"trap_level": "",
			"source_interface": "",
			"timestamps": False
		},
		"port_security": {
				"interfaces": {}

		},
		"dhcp_snooping": {
				"enabled_vlans": [],
				"interfaces": {},
				"option82": False
		},
		"dai": {
			"arp_inspection": True,
			"enabled_vlans": [],
			"interfaces": {},
			"log_buffer": {}
		}, 
		"cdp": {
			"enabled": False,
			"timer": None,
			"holdtime": None,
			"interfaces": {},
		}, 
		"etherchannel": {
			"enabled": False, 
			"groups": {}
		}, 
		"static_routes": []
			}
		is_switch = device_name.role.slug == "switch"
		is_router = device_name.role.slug == "router"
		ospf_process = {}
		context =  device_name.config_context or {}
		acl_context = context.get("acl", {})
		acl_binding_context = context.get("acl_binding", {})
		ntp_context = context.get("ntp", {})
		qos_context = context.get("qos", {})
		stp_context = context.get("stp", {})
		hsrp_context = context.get("hsrp", {})
		nat_context = context.get("ntp", {})
		dhcp_context = context.get("dhcp", {})
		snmp_context = context.get("snmp", {})
		syslog_context = context.get("syslog", {})
		psecurity_context = context.get("port_security", {})
		snooping_context = context.get("dhcp_snooping", {})
		dai_context = context.get("dai", {})
		cdp_context = context.get("cdp", {})
		ether_context = context.get("etherchannel", {})
		static_context = context.get("static_routes", {})
		for v in all_vlans: 
					config_data[host_ip]["vlans"].append({
							"name": v.name,
							"vlan_id": v.vid,
						})
		for device_interface in device_interfaces.get(device_name.id, []): 
			tags = [t.slug for t in device_interface.tags]
			if (device_interface.type and
				device_interface.type.value not in ["virtual", "lag", "bridge"]):
				config_data[host_ip]["interfaces"].append({
						"device_ip": host_ip,
						"interface": device_interface.name,
						"description": device_interface.description or "",
						"should_be_up": device_interface.custom_fields.get("should_be_up", ""),

						 "stp": {
							        "portfast": device_interface.custom_fields.get("stp_portfast", False),
							        "bpdu_guard": device_interface.custom_fields.get("stp_bpdu_guard", False),
							        "root_guard": device_interface.custom_fields.get("stp_root_guard", False),
							        "loop_guard": device_interface.custom_fields.get("stp_loop_guard", False),
							        "bpdu_filter": device_interface.custom_fields.get("stp_bpdu_filter", False)
							    }
					})
				config_data[host_ip]["stp"]["interfaces"].append({
							"portfast": device_interface.custom_fields.get("stp_portfast", False),
					        "bpdu_guard": device_interface.custom_fields.get("stp_bpdu_guard", False),
					        "root_guard": device_interface.custom_fields.get("stp_root_guard", False),
					        "loop_guard": device_interface.custom_fields.get("stp_loop_guard", False),
					        "bpdu_filter": device_interface.custom_fields.get("stp_bpdu_filter", False)

					})
				for v in device_interface.tagged_vlans:
				    vlan_id = str(v.vid)

				    if vlan_id in config_data[host_ip]["stp"]["vlans"]:
				        config_data[host_ip]["stp"]["vlans"][vlan_id]["interfaces"][device_interface.name] = {
				            "portfast": device_interface.custom_fields.get("stp_portfast", False),
				            "bpdu_guard": device_interface.custom_fields.get("stp_bpdu_guard", False),
				            "root_guard": device_interface.custom_fields.get("stp_root_guard", False),
				            "loop_guard": device_interface.custom_fields.get("stp_loop_guard", False),
				            "bpdu_filter": device_interface.custom_fields.get("stp_bpdu_filter", False)
				        }

			if is_switch: 
				if (device_interface.mode and device_interface.mode.value == "access"
					and device_interface.untagged_vlan):
					config_data[host_ip]["access_ports"].append({
							"device_ip": host_ip,
							"access_interface": device_interface.name,
							"access_vlan": device_interface.untagged_vlan.vid
						})
				if (device_interface.mode and device_interface.mode.value == "tagged" 
					and device_interface.tagged_vlans):
						config_data[host_ip]["trunk_ports"].append({
								"device_ip": host_ip,
								"trunk_interface": device_interface.name,
								"mode": "trunk",
								"allowed_vlans": ",".join(str(v["vid"]) for v in device_interface.tagged_vlans)
							})
			if is_router:
				interface_ips = interface_ip.get(device_interface.id, [])
				for interface_ip in interface_ips:
					r_ip = ipaddress.ip_interface(str(interface_ip.address))
					if "roas" in tags:
						for v in device_interface.tagged_vlans:
							r_ip = ipaddress.ip_interface(str(interface_ip.address))
							config_data[host_ip]["roas"].append({
									"device_ip": host_ip,
									"interface": device_interface.name,
									"router_vlan": v.vid,
									"ip": str(r_ip.ip),
									"mask": str(r_ip.netmask) 
								})
					ospf_custom =  ospf_config_by_interface.get(device_interface.id, {})
					if "ospf" in tags and ospf_custom:
						proc_id = ospf_custom.get("process_id", "")
						area_id = ospf_custom.get("area_id", "")

						if proc_id not in ospf_process: 
							ospf_process[proc_id] = {
								"interfaces": {},
								"router_id": None,
								"auth_type": ospf_custom.get("auth_type", "")
							}
						if device_interface.name not in ospf_process[proc_id]["interfaces"]:
							ospf_process[proc_id]["interfaces"][device_interface.name] = {
									"network_address": str(r_ip.network.network_address),
									"wildcard": str(r_ip.network.hostmask),
									"area": area_id,
									"ospf_interface": device_interface.name,
									"expected_dr": ospf_custom.get("ospf_dr", ""),
									"expected_bdr": ospf_custom.get("ospf_bdr", ""),
									"network_type": ospf_custom.get("network_type",""),
									"ospf_hello": ospf_custom.get("ospf_hello", ""),
									"ospf_dead": ospf_custom.get("ospf_dead", ""),
									"expected_neighbors": set(
											ospf_custom.get("ospf_neighbors", {}).get("expected_neighbors", [])
										),
									"actual_neighbors": set() 
							}
		if ospf_process: 
			ospf_context = device_name.config_context.get("ospf", {})
			for proc_id, proc_data in ospf_process.items():
				interfaces_payload = {}

				for interface_name, interface_data in data["interfaces"].items():
				    interfaces_payload[interface_name] = {
				        "name": interface_name,
				        "subnet": interface_data.get("subnet"),
				        "wildcard": interface_data.get("wildcard"),
				        "area": interface_data.get("area"),
				        "network_type": interface_data.get("network_type"),
				        "hello_interval": interface_data.get("hello_interval"),
				        "dead_interval": interface_data.get("dead_interval"),
				        "expected_dr": interface_data.get("expected_dr"),
				        "expected_bdr": interface_data.get("expected_bdr"),
				        "expected_neighbors": interface_data.get("expected_neighbors", [])
				    }
				config_data["ospf"].append({
				    "device": host_ip,
				    "process_id": int(proc_id),
				    "router_id": context.get(int(proc_id), {}).get("router_id", ""),
				    "auth_type": data.get("auth_type", "none"),
				    "hello_interval": data.get("hello_interval", 10),
				    "dead_interval": data.get("dead_interval", 40),

				    "interfaces": interfaces_payload,

				    "network_list": [
				        {
				            "subnet": i["subnet"],
				            "wildcard": i["wildcard"],
				            "area": i["area"],
				            "interface": i["name"]
				        }
				        for i in interfaces_payload.values()
				    ]
				})
		if acl_context: 
			config_data[host_ip]["acl"] = acl_context
		for binding in acl_binding_context: 
			config_data[host_ip]["acl_binding"].append({
					"interface": binding.get("interface", ""),
					"acl_name": binding.get("acl_name", ""),
					"direction": binding.get("direction", "")
				})
		if ntp_context: 
			ntp_keys = ntp_context.get("keys", [])
			ntp_servers = ntp_context.get("servers", [])

			ntp_key = normalize_to_list(ntp_keys)
			ntp_server = normalize_to_list(ntp_servers)

			config_data[host_ip]["ntp"]["keys"].extend(ntp_key)
			config_data[host_ip]["ntp"]["servers"].extend(ntp_server)
		if qos_context:
			qos_context_list = normalize_to_list(qos_context)
			for qos in qos_context_list: 
				config_data[host_ip]["qos"]["priorities"].append({
						"policy_name": qos.get("policy_name"),
						"attachments": qos.get("attachments", ""),
						"class_maps": qos.get("class_maps", [])
					})
		if stp_context:
			config_data[host_ip]["stp"]["mode"] = stp_context.get("mode", "")
			config_data[host_ip]["stp"]["vlan_priorities"] = (
					stp_context.get("vlan_priorities")
				)
		if hsrp_context:
			for h in hsrp_context: 
				config_data[host_ip]["hsrp"].append({
						"interface": h.get("interface", 2),
						"version": h.get("version", ""),
						"group": h.get("group", ""),
						"vip": h.get("ip", ""),
						"priority": h.get("priority", 100),
						"preempt": h.get("preempt", False),
						"router_vlan": h.get("router_vlan", "")
					})
		if nat_context:
			#list
			nat["dynamic"].extend(
					nat_context.get("dynamic", [])
				)
			nat["static"].extend(
					nat_context.get("static", [])
				)
			#vs dicts 
			if nat_context.get("pat"):
				nat["pat"] = nat_context.get("pat")
			nat["interfaces"]["inside"].extend(
					nat_context.get("interfaces", {}).get("inside", [])
				)
			nat["interfaces"]["outside"].extend(
					nat_context.get("interfaces", {}).get("outside", [])
				)
		if is_router and dhcp_context:
			config_data[host_ip]["dhcp"]["excluded_addresses"].extend(
					dhcp_context.get("excluded_addresses", [])
				)
			config_data[host_ip]["dhcp"]["pools"].extend(
					dhcp_context.get("pools")
				)
			config_data[host_ip]["dhcp"]["helper"]["interfaces"].extend(
					dhcp_context.get("helper", {}).get("interfaces", [])
				)
		if snmp_context:
			config_data[host_ip]["snmp"]["communities"].extend(
					snmp_context.get("communities", [])
				)
			config_data[host_ip]["snmp"]["contact"] = (
					snmp_context.get("contact", "")
				)
			config_data[host_ip]["snmp"]["hosts"].extend(
					snmp_context.get("hosts", [])
				)
			config_data[host_ip]["snmp"]["location"] = (
					snmp_context.get("location", "")
				)
			if snmp_context.get("traps"):
				config_data[host_ip]["snmp"]["traps"] = snmp_context.get("traps", {})
		if syslog_context:
			config_data[host_ip]["syslog"]["facility"] = (
					syslog_context.get("facility", "local7")
				)
			config_data[host_ip]["syslog"]["hosts"].extend(
					syslog_context.get("hosts", [])
				)
			config_data[host_ip]["syslog"]["source_interface"] = (
					syslog_context.get("source_interface", "")
				)
			config_data[host_ip]["syslog"]["timestamps"] = (
					syslog_context.get("timestamps", False)
				)
			config_data[host_ip]["syslog"]["trap_level"] = (
					syslog_context.get("trap_level", "")
				)
		if psecurity_context: 
			interfaces = psecurity_context.get("interfaces", {})
			for interface_name, ps_values in interfaces.items():
				config_data[host_ip]["interfaces"][interface_name] = {
						"enabled": ps_values.get("enabled", ""),
						"mac_addresses": ps_values.get("mac_addresses", []),
						"maximum": ps_values.get("maximum", ""),
						"sticky": ps_values.get("sticky", ""),
						"violation": ps_values.get("violation", "")
					}
		if snooping_context:
			config_data[host_ip]["enabled_vlans"].extend(
					snooping_context.get("enabled_vlans", [])
				)
			config_data[host_ip]["option82"] = (
					snooping_context.get("option82")
				)
			interfaces = snooping_context.get("interfaces", {})
			for interface_name, int_value in interfaces.items():
				config_data[host_ip]["interfaces"][interface_name] = {
					"rate_limit": int_value.get("rate_limit", None),
					"trusted": int_value.get("trusted", False)
				}
		if dai_context: 
			config_data[host_ip]["dai"]["arp_inspection"] = (
					dai_context.get("arp_inspection", "")
				)
			config_data[host_ip]["dai"]["enabled_vlans"].extend(
					dai_context.get("enabled_vlans", [])
				)
			interfaces = dai_context.get("interfaces", {})
			for interface_name, int_value in interfaces.items():
				config_data[host_ip]["dai"]["interfaces"][interface_name] = {
						"rate_limit": int_value.get("rate_limit", None),
						"trusted": int_value.get("trusted", False)
				}
			config_data[host_ip]["dai"]["log_buffer"] = (
					dai_context.get("log_buffer", {})
				)
		if cdp_context: 
			config_data[host_ip]["cdp"]["enabled"] = (
					cdp_context.get("enabled", False)
				)
			config_data[host_ip]["cdp"]["timer"] = (
					cdp_context.get("timer", None)
				)
			config_data[host_ip]["cdp"]["holdtime"] = (
					cdp_context.get("holdtime", None)
				)
			interfaces = cdp_context.get("interfaces", {})
			for interface_name, int_value in interfaces.items():
				config_data[host_ip]["cdp"]["interfaces"][interface_name] = {
						"enabled": int_value.get("enabled", False)
				}
		if ether_context: 
			config_data[host_ip]["etherchannel"]["enabled"] = (
					ether_context.get("enabled", False)
				)
			config_data[host_ip]["etherchannel"]["groups"] = (
						ether_context.get("groups", {})
				)
		if static_context:
			config_data[host_ip]["static_routes"].extend(
					static_context.get("static_routes")
				)
	return inventory, config_data