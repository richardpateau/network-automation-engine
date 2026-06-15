import pynetbox
from collections import defaultdict
import ipaddress
from netmiko import ConnectHandler
from jinja2 import Environment, FileSystemLoader
from ncclient import manager 
import xmltodict
from ciscoconfparse import CiscoConfParse
template_env = Environment(
		loader=FileSystemLoader("/run/media/rich/HDD/Templates/"),
		trim_blocks=True,
		lstrip_blocks=True
	)
DRY_RUN = True
netbox_url = "http://localhost:8000"
netbox_token = "*****"
from enum import Enum
import re 
class OpStatus(Enum): 
	SUCCESS = "SUCCESS"
	FAILED_CONFIG = "FAILED_CONFIG"
	FAILED_VALIDATION = "FAILED_VALIDATION"
	ERROR = "ERROR"
	PENDING = "PENDING"
	CONFIGURED = "CONFIGURED"
	DRY_RUN = "DRY_RUN"
class StepStatus(Enum): 
	SUCCESS = "SUCCESS"
	FAILED = "FAILED" 
	ERROR = "ERROR"
	DRY_RUN = "DRY_RUN"
	SKIPPED = "SKIPPED"
def safe_int(value):
	try: 
		return int(value)
	except (TypeError, ValueError): 
		return None
def normalize_to_list(value):
	if not value:
		return []
	return [value] if isinstance(value, dict) else value
def build_index(interfaces, ip_addresses, vlans):
	device_interfaces = defaultdict(list)
	interface_ip = defaultdict(list)
	subnet_ip = defaultdict(list)
	ospf_config_by_interface = {}
	vlan_by_id = {}

	for interface in interfaces: 
		if interface.device: 
			device_interfaces[interface.device.id].append(interface)
		if interface.custom_fields.get("ospf_enabled"):
			ospf_config_by_interface[interface.id] = {
				"process_id": interface.custom_fields.get("ospf_process_id", 1),
				"area_id": interface.custom_fields.get("ospf_area_id", 0),
				"auth_type": interface.custom_fields.get("ospf_auth_type", ""),
				"ospf_dr": interface.custom_fields.get("ospf_dr", ""),
				"ospf_bdr": interface.custom_fields.get("ospf_bdr", ""),
				"ospf_hello": interface.custom_fields.get("ospf_hello_interval", 10),
				"ospf_dead": interface.custom_fields.get("ospf_dead_interval", 40),
				"network_type": interface.custom_fields.get("ospf_network_type", "")
			}
	for ip in ip_addresses:
		if ip.assigned_object_id:
			interface_ip[ip.assigned_object_id].append(ip)
		ip_object = ipaddress.ip_interface(str(ip.address))
		subnet = str(ip_object.network.network_address)
		subnet_ip[subnet].append(ip)
	for v in vlans:
		vlan_by_id[v.id] = {
			"vlan_id": v.vid,
			"name": v.name,
			"object": v 
		}

	return device_interfaces, interface_ip, subnet_ip, ospf_config_by_interface, vlan_by_id
def get_netbox():
	nb = pynetbox.api(url=netbox_url, token=netbox_token)
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
	    "qos": [],
	    "stp": {
	    	"mode": "",
	    	"root_primary": [],
	    	"root_secondary": []
	    }
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
									"expected_neighbors": set(),
									"actual_neighbors": set() 
							}
						current_subnet = str(r_ip.network.network_address)
						ospf_ips = subnet_ip.get(current_subnet, [])
						for ospf_ip in ospf_ips: 
							ospf_ip_address = str(ospf_ip.address).split('/')[0]
							if str(r_ip.ip) != ospf_ip_address:
								ospf_process[proc_id]["interfaces"][device_interface.name]["expected_neighbors"].add(
										ospf_ip_address
										)
		if ospf_process: 
			ospf_context = device_name.config_context.get("ospf", {})
			for proc_id, proc_data in ospf_process.items():
				interfaces_payload = {}

				for interface_name, interface_data in proc_data["interfaces"].items(): 
					interfaces_payload[interface_name] = {
							"interface_name": interface_name,
							"network_address": interface_data.get("network_address", ""),
							"wildcard": interface_data.get("wildcard", ""),
							"area": interface_data.get("area", ""),
							"network_type": interface_data.get("network_type", ""),
							"ospf_hello": interface_data.get("ospf_hello", ""),
							"ospf_dead": interface_data.get("ospf_dead", ""),
							"expected_dr": interface_data.get("expected_dr", ""),
							"expected_bdr": interface_data.get("expected_bdr", ""),
							"expected_neighbors": interface_data.get("expected_neighbors")
					}
				config_data[host_ip]["ospf"].append({
						"device_ip": host_ip,
						"process_id": safe_int(proc_id),
						"router_id": ospf_context.get(str(proc_id), {}).get("router_id", ""),
						"auth_type": proc_data.get("auth_type", ""),
						"interfaces": interfaces_payload,
						"network_list": [
							{
								"network_address": interface.get("network_address"),
								"wildcard": interface.get("wildcard", ""),
								"area": interface.get("area", ""),
								"interface": interface.get("interface_name")
							}
								for interface in interfaces_payload.values()
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
				config_data[host_ip]["qos"].append({
						"policy_name": qos.get("policy_name"),
						"attachments": qos.get("attachments", ""),
						"class_maps": qos.get("class_maps", [])
					})
		if stp_context:
			config_data[host_ip]["stp"]["mode"] = stp_context.get("mode", "")
			config_data[host_ip]["stp"]["vlan_priorities"] = (
					stp_context.get("vlan_priorities")
				)

	return inventory, config_data
def collect_device_state(conn): 
	device_state = {}
	try: 
		device_state["vlans"] = (
				conn.send_command("show vlan", use_genie=True)
			)
	except Exception: 
		device_state["vlans"] = {}
	
	try: 
		device_state["switchports"] = (
				conn.send_command("show interfaces switchport", use_genie=True)
			)
	except Exception: 
		device_state["switchports"] = {}

	try: 
		device_state["interfaces"] = (
				conn.send_command("show ip interface brief", use_genie=True)
			)
	except Exception: 
		device_state["interfaces"] = {}
	try: 
		device_state["stp"] = conn.send_command(
				"show spanning-tree", use_genie=True
			)
	return device_state
def restconf_get(session, url):
	try: 
		response = session.get(url, timeout=20)
		if response.status_code in [200,201]: 
			return response.json()
		return {}
	except Exception:
		return {}
def collect_restconf_state(device_ip, session, log):
	restconf_state = {}
	try: 
									#Interface
		interface_url = (
				f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/interface"
			)
		restconf_state["interface_restconf"] = restconf_get(
				session,
				interface_url
			)
									#OSPF Config 
		ospf_url = (
				f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/router"
			)
		restconf_state["ospf_restconf"] = restconf_get(
				session,
				ospf_url
			)
								#OSPF Opertational
		ospf_oper_url = (
				f"http://{device_ip}/restconf/dats/Cisco-IOS-XE-ospf_oper:ospf-oper-data"
			)
		restconf_state["ospf_oper_restconf"] = restconf_get(
				session,
				ospf_oper_url
			)
	except Exception as e: 
		log.exception(
				f"Try/Exception Error | {device_ip} | def collect_restconf_state | {e}"
			)
	return restconf_state
def collect_netconf_state(device_ip, username, password, log):
    netconf_state = {}

    try:
        with manager.connect(
            host=device_ip,
            port=830,
            username=username,
            password=password,
            hostkey_verify=False,
            timeout=30
        ) as m:

            filter_xml = """
            <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"/>
            """

            response = m.get_config(
                source="running",
                filter=("subtree", filter_xml)
            )

            if response.ok:
                netconf_data = xmltodict.parse(response.data_xml)

                netconf_state["native_netconf"] = (
                    netconf_data.get("rpc-reply", {})
                          .get("data", {})
                          .get("native", {})
                )
            else:
                netconf_state["native_netconf"] = {}

    except Exception as e:
        log.info(f"NETCONF collection error | {device_ip} | {e}")
        netconf_state["native_netconf"] = {}

    return netconf_state
def build_vlan(device_state): 
	device_state_vlan = device_state.get("vlans", {})
	vlan_data = device_state_vlan.get("vlans", {})
	actual_vlans = {}
	for vlan_id, vlan_values in vlan_data.items():
		actual_vlans[str(vlan_id)] = {
			"name": vlan_values.get("name"),
		}
	return actual_vlans
def build_access(device_state): 
	device_state_access = device_state.get("switchports", {})
	actual_access = {}

	for access_int, access_values in device_state_access.items():
		operational_mode = access_values.get("operational_mode", "").lower()

		if "access" not in operational_mode or "trunk" in operational_mode:
			continue 
		access_interface = access_int.lower().strip()
		access_vlan = str(access_values.get("access_vlan", "")).strip()

		actual_access[access_interface] = {
			"access_interface": access_interface,
			"operational_mode": operational_mode,
			"access_vlan": access_vlan
		}
	return actual_access
def build_trunk(device_state):
	device_state_trunk = device_state.get("switchports", {})
	trunk_data = device_state_trunk.get("trunks", {})
	actual_trunk = {}
	for trunk_int, trunk_values in device_state_trunk.items():
		operational_mode = trunk_values.get("operational_mode", "")

		if "trunk" not in operational_mode:
			continue
		trunk_interface = trunk_int
		allowed_vlans = trunk_values.get("trunk_vlans", "")

		actual_trunk[trunk_interface] = {
			"trunk_interface": trunk_interface,
			"allowed_vlans": allowed_vlans,
			"operational_mode": operational_mode
		}
	return actual_trunk
def build_interface(device_state): 
	device_state_interface = device_state.get("interfaces", {})
	actual_interfaces = {}
	interfaces = device_state_interface.get("interface", {})
	for interface_name, interface_values in interfaces.items():
		if not interfaces:
			continue
		status = interface_values.get("status", "")
		protocol = interface_values.get("protocol", "")
		interface_name = interface_name.lower().strip()
		actual_interfaces[interface_name] = {
				"interface": interface_name,
				"status": status,
				"protocol": protocol,
				"is_up": status == "up" and protocol == "up"
		}
	return actual_interfaces
def build_stp_global1(parse):
    actual_stp = {
        "mode": "",
        "vlan_priorities": {}
    }

    for line in parse.find_objects(r"^spanning-tree"):
        text = line.text.strip()

        if text.startswith("spanning-tree mode"):
            stp["mode"] = text.split()[-1]

        elif text.startswith("spanning-tree vlan") and "priority" in text:
            parts = text.split()

                vlan = safe_int(parts[2])
                priority = safe_int(parts[4])

                stp["vlan_priorities"][vlan] = priority

    return actual_stp
def build_stp_global(device_state):
	stp = device_state.get("stp", {})
	actual_stp = {
		"mode": "",
		"vlan_priorities": {},
	}
	mode = stp.get("rapid_pvst", {}) or ("pvst", {})
	vlans = mode.get("vlans", {})

	stp["mode"] = mode 

	for vlan_id, data in vlans.items():
		vlan = safe_int(vlan_id)

		priority = data.get("bridge", {}).get("priority", "")

		actual_stp["vlan_priorities"][vlan] = priority
	return actual_stp
def build_stp_interfaces(parse):
	act_stp_int  = {}

	for interface in parse.find_objects(r"^interface"):
		name = interface.text.split()[1]
		act_stp_int[name] = {
			"portfast": False,
			"bpdu_guard": False,
			"root_guard": False,
			"loop_guard": False,
			"bpdu_filter": False
		}
		for config in interface.children:
			text = config.text.strip()

			if "portfast" in text:
				act_stp_int[name]["portfast"] = True 
			if "bpduguard" in text: 
				act_stp_int[name]["bpdu_guard"] = True
			if "guard loop" in text: 
				act_stp_int[name]["loop_guard"] = True
			if "guard root" in text:
				act_stp_int[name]["root_guard"] = True
			if "bpdufilter" in text: 
				act_stp_int[name]["bpdu_filter"] = True 
	return act_stp_int
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
def check_vlan(expected_vlans, actual_vlans):
	failures = []

	expected_vlan_id = str(expected_vlans.get("vlan_id", "")).strip()
	expected_name = str(expected_vlans.get("name", "")).strip()

	actual_vlan = actual_vlans.get(expected_vlan_id)

	if not actual_vlan: 
		failures.append(
				f"VLAN {expected_vlan_id} not found on device."
			)
		return False, failures

	actual_name = actual_vlan.get("name", "").strip()

	if expected_name.lower() != actual_name.lower():
		failures.append(
				f"VLAN Mismatch | Expected: {expected_name} | Actual: {actual_name}"
			)
	return len(failures) == 0, failures
def check_access(expected_access, actual_config): 
	failures = []
	exp_interface = str(expected_access.get("access_interface", "")).lower().strip()
	exp_vlan = str(expected_access.get("access_vlan", "")).strip()

	actual = actual_config.get(exp_interface)
	if not actual:
		failures.append(
				f"Missing Access Port | Expected Interface: {exp_interface} | "
				f"Expected VLAN: {exp_vlan}"
			)
		return False, failures

	actual_vlan = str(actual.get("access_vlan", "")).strip()

	if exp_vlan != actual_vlan: 
		failures.append(
				f"Mismath Detected Access Port | Interface: {exp_interface} | VLAN: "
				f"Expected VLAN: {exp_vlan} | Actual VLAN: {actual_vlan}"
			)
		return False, failures

	actual_mode = actual.get("operational_mode").lower().strip()
	if actual_mode != "static access":
		failures.append(
				f"Wrong Interface Operational Mode | Actual: {actual_mode}"
				f" Expected: static access"
			)
	return len(failures) == 0, failures
def check_trunk(expected_trunk, actual_config): 
	failures = []
	exp_interface = expected_trunk.get("trunk_interface", "").lower().strip()
	exp_allowed_vlans = str(expected_trunk.get("allowed_vlans", "")).strip()
	exp_mode = expected_trunk.get("operational_mode", "").lower().strip()

	actual = actual_config.get(exp_interface)
	if not actual: 
		failures.append(
				f"Missing Trunk Interface | Interface: {exp_interface} | "
				f"Expected Allowed VLANs: {exp_allowed_vlans}"
			)
		return False, failures
	actual_vlans = str(actual.get("allowed_vlans", "")).strip()
	actual_mode = actual.get("operational_mode", "").lower().strip()
	if exp_allowed_vlans != actual_vlans: 
		failures.append(
				f"Mismatch Found Trunk Port Allowed VLANs | Interface: {exp_interface}"
				f"Expected: {exp_allowed_vlans} | Actual: {actual_vlans}"
			)
		return False, failures
	if exp_mode != actual_mode: 
		failures.append(
				f"Incorrect Operational Mode | Interface: {exp_interface} | "
				f"Expected: {exp_mode} | Actual: {actual_mode}"
			)
	return len(failures) == 0, failures
def check_interface(expected_int, actual_config): 
	failures = []
	exp_interface = expected_int.get("interface", "").lower().strip()
	exp_is_up = expected_int.get("should_be_up", False)

	actual = actual_config.get(exp_interface)
	if not actual: 
		failures.append(
				f"Missing Interface On Device | Interface: {exp_interface}"
			)
		return False, failures
	actual_is_up = actual.get("is_up", False )
	if exp_is_up != actual_is_up:
		failures.append(
			 f"Mismatched Interface State | Expected Should Be Up/Up: {exp_is_up} "
			 f"Actual Should be Up/Up: {actual_is_up}"
			)

	return len(failures) == 0, failures
def check_stp_global(expected_stp, actual_config): 
	failures = []

	exp_mode = expected_stp.get("mode", "").lower().strip()
	act_mode = actual_config.get("mode", "").lower().strip()

	if exp_mode and exp_mode != act_mode: 
		failures.append(
				f"Mismatched STP Mode | Expected: {exp_mode} | Actual: {act_mode}"
			)
		return False, failures
	exp_vlans = expected_stp.get("vlan_priorities", {})
	act_vlans = actual_config.get("vlan_priorities", {})

	exp_keys = set(exp_vlans.keys())
	act_keys = set(act_vlans.keys())

	if exp_keys != act_keys: 
		missing = exp_keys - act_keys
		extra = act_keys - exp_keys

		if missing:
			failures.append(
					f"Missing VLAN (STP)"
				)
	all_vlans = set(exp_vlans.keys()) | set(act_vlans.keys())

	if exp_vlans.keys() != act_vlans.keys(): 
		failures.append(

			)
def check_roas(expected_roas, actual_config): 
	failures = []
	exp_interface = expected_roas.get("interface", "")
	exp_vlan = str(expected_roas.get("router_vlan", ""))
	exp_ip = expected_roas.get("ip", "")
	exp_mask = expected_roas.get("mask", "")
	exp_ip_mask = f"{exp_ip}/{exp_mask}"
	actual = actual_config.get(exp_interface)
	if not actual: 
		failures.append(
				f"Missing ROAS Interface on Device | Interface: {exp_interface} | VLAN: "
				f"{exp_vlan} | IP: {exp_ip}/{exp_mask}"
			)
		return False, failures
	actual_vlan = str(actual.get("router_vlan", ""))
	if exp_vlan != actual_vlan: 
		failures.append(
				f"ROAS VLAN Mismatch | Expected: {exp_vlan} | Actual: {actual_vlan}"
			)
		return False, failures
	actual_ip = actual.get("ip", "")
	actual_mask = actual.get("mask", "")
	actual_ip_mask = f"{actual_ip}/{actual_mask}"

	if exp_ip_mask != actual_ip_mask: 
		failures.append(
				f"ROAS IP/Mask Mismatch | Interface: {exp_interface} | "
				f"Expected IP/Mask: {exp_ip_mask} | Actual IP/Mask: {actual_ip_mask}"
			)
	return len(failures) == 0, failures
def check_ospf(expected_ospf, actual_config): 
	failures = []
	exp_proc = expected_ospf.get("process_id", "")
	exp_router_id = expected_ospf.get("router_id", "")
	exp_net_list = expected_ospf.get("network_list", [])
	actual = actual_config.get(exp_proc)
	if not actual: 
		failures.append(
				f"Missing Process ID (OSPF) | ID: {exp_proc}"
			)
		return False, failures
	actual_router_id = actual.get("router_id", "")
	if exp_router_id != actual_router_id: 
		failures.append(
				f"(OSPF) Mismatched Router ID | Process: {exp_proc} | "
				f"Expected RID: {exp_router_id} | Actual RID: {actual_router_id}"
			)
		return False, failures
	actual_net_list = actual.get("network_list", [])
	for exp_net in exp_net_list: 
		matched = False 
		exp_subnet = str(exp_net.get("subnet", ""))
		exp_wildcard = str(exp_net.get("wildcard", ""))
		exp_area = str(exp_net.get("area", ""))
		for act_net in actual_net_list: 
			act_subnet = str(act_net.get("subnet", ""))
			act_wildcard = str(act_net.get("wildcard", ""))
			act_area = str(act_net.get("area", ""))

			if (
				exp_subnet == act_subnet and 
				exp_wildcard == act_wildcard and 
				exp_area == act_area
				):
				matched = True
			if not matched:
				failures.append(
					f"Expected OSPF Network Not Found | "
					f"Nework Address: {exp_subnet} | "
					f"Wildcard: {exp_wildcard} | "
					f"Area: {exp_area}"
				)
	return len(failures) == 0, failures
def check_ntp(expected_ntp, actual_config):
	failures = []
	exp_ntp = expected_ntp.get("ntp", {})
	exp_keys = exp_ntp.get("keys", [])
	exp_servers = exp_ntp.get("servers", [])
	act_keys = actual_config.get("keys", [])
	act_servers = actual_config.get("servers", [])

	for exp_key in exp_keys:
		exp_id = exp_key.get("id", "")
		exp_trusted = exp_key.get("trusted", False)
		matched = False 
		for act_key in act_keys: 
			act_id = act_key.get("id", "")
			act_trusted = act_key.get("trusted", "")

			if exp_id == act_id: 
				matched = True 

				if exp_trusted != act_trusted:
					failures.append(
							f"NTP Trusted (T/F) Key Mismatch | Key: {exp_id} | "
							f"Expected: {exp_trusted} | Actual: {act_trusted}"
						)
		if not matched: 
			failures.append(
					"Missing Key ID | Key ID: {exp_id}"
				)
	for exp_server in exp_servers: 
		exp_ip = exp_server.get("ip", "")
		exp_id = exp_server.get("key_id", "")
		for act_server in act_servers:
			act_ip = act_server.get("server_ip", "")
			act_id = act_server.get("server_id", "")
			matched = False 

			if exp_key == act_ip: 
				matched = True 

				if exp_id != act_id: 
					failures.append(
							f"(NTP) Mismatched Server Key ID | Server IP: {exp_ip} | "
							f"Expected ID: {exp_id} | Actual ID: {act_id}" 
						)
		if not matched: 
			failures.append(
					f"Missing NTP Server on Device | Expected IP: {exp_ip} | "
					f"Actual: {act_ip}"
				)
	return len(failures) == 0, failures
def check_qos(expected_qos, actual_config): 
	failures = []
	exp_policies =normalize_to_list(expected_qos.get("policies", []))
	act_policies =normalize_to_list(actual_config.get("policies", []))

	act_lookup = {
		p.get("policy_name"): p
		for p in act_policies
	}
	for exp_policy in exp_policies: 
		name = exp_policy.get("policy_name", "")
		act_policy = act_lookup.get(name)

		if not act_policy: 
			failures.append(
					f"Missing QOS Policy | Expected: {name}"
				)
			continue 
		exp_classes = exp_policy.get("class_maps", [])
		act_classes = act_policy.get("class_maps", [])
		for exp_class in exp_classes: 
			matched = False
			for act_class in act_classes:
				if (
					exp_class.get("name", "") == act_class.get("name", "") and 
					exp_class.get("action_type", "") == act_class.get("action_type", "") and 
					exp_class.get("match_type", "") == act_class.get("match_type", "") and 
					exp_class.get("bandwidth", "") == act_class.get("bandwidth", "") and 
					exp_class.get("protocol", "") == act_class.get("protocol", "")
					):
					matched = True 
			if not matched: 
				failures.append(
						f"Expected Class Map Missing From Policy | Policy: {name} | "
						f"Class Config: {exp_class}"
					)
			exp_attached = normalize_to_list(exp_policy.get("attachments", []))
			act_attached = normalize_to_list(act_policy.get("attachments", []))
			for exp_attach in exp_attached: 
				matched = False 
				for act_attach in act_attached: 
					if (
						exp_attach.get("interface") == act_attach.get("interface") and 
						exp_attach.get("direction") == act_attach.get("direction")
						):
						matched = True 
				if not matched: 
					failures.append(
							f"Expected Policy Not Assigned to Interface | Policy: {name} | "
							f"Interface: {exp_attach.get("interface")} | "
							f"Direction: {exp_attach.get("direction")}"
						)
	return len(failures) == 0, failures 
def configure_vlan(conn, device_ip, vlan_data, log): 
	vlan_id = vlan_data.get("vlan_id", "")
	name = vlan_data.get("name", "")

	try: 
		template = template_env.get_template("vlan.j2")
		commands = template.render(
				vlan_id=vlan_id,
				name=name
			).splitlines()

		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (f"[DRY_RUN] Would Configure VLANs | "
                			f"VLAN: {vlan_id} | Name: {name}"
                	)
			}

		conn.send_config_set(commands)

		log.info(
            "vlan_config",
            extra={
                "device_ip": device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "status": StepStatus.SUCCESS.value,
                "vlan_id": vlan_id,
                "name": name,
                "message": (f"VLAN configured successfully | "
                			f"VLAN: {vlan_id} | Name: {name}"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (f"VLAN configured successfully | "
                			f"VLAN: {vlan_id} | Name: {name}"
                	)
			}
	except Exception as e: 
		log.info(
            "vlan_config",
            extra={
                "device_ip": device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "status": StepStatus.ERROR.value,
                "vlan_id": vlan_id,
                "name": name,
                "message": (f"Try/Exception Error | VLAN Configuration | "
                			f"VLAN: {vlan_id} | Name: {name} | Error: {e}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(f"Try/Exception Error | VLAN Configuration | "
                		   f"VLAN: {vlan_id} | Name: {name} | Error: {e}"
                	),
				"error": str(e)
			}
def configure_access(conn, device_ip, access_data, log): 
	access_interface = access_data.get("access_interface", "")
	access_vlan = access_data.get("access_vlan", "")

	try: 
		template = template_env.get_template("access_port.j2")
		commands = template.render(
				access_interface=access_interface,
				access_vlan=access_vlan
			).splitlines()
		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure Access Port | Interface: {access_interface} | "
						f"VLAN: {access_vlan}"
                	)
			}
		conn.send_config_set(commands)

		log.info(
            "access_config",
            extra={
                "device_ip": device_ip,
                "component": "access_port_automation",
                "event_type": "access_config",
                "status": StepStatus.SUCCESS.value,
                "vlan_id": access_vlan,
 				"interface": access_interface,
                "message": (f"Access Port configured successfully | "
                			f"Interface: {access_interface} | VLAN: {access_vlan}"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary":(f"Access Port configured successfully | "
                		   f"Interface: {access_interface} | VLAN: {access_vlan}"
                	)
			}
	except Exception as e: 
		log.info(
            "access_config",
            extra={
                "device_ip": device_ip,
                "component": "access_port_automation",
                "event_type": "access_config",
                "status": StepStatus.ERROR.value,
                "vlan_id": access_vlan,
 				"interface": access_interface,
                "message": (f"Try/Exception Error | Access Port Configuration | "
                			f"Interface: {access_interface} | VLAN: {access_vlan}"
                			f" | Error: {e}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(f"Try/Exception Error | Access Port Configuration | "
                			f"Interface: {access_interface} | VLAN: {access_vlan}"
                			f" | Error: {e}]"
                	),
				"error": str(e)
			}
def configure_trunk(conn, device_ip, trunk_data, log): 
	trunk_interface = trunk_data.get("trunk_interface", "")
	allowed_vlans = trunk_data.get("allowed_vlans", "")

	try: 
		template = template_env.get_template("trunk_ports.j2")
		commands = template.render(
				trunk_interface=trunk_interface,
				allowed_vlans=allowed_vlans
			).splitlines()

		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (f"[DRY_RUN] Would Configure Trunk Interface | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans}"
                	)
			}

		conn.send_config_set(commands)

		log.info(
            "trunk_config",
            extra={
                "device_ip": device_ip,
                "component": "trunk_automation",
                "event_type": "trunk_config",
                "status": StepStatus.SUCCESS.value,
                "trunk_interface": trunk_interface,
                "allowed_vlans": allowed_vlans,
                "message": (f"Trunk Interface configured successfully | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans}"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (f"Trunk Interface configured successfully | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans}"
                	)
			}
	except Exception as e: 
		log.info(
            "trunk_config",
            extra={
                "device_ip": device_ip,
                "component": "trunk_automation",
                "event_type": "trunk_config",
                "status": StepStatus.ERROR.value,
                "trunk_interface": trunk_interface,
                "allowed_vlans": allowed_vlans,
                "message": (f"Try/Exception Error | Trunk Interface Configuration | "
                			f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans} | Error: {e}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(f"Try/Exception Error | VLAN Configuration | "
                		   f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans} | Error: {e}"
                	),
				"error": str(e)
			}
def configure_interfaces(conn, device_ip, interface_data, log): 
	interface = interface_data.get("interface", "")
	description = interface_data.get("description", "")
	should_be_up = interface_data.get("should_be_up", False)
	if should_be_up: 
		state = "no shutdown"
	else: 
		state = "shutdown"
	try: 
		template = template_env.get_template("interface.j2")
		commands = template.render(
				interface=interface,
				description=description,
				state=state
			).splitlines()
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (f"[DRY_RUN] Would Change Interface Status | Interface: {interface} "
							f"| Should Be Up/Up: {should_be_up}" 
                	)
			}

		conn.send_config_set(commands)

		log.info(
            "interface_config",
            extra={
                "device_ip": device_ip,
                "component": "interface_automation",
                "event_type": "interface_config",
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "should_be_up": should_be_up,
                "message": (f"Interface Status Successfully changed | Interface: {interface} "
						    f"| Should Be Up/Up: {should_be_up}" 
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (f"Interface Status Successfully Changed | Interface: {interface} "
						    f"| Should Be Up/Up: {should_be_up}" 
                	)
			}
	except Exception as e: 
		log.info(
            "interface_config",
            extra={
                "device_ip": device_ip,
                "component": "interface_automation",
                "event_type": "interface_config",
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "should_be_up": should_be_up,
                "message": (f"Try/Exception Error | Interface Status Configuration | "
                			f"Interface: {interface} | "
                			f"Should Be Up/Up: {should_be_up} | Error: {e}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(f"Try/Exception Error | Interface Status Configuration | "
                		   f"Interface: {interface} | "
                			f"Should Be Up/Up: {should_be_up} | Error: {e}"
                	),
				"error": str(e)
			}
def configure_roas(session, device_ip, roas_data, log): 
	interface = roas_data.get("interface", "")
	router_vlan = roas_data.get("router_vlan", "")
	ip = roas_data.get("ip", "")
	mask = roas_data.get("mask", "")
	new_int = re.search(r'[\d./]+$', interface).group()

	try: 
		template = template_env.get_template("restconf_roas.j2")
		commands = template.render(
				new_interface=new_int,
				router_vlan=router_vlan,
				ip=ip,
				mask=mask
			)
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure ROAS | "
						f"Interface: {interface} | VLAN: {router_vlan} | "
						f"IP: {ip}/{mask} | Transport: RESTCONF"
				)
			}
		response = session.patch(
				url=f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/interface",
				data=commands
			)
		if response.status_code not in [200,201,204]: 
			return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": (f"ROAS config failed {response.text}"
                		    f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask}"
                	),
                "error": response.text
            }

		log.info(
            "roas_config",
            extra={
                "device_ip": device_ip,
                "component": "roas_automation",
                "event_type": "roas_config",
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "vlan_id": router_vlan,
                "ip": f"{ip}/{mask}",
                "message": (f"ROAS Successfully Configured | "
						    f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask} | Transport: RESTCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (f"ROAS Successfully Configured | "
						    f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask} | Transport: RESTCONF"
                	)
			}
	except Exception as e: 
		log.info(
            "roas_config",
            extra={
                "device_ip": device_ip,
                "component": "roas_automation",
                "event_type": "roas_config",
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "vlan_id": router_vlan,
                "ip": f"{ip}/{mask}",
                "message": (f"Try/Exception Error | ROAS Configuration | "
                			f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask} | Transport: RESTCONF"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(f"Try/Exception Error | ROAS Configuration | "
                			f"Interface: {interface} | VLAN: {router_vlan} | "
						    f"IP: {ip}/{mask} | Transport: RESTCONF"
                	),
				"error": str(e)
			}
def configure_ospf(session, device_ip, ospf_data, log): 
	process_id = ospf_data.get("process_id", "")
	router_id = ospf_data.get("router_id", "")
	network_list = ospf_data.get("network_list", [])
	network = ",".join(
			f"{n['subnet']}/{n['wildcard']} area {n['area']}"
			for n in network_list
		)
	try: 
		template = template_env.get_template("OSPF.j2")
		commands = template.render(
				process_id=process_id,
				router_id=router_id,
				network_list=network_list
			)
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure OSPF | "
						f"Process ID: {process_id} | "
						f"RID: {router_id} | Networks: {network} | Transport: RESTCONF"
				)
			}
		response = session.patch( 
				url = f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/router",
				data=commands
			)
		if response.status_code not in [200,201,204]: 
			return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": (
                			f"OSPF config failed {response.text}"
                		    f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: RESTCONF"
                	),
                "error": response.text
            }

		log.info(
            "ospf_config",
            extra={
                "device_ip": device_ip,
                "component": "ospf_automation",
                "event_type": "ospf_config",
                "status": StepStatus.SUCCESS.value,
                "process_id": process_id,
                "RID": router_id,
                "networks": network,
                "message": (
                			f"OSPF Successfully Configured | "
						    f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: RESTCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"OSPF Successfully Configured | "
						    f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: RESTCONF"
                	)
			}
	except Exception as e: 
		log.info(
            "ospf_config",
            extra={
                "device_ip": device_ip,
                "component": "ospf_automation",
                "event_type": "ospf_config",
                "status": StepStatus.ERROR.value,
                "process_id": process_id,
                "RID": router_id,
                "networks": network,
                "message": (f"Try/Exception Error | OSPF Configuration | "
                			f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: RESTCONF"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | OSPF Configuration | "
                			f"Process ID: {process_id} | "
						    f"RID: {router_id} | Networks: {network} | Transport: RESTCONF"
                	),
				"error": str(e)
			}
def configure_ntp(session, device_ip, ntp_data, log): 
	ntp = ntp_data.get("ntp", {})
	ntp_keys = ntp.get("keys", [])
	ntp_servers = ntp.get("servers", [])

	key_log = ",".join(
		f"ID: {n.get('id', '')} | Trusted: {n.get('trusted', False)}"
		for n in ntp_keys
		)
	server_log = " | ".join(
		f"Server IP: {n['ip']} | Key ID: {n['key_id']}"
		for n in ntp_servers
		)
	try: 
		template = template_env.get_template("NTP.j2")
		commands = template.render(
				ntp_keys=ntp_keys,
				ntp_servers=ntp_servers
			)
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure NTP | "
						f"{key_log}"
						f"| {server_log}"
				)
			}
		response = session.edit_config(
				target="running",
				config=commands
			)
		if not response.ok: 
			return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": (
                		f"NTP Configuration Failed | "
                		f"{key_log}"
                		f"| {server_log} | Transport: NETCONF"
                	),
                "error": str(response)
            }
		
		log.info(
			"ntp_config",
            extra={
                "device_ip": device_ip,
                "component": "ntp_automation",
                "event_type": "ntp_config",
                "status": StepStatus.SUCCESS.value,
                "key_config": key_log,
                "server_config": server_log,
                "message": (
                		f"NTP Configuration Successful | "
                		f"{key_log} | "
                		f"{server_log} | Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"NTP Configuration Successful | "
                		    f"{key_log} | "
                		    f"{server_log} | Transport: NETCONF"
                	)
			}
	
	except Exception as e: 
		log.info(
            "ntp_config",
            extra={
                "device_ip": device_ip,
                "component": "ntp_automation",
                "event_type": "ntp_config",
                "status": StepStatus.ERROR.value,
                "key_config": key_log,
                "server_config": server_log,
                "message": (f"Try/Exception Error | NTP Configuration | "
                			f"{key_log} | "
                		    f"{server_log} | Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | NTP Configuration | "
                			f"{key_log} | "
                		    f"{server_log} | Transport: NETCONF"
                	),
				"error": str(e)
			}
def configure_qos(session, device_ip, qos_data, log):
	qos = qos_data.get("qos", {})
	policy_name = qos.get("policy_name", "")
	attachments = qos.get("attachments", [])
	class_maps = qos.get("class_maps", [])
	attachment_log = " | ".join(
			f"{a.get('interface')} {a.get('direction')}"
			for a in attachments
		)
	class_map_log = " | ".join(
			f"{c.get('name')} {c.get('protocol')} {c.get('action_type')} {c.get('bandwidth')}"
			for c in class_maps
		)
	try: 
		policy_template = template_env.get_template("QOS_NETCONF.j2")
		policy_commands = policy_template.render(
				class_maps=class_maps,
				policy_name=policy_name
			)
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure QOS | "
						f"Policy: {policy_name} | "
						f"Class Map: {class_map_log} | Config: {attachment_log} | "
						F"Transport: NETCONF"
				)
			}
		policy_response = session.edit_config(
					target="running",
					config=policy_commands
				)
		
		if not policy_response.ok:
			return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": (
                		f"QOS Configuration Failed | "
                		f"Policy: {policy_name} | "
						f"Class Map: {class_map_log} | Transport: NETCONF"
                	),
                "error": str(policy_response)
            }
		interface_template = template_env.get_template("INTERFACE_NETCONF.j2")
		for a in attachments:
			interface = a.get("interface", "")
			direction = a.get("direction", "")
			interface_type = re.split(r'\d', interface, maxsplit=1)[0]
			attachment_commands = interface_template.render(
					interface_type=interface_type,
					interface=interface,
					direction=direction,
					policy_name=policy_name
				)
			interface_response = session.edit_config(
					target="running",
					config=attachment_commands
				)
			if not interface_response.ok:
				return {
	                "status": OpStatus.CONFIG_FAILED.value,
	                "summary": (
	                		f"Interface (QOS) Configuration Failed | "
	                		f"Policy: {policy_name} | "
	                		f"Config: {attachment_log} | Transport: NETCONF"
	                	),
	                "error": str(interface_response)
	            }
		log.info(
			"qos_config",
            extra={
                "device_ip": device_ip,
                "component": "qos_automation",
                "event_type": "qos_config",
                "status": StepStatus.SUCCESS.value,
                "policy_name": policy_name,
                "class_maps": class_map_log,
                "attachments": attachment_log,
                "message": (
		                		f"QOS Configuration Successful | "
		                		f"Policy: {policy_name} | "
								f"Class Map: {class_map_log} | Config: {attachment_log} | "
								f"Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
						 		f"QOS Configuration Successful | "
	                		    f"Policy: {policy_name} | "
								f"Class Map: {class_map_log} | Config: {attachment_log} | "
								f"Transport: NETCONF"
                	)
			}

	except Exception as e: 
		log.info(
            "qos_config",
            extra={
                "device_ip": device_ip,
                "component": "qos_automation",
                "event_type": "qos_config",
                "status": StepStatus.ERROR.value,
                "policy_name": policy_name,
                "class_maps": class_map_log,
                "attachments": attachment_log,
                "error": str(e),
                "message": (f"Try/Exception Error | QOS Configuration | "
                			f"Policy: {policy_name} | "
							f"Class Map: {class_map_log} | Config: {attachment_log} | "
							f"Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | QOS Configuration | "
                			f"Policy: {policy_name} | "
							f"Class Map: {class_map_log} | Transport: NETCONF"
                	),
				"error": str(e)
			}
		