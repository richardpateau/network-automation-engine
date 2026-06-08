import pynetbox
from collections import defaultdict
import ipaddress
netbox_url = "http://localhost:8000"
netbox_token = "*****"
def safe_int(value):
	try: 
		return int(value)
	except (TypeError, ValueError): 
		return None
def normalize_to_list(value): 
	if not value: 
		return []
    return [value] if isinstance(value, dict) else data
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
	    "qos": []
			}
		is_switch = device_name.role.slug == "switch"
		is_router = device_name.role.slug == "router"
		ospf_process = {}
		context =  device_name.config_context or {}
		acl_context = context.get("acl", {})
		acl_binding_context = context.get("acl_binding", {})
		ntp_context = context.get("ntp", {})
		for v in all_vlans: 
					config_data[host_ip]["vlans"].append({
							"name": v.name,
							"vlan_id": v.vid,
						})
		for device_interface in device_interfaces.get(device_name.id, []): 
			tags = [t.slug for t in device_interface.tags]
			if (device_interface.type
				device_interface.type.value not in ["virtual", "lag", "bridge"]
				)
				config_data[host_ip]["interfaces"].append({
						"device_ip": host_ip,
						"interface": device_interface.name,
						"should_be_up": device_interface.custom_fields.get("should_be_up", "")
					})

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
								"allowed_vlans": ",".join(str(v["vid"]) for v in device_interface.tagged_vlans)
							})
			if is_router:
				interface_ips = interface_ip.get(device_interface.id, [])
				for interface_ip in interface_ips:
					r_ip = ipaddress.ip_interface(str(interface_ip.address))
					if("roas" in tags):
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
					if ("ospf") in tags and ospf_custom:
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




