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
				"transport": 
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
	    	"contact"
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
			"arp_inspection": true,
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
	except Exception:
		device_state["stp"] = {}
	try: device_state["running_config"] = conn.send_command(
			"show running-config"
		)
	except Exception: 
		device_state["running_config"] = {}
	try: 
		device_state["syslog"] = (
				conn.send_command("show logging", use_genie=True)
			)
	except Exception: 
		device_state["syslog"] = {}
	try: 
		device_state["cdp"] = (
				conn.send_command("show cdp")
			)
	except Exception:
		device_state["cdp"] = {}
	try: 
		device_state["cdp_interface"] = (
				conn.send_command("show cdp interface")
			)
	except Exception:
		device_state["cdp_interface"] = {}
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
def build_stp_global(device_state):
	stp = device_state.get("stp", {})
	actual_stp = {
		"mode": "",
		"vlan_priorities": {},
	}
	if "rapid_pvst" in stp:
		mode = "rapid_pvst"
		vlans = stp.get("rapid_pvst", {}).get("vlans", {})
	elif "pvst" in stp:
		mode = "pvst"
		vlans = stp.get("pvst", {}).get("vlans", {})
	else: 
		mode = "unknown"
		vlans = {}
	actual_stp["mode"] = mode 
	for vlan_id, data in vlans.items():
		vlan = safe_int(vlan_id)

		priority = data.get("bridge", {}).get("configured_bridge_priority", 32768)

		actual_stp["vlan_priorities"][vlan] = priority
	return actual_stp
def build_stp_interfaces(running_config):
	parse = CiscoConfParse(running_config.splitlines())
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
def build_snmp_nc(netconf_state): 
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
def build_snmp_netmiko(device_state):
	parse = CiscoConfParse(device_state.splitlines())
	actual_snmp = {
			"communities": [],
	    	"hosts": [],
	    	"traps": {},
	    	"location": "",
	    	"contact": ""
		}

	for s in parse.find_objects(r"^snmp-server community"):
		parts = s.text.split()

		actual_snmp["communities"].append({
				"snmp_name": parts[2],
				"permission": parts[3].lower()
			})
	for s in parse.find_objects(r"^snmp-server location"):
		parts = s.text.split()

		actual_snmp["location"] = " ".join(parts[2:])
	for s in parse.find_objects(r"^snmp-server contact"):
		parts = s.text.split()

		actual_snmp["contact"] = " ".join(parts[2:])
	for s in parse.find_objects(r"^snmp-server enable traps"):
		line = s.text.lower()

		if " enable traps snmp" in line: 
			actual_snmp["traps"]["snmp"] = True 
		if " enable traps syslog" in line: 
			actual_snmp["traps"]["syslog"] = True 
	for s in parse.find_objects(r"^snmp-server host"):
		parts = s.text.split()
		if len(parts) >= 6: 
			actual_snmp["hosts"].append({
					"snmp_ip": parts[2],
					"snmp_version": parts[4],
					"snmp_name": parts[5]
				})
	return actual_snmp
def build_syslog_nc(netconf_state): 
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
def build_syslog_netmiko(running_config, device_state): 
	actual_syslog = {
			"hosts": [],
			"trap_level": "",
			"source_interface": "",
			"timestamps": False
		}
	state_logging = device_state.get("syslog", {})
	logging = state_logging.get("logging", {})
	parse = CiscoConfParse(running_config.splitlines())
	for p in parse.find_objects(r"^service timestamps"):
		if "log datetime msec" in p.text: 
			actual_syslog["timestamps"] = True 
	trap_level = logging.get("trap", {}).get("level", "")
	if trap_level: 
		actual_syslog["trap_level"] = trap_level
	logging_to = logging.get("trap", {}).get("logging_to", {})
	if logging_to: 
		for ip in logging_to:
			actual_syslog["hosts"].append(ip)
	source_interface = logging.get("trap", {}).get("logging_source_interface", {})
	if source_interface: 
		for interface in source_interface:
			actual_syslog["source_interface"] = interface
	return actual_syslog
def build_port_security(running_config): 
	parse = CiscoConfParse(running_config.splitlines())

	actual_psecurity = {
			"interfaces": {}
	}
	for p in parse.find_objects(r"^interface"):
		interface_name = p.text.split()[1]
		ps_config = actual_psecurity["interfaces"].setdefault(interface_name, {
					"enabled": False,
					"maximum": None,
					"violation": "",
					"sticky": False,
					"mac_addresses": []
			})
		for child in p.children:
			full_confg = child.text.strip()
			config = child.text.strip().split()
			if "switchport port-security" == full_confg: 
				ps_config["enabled"] = True 
			if "port-security maximum" in full_confg: 
				ps_config["maximum"] = safe_int(config[-1])
			if "port-security violation" in full_confg: 
				ps_config["violation"] = config[-1]
			if "port-security mac-address sticky" in full_confg:
				ps_config["sticky"] = True
			if "switchport port-security mac-address" in full_confg: 
				ps_config["mac_addresses"].append(config[-1])
	return actual_psecurity
def build_snooping(running_config): 
	actual_snooping = {
				"enabled_vlans": [],
				"interfaces": {},
				"option82": False
		}
	parse = CiscoConfParse(running_config.splitlines())
	for p in parse.find_objects(r"^ip dhcp snooping"):
			full_config = p.text.strip()
			config = p.text.split()
			if "snooping vlan" in full_config:
				vlan = config[-1].split(",")
				vlan_list = [safe_int(v) for v in vlan if v.isdigit()]
				actual_snooping["enabled_vlans"] = vlan_list
			if "no ip dhcp snooping information" in full_confg: 
				actual_snooping["option82"] = False  
	for p in find_objects(r"^interface"): 
		part = p.text.split()
		interface_name = part[-1]

		for child in p.children: 
			full_config = child.text.strip()
			config = child.text.split()

			if "snooping limit rate" in full_config:
				actual_snooping["interfaces"][interface_name] = {
						"rate_limit": config[-1]
				}
			if "snooping trust" in full_config:
				actual_snooping["interfaces"][interface_name] = {
						"trusted": True
				}
	return actual_snooping
def build_dai(running_config):
	parse = CiscoConfParse(running_config.splitlines())
	actual_dai = {
		"arp_inspection": "",
		"enabled_vlans": [],
		"interfaces": {},
		"log_buffer": {}
	}
	for p in parse.find_objects(r"^ip arp inspection"): 
		full_config = p.text.strip()
		config = p.text.strip().split()
		actual_dai["arp_inspection"] = True
		if "inspection vlan" in full_config: 
			vlans = config[-1].split(",")
			vlan_list = [safe_int(v) for v in vlans if v.isdigit()]
			actual_dai["enabled_vlans"] = vlan_list
		if "inspection log-buffer" in full_config:
			actual_dai["log_buffer"] = {
				"enabled": True,
				"entries": safe_int(config[-1])
			}
	for i in parse.find_objects(r"^interface"): 
		part = i.text.strip().split()
		interface_name = part[-1]

		intf = actual_dai["interfaces"].setdefault(
				interface_name,
				{
					"trusted": False,
					"rate_limit": None
				}
			)
		for c in i.children: 
			full_config = c.text.strip()
			config = c.text.strip().split()
			if "inspection trust" in full_config:
				intf["trusted"] = True
			if "inspection limit rate" in full_config:
				intf["rate_limit"] = safe_int(config[-1])
	return actual_dai
def build_cdp_nc(netconf_state): 
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
def build_cdp_netimko(run_global, run_interface):
	actual_cdp = {
		"enabled": False,
		"timer": None,
		"holdtime": None,
		"interfaces": {}
	}
	parse = CiscoConfParse(run_global.splitlines())
	for p in parse.find_objects(r"^Global CDP information:"):
		for c in p.children: 
			config = c.text.strip().split()
			full_config = c.text.strip()

			if "Sending CDP packets every" in full_config: 
				actual_cdp["timer"] = safe_int(config[-2])
			if "Sending a holdtime value" in full_config: 
				actual_cdp["holdtime"] = safe_int(config[-2])
			if "enabled" in full_config: 
				actual_cdp["enabled"] = True 
	parse_2 = CiscoConfParse(run_interface.splitlines())
	for p in parse_2.find_objects(r"^\S+"):
		config = p.text.strip().split()
		interface_name = config[0]

		actual_cdp["interfaces"][interface_name] = {
			"enabled": True 
		}
	return actual_cdp
def build_etherchannel(running_config): 
	parse = CiscoConfParse(running_config.splitlines())
	actual_ether = {
		"enabled": False,
		"groups": {}
	}

	for p in parse.find_objects(r"^interface"): 
		config = p.text.strip().split()
		interface_name = config[-1]
		full_config = p.text.strip()
		for c in p.children:
			full_config = c.text.strip()
			config = c.text.strip().split()

			if "channel-group" in full_config: 
				group = safe_int(config[-3])
				mode = config[-1]
				group_entry = actual_ether["groups"].setdefault(group,{
						"mode": mode,
						"interfaces": [], 
						"description": None,
						"switchport_mode": None,
						"type": None, 
						"enabled": True 
					})
				group_entry["interfaces"].append(interface_name)

				if mode in ["active", "passive"]: 
					group_entry["type"] = "lacp"
				elif mode in ["desirable", "auto"]: 
					group_entry["type"] = "pagp"
				else: 
					group_entry["type"] = "static"
	for p in parse.find_objects(r"^interface Port-channel"):
		config = p.text.strip().split()
		group = safe_int(config[-1][12:])
		group_entry = actual_ether["groups"].get(group)
		if not group_entry:
			continue
		for c in p.children:
			full_config = c.text.strip().lower()
			config = c.text.strip().split()
			if full_config.startswith("description"): 
				group_entry["description"] = " ".join(config[1:])
			elif full_config.startswith("switchport mode"): 
				group_entry["switchport_mode"] = config[-1]
	return actual_ether
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
					f"(STP) Missing VLANs | Expected: {exp_keys} | Actual: {act_keys}"
				)
		if extra:
			failures.append(
					f"(STP) Unexpected VLANs | Expected: {exp_keys} | Actual: {act_keys}"
				)
		return False, failures
	for vlan in exp_keys: 
		exp_priority = exp_vlans.get(vlan)
		act_priority = act_vlans.get(vlan)
		if exp_priority != act_priority:
			failures.append(
					f"(STP) Mismatched Bridge Priority | "
					f"VLAN: {vlan_id} | "
					f"Expected: {exp_priority} | "
					f"Actual: {act_priority}"
				)
	return len(failures) == 0, failures
def check_stp_interfaces(expected_int, actual_config):
	failures = []
	exp_int = expected_int.get("interface", "")
	exp_stp = expected_int.get("stp", {})
	actual = actual_config.get(exp_int)
	if not actual: 
		failures.append(
				f"(STP) Missing Interface | Interface: {exp_int}"
			)
		return False, failures
	for mode, exp_values in exp_stp.items():
		act_values = actual.get(mode, False )

		if exp_values != act_values:
			failures.append(
					f"(STP) Mismatched STP Mode | Interface: {exp_int} | "
					f"Feature: {mode} | Expected: {exp_values} | Actual: {act_values}"
				)
	return len(failures) == 0, failures
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
	exp_ospf
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
	exp_policies = normalize_to_list(expected_qos.get("policies", []))
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
def check_hsrp(expected_hsrp, actual_config): 
	failures = []
	actual_hsrp = {
		(a.get("interface"), a.get("router_vlan"), a.get("group")): a 
		for a in actual_config
	}
	exp_keys = {
		(	e.get("interface", ""),
			e.get("router_vlan", ""),
			e.get("group", "")

			) for e in expected_hsrp
	}
	act_keys = set(actual_hsrp.keys())
	extra = act_keys - exp_keys
	if extra:
		for interface, vlan, group in extra:
			failures.append(
	        f"(HSRP) Unexpected Configuration | "
	        f"Interface: {interface} | VLAN: {vlan} | Group: {group}"
    	)

	for exp in expected_hsrp:
		exp_key = (
				exp.get("interface", ""),
				exp.get("router_vlan", ""),
				exp.get("group", "")
			)
		actual = actual_hsrp.get(exp_key)

		if not actual: 	
			failures.append(	
					f"(HSRP) Missing Configuration | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
				)
			continue 
		if exp.get("vip") != actual.get("vip"):
			failures.append(
					f"(HSRP) Mismatched Virtual IP | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
					f"Expected: {exp.get('vip')} | Actual: {actual.get('vip')}"
				)
		if exp.get("priority") != actual.get("priority"):
			failures.append(
					f"(HSRP) Mismatched Priority | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
					f"Expected: {exp.get('priority')} | Actual: {actual.get('priority')}" 
				)
		if exp.get("preempt") != actual.get("preempt"):
		    failures.append(
		        f"(HSRP) Mismatched Preempt | Interface: {exp_key[0]} | "
		        f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
		        f"Expected: {exp.get('preempt')} | Actual: {actual.get('preempt')}"
		    )
		if exp.get("version") != actual.get("version"):
			failures.append(
					f"(HSRP) Mismatched Version | Interface: {exp_key[0]} | "
					f"VLAN: {exp_key[1]} | Group: {exp_key[2]}"
					f"Expected: {exp.get('version')} | Actual: {actual.get('version')}" 
				)
	return len(failures) == 0, failures
def check_nat(expected_nat, actual_config):
	failures = []
	if expected_nat.get("pat"):
		if not actual_config.get("pat"):
			failures.append(
					f"(NAT) Configuration Drift: Missing PAT"
				)
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
			failures.append(
					f"(PAT) Configuration Drift | Unexpected PAT Configuration"
				)
	if expected_nat.get("static"):
		if not actual_config.get("static"): 
			failures.append(
					f"(NAT) Configuration Drift: Missing Static Configuration"
				)
		exp_static = expected_nat.get("static", [])
		act_static = actual_config.get("static", [])

		exp_set = {(s["inside_ip"], s["outside_ip"]) for s in exp_static}
		act_set = {(s["inside_ip"], s["outside_ip"]) for s in act_static}

		missing = exp_set - act_set
		extra = act_set - exp_set 

		for inside,outside in missing:
			failures.append(
					f"(NAT STATIC) Missing Static Configuration | "
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
							f"(Dynamic NAT) Mismatched Pool Beginning IP | Pool: {p_name} |"
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
			failures.append(
					f"(NAT) Missing Inside Interface: {','.join(missing)} "
				)
		if extra: 
			failures.append(
					f"(NAT) Extra Inside Interface: {','.join(extra)} "
				)
	if exp_outside:
		act_outside = actual_config.get("interfaces", {}).get("outside", [])
		exp_set = set(exp_outside)
		act_set = set(act_outside)

		extra = act_set - exp_set 
		missing = exp_set - act_set

		if missing: 
			failures.append(
					f"(NAT) Missing Outside Interface: {','.join(missing)} "
				)
		if extra: 
			failures.append(
					f"(NAT) Extra Outside Interface: {','.join(extra)} "
				)

	return len(failures) == 0, failures
def check_dhcp(expected_dhcp, actual_config): 
	failures = []
	exp_pools = expected_dhcp.get("pools", [])
	act_pools = actual_config.get("pools", [])
	exp_key = {
		(e.get("pool_name")): e
		for e in exp_pools
	}
	act_key = {
		(a.get("pool_name", "")): a
		for a in act_pools
	}
	extra = act_key.keys() - exp_key.keys()
	if extra: 
		failures.append(
				f"(DHCP) Rogue DHCP Pool | Name: {extra}"
			)
	for e in exp_pools: 
		actual = act_key.get(e.get("pool_name", ""))
		if not actual: 
			failures.append(
					f"(DHCP) Missing DHCP Pool | Name: {e.get('pool_name', '')}"
				)
			continue 
		if e.get("default_gateway") != actual.get("default_gateway"): 
			failures.append(
					f"(DHCP) Default Gateway Mismatch | Pool: {e.get('pool_name', '')} | "
					f"Expected: {e.get('default_gateway', '')} | Actual: "
					f"{actual.get('default_gateway', '')}"
				) 
		if e.get("dns_ip") != actual.get("dns_ip"):
			failures.append(
					f"(DHCP) DNS Server IP Mismatch | Pool: {e.get('pool_name', '')} | "
					f"Expected: {e.get('dns_ip', [])} | Actual: {actual.get('dns_ip', [])}"
				)
		if (
				e.get("lease_days") != actual.get("lease_days")
				or e.get("lease_hours") != actual.get("lease_hours")
				or e.get("lease_minutes") != actual.get("lease_minutes")
			): 
			failures.append(
					f"(DHCP) Mismatched Lease Duration | Pool: {e.get('pool_name', '')} | "
					f"Expected(Days/Hours/Min): {e.get('lease_days')}/{e.get('lease_hours')}/"
					f"{e.get('lease_minutes')} | Actual: {actual.get('lease_days')}/"
					f"{actual.get("lease_hours")}/{actual.get('lease_minutes')}"
				)
		if (
				e.get("pool_ip") != actual.get("pool_ip")
				or e.get("pool_mask") != actual.get("pool_mask")
			):
			failures.append(
					f"(DHCP) Mismatched IP or Mask | Pool: {e.get('pool_name', '')} | "
					f"Expected: {e.get("pool_ip")}/{e.get("pool_mask")} | "
					f"Actual: {actual.get("pool_ip")}/{actual.get("pool_mask")}"
				)
		if e.get("domain_name") != actual.get("domain_name"): 
			failures.append(
					f"(DHCP) Mismatched Domain Name | Pool: {e.get('pool_name')} | "
					f"Expected: {e.get('domain_name')} | Actual: {actual.get('domain_name')}"
				)
	exp_excluded = expected_dhcp.get("excluded_addresses", [])
	act_excluded = actual_config.get("excluded_addresses", [])

	act_lookup = {a.get("start_ip"): a.get("end_ip") for a in act_excluded}
	exp_lookup = {e.get("start_ip"): e.get("end_ip") for e in exp_excluded}
	for e in exp_excluded: 
		exp_start = e.get("start_ip", "")
		exp_end = e.get("end_ip", "")
		actual = act_lookup.get(exp_start)
		if actual is None:
			failures.append(f"(DHCP) Missing Excluded Starting IP: {exp_start}")
		elif actual != exp_end:
			failures.append(
					f"(DHCP) Missing Excluded End IP | Start: {exp_start} "
					f"Expected End: {exp_end} | Actual: {actual}"
				)
	extra = act_lookup.keys() - exp_lookup.keys()
	for start in extra: 
		act_entry = next((a for a in act_excluded if a.get('start_ip') == start), {})
		failures.append(
				f"(DHCP) Unexpected Excluded IP addresses | "
				f"Start: {start} | End: {act_entry.get('end_ip', '')}"
			)
	exp_helpers = expected_dhcp.get("helper", {}).get("interfaces", [])
	act_helpers = actual_config.get("helper", {}).get("interfaces", [])

	exp_lookup = defaultdict(list)
	for e in exp_helpers:
		exp_lookup[e.get("interface_name")].append(e.get("helper_ip"))
	act_lookup = defaultdict(list)
	for a in act_helpers: 
		act_lookup[a.get("interface_name")].append(a.get("helper_ip"))
	all_interfaces = set(exp_lookup.keys()) | set(act_lookup.keys())

	for interface_name in all_interfaces:
		exp_ips = set(exp_lookup.get(interface_name, []))
		act_ips = set(act_lookup.get(interface_name, []))

		missing = exp_ips - act_ips 
		extra = act_ips - exp_ips 

		for ip in missing: 
			failures.append(
					f"(DHCP) Missing Helper IP | Interface: {interface_name} | "
					f"Helper IP: {ip}"
				)
		for e in extra: 
			failures.append(
					f"(DHCP) Drift Detected: Unexpected Helper IP | "
					f"Interface: {interface_name} | Helper IP: {e}"
				)
	return len(failures) == 0, failures  
def check_snmp(expected_snmp, actual_config): 
	failures = []
	exp_communities = expected_snmp.get("communities", [])
	act_communities = actual_config.get("communities", [])
	exp_tuple = {(e.get("snmp_name")):(e.get("permission")) for e in exp_communities}
	act_tuple = {(a.get("snmp_name")): (a.get("permission")) for a in act_communities}
	extra_c = act_tuple.keys() - exp_tuple.keys()
	for name in extra_c: 
		failures.append(
				f"(SNMP) Drift Detected: Unexpected SNMP Community Found | "
				f"Name: {name} | Permission: {act_tuple.get(name)}"
			)
	for name in exp_tuple: 
		actual = act_tuple.get(name)
		if actual is None: 
			failures.append(
					f"(SNMP) Missing SNMP Community | Name: {name}"
				)
			continue
		exp_permission = exp_tuple.get(name)

		if exp_permission != actual: 
			failures.append(
					f"(SNMP) Mismatched Community Permission | Name: {name} | "
					f"Expected: {exp_permission} | Actual: {actual}"
				)
	if expected_snmp.get("contact") != actual_config.get("contact"):
		failures.append(
				f"(SNMP) Mismatched Contact | Expected: {expected_snmp.get('contact')} | "
				f"Actual: {actual_config.get('contact')}"
			)
	exp_hosts = normalize_to_list(expected_snmp.get("hosts"))
	act_hosts = normalize_to_list(actual_config.get("hosts"))

	exp_tuple = {
			(h.get("snmp_name", ""), h.get("snmp_ip", ""), h.get("snmp_version", ""))
			for h in exp_hosts
	}
	act_tuple = {
				(h.get("snmp_name", ""), h.get("snmp_ip", ""), h.get("snmp_version", ""))
				for h in act_hosts
		}
	extra = act_tuple - exp_tuple 

	for name, ip, version in extra: 
		failures.append(
				f"(SNMP) Extra SNMP Found | Name: {name} | IP: {ip} | "
				f"Version: {version}"
			)
	act_lookup = {(a.get("snmp_name")): a for a in act_hosts}
	for e in exp_hosts: 
		actual = act_lookup.get(e.get("snmp_name"))
		if not actual: 
			failures.append(
					f"(SNMP) Community Name Not Found | Name: {e.get('snmp_name')}"
				)
			continue
		if actual.get("snmp_ip") != e.get("snmp_ip"): 
			failures.append(
					f"(SNMP) Mismatched SNMP IP Found | Name: {e.get('snmp_name')} | "
					f"Expected IP: {e.get('snmp_ip')} | Actual: {actual.get('snmp_ip')}"
				)
		if actual.get("snmp_version") != e.get("snmp_version"): 
			failures.append(
					f"(SNMP) Mismatched SNMP Version | Name: {e.get('snmp_name')} | "
					f"Expected: {e.get('snmp_version')} | Actual: {actual.get('snmp_version')}"
				)
	if expected_snmp.get("location") != actual_config.get("location"): 
		failures.append(
				f"(SNMP) SNMP Location Mismath | Expected: {expected_snmp.get('location')} | "
				f"Actual: {actual_config.get('location')}" 
			)
	exp_traps = expected_snmp.get("traps", {})
	act_traps = actual_config.get("traps", {})
	if exp_traps.get("config"): 
		if exp_traps.get("config") != act_traps.get("config"):
			failures.append(
					f"(SNMP) Mismatched Traps | Config | Expected: {exp_traps.get('config')} | "
					f"Actual: {act_traps.get('config')}"
				)
	if exp_traps.get('snmp') != act_traps.get('snmp'):
		failures.append(
				f"(SNMP) Mismatched Traps | SNMP | Expected: {exp_traps.get('snmp')} | "
				f"Actual: {act_traps.get('snmp')}"
			)
	if exp_traps.get('syslog') != act_traps.get('syslog'): 
		failures.append(
				f"(SNMP) Mismatched Traps | Syslog | Expected: {exp_traps.get('syslog')} | "
				f"Actual: {act_traps.get('syslog')}"
			)
	return len(failures) == 0, failures
def check_syslog(expected_syslog, actual_config, transport): 
	failures = []
	exp_hosts = set(expected_syslog.get("hosts", []))
	act_hosts = set(actual_config.get("hosts", []))

	missing_hosts = exp_hosts - act_hosts
	extra_hosts = act_hosts - exp_hosts

	if missing_hosts:
		for ip in missing_hosts: 
			failures.append(
					f"(SYSLOG) Missing Syslog Host | IP: {ip}"
				)
	if extra_hosts: 
		for ip in extra_hosts: 
			failures.append(
					f"(SYSLOG) Drift: Extra Syslog Host | IP: {ip}"
				)
	if transport == "NETCONF": 
		if expected_syslog.get("facility") != actual_config.get("facility"): 
			failures.append(
					f"(SYSLOG) Mismatched Facility | Expected: {expected_syslog.get('facility')} | "
					f"Actual: {actual_config.get('facility')}"
				)
	if expected_syslog.get("source_interface"): 
		if expected_syslog.get("source_interface") != actual_config.get("source_interface"):
			failures.append(
					f"(SYSLOG) Mismatched Source Interface | "
					f"Expected: {expected_syslog.get('source_interface')} | "
					f"Actual: {actual_config.get('source_interface')}"
				)
	if expected_syslog.get("timestamps") is True: 
		if not actual_config.get("timestamps"):
			failures.append(
					f"(SYSLOG) Mismatched Timestamps Configuration | service timestamps log datetime msec "
					f"Expected: {expected_syslog.get('timestamps')} | "
					f"Actual: {actual_config.get('timestamps')}"
				)
	if expected_syslog.get("trap_level") != actual_config.get("trap_level"): 
		failures.append(
				f"(SYSLOG) Mismatched Trap Level | "
				f"Expected: {expected_syslog.get('trap_level')} | "
				f"Actual: {actual_config.get('trap_level')}"
			)
	return len(failures) == 0, failures
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
					f"(Port Security) Interface Not Configured with PS | "
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
				failures.append(
						f"(Port Security) Missing MAC Address | "
						f"MAC: {m}"
					)
		if extra_mac: 
			for e in extra_mac: 
				failures.append(
						f"(Port Security) Drift: Extra MAC Address Found | "
						f"MAC: {e}"
					)
	return len(failures) == 0, failures
def check_snooping(expected_snooping, actual_config): 
	failures = []
	exp_vlans = set(expected_snooping.get("enabled_vlans", []))
	act_vlans = set(actual_config.get("enabled_vlans", []))
	missing_vlans = exp_vlans - act_vlans
	extra_vlans = act_vlans - exp_vlans

	if missing_vlans: 
		failures.append(
				f"(DHCP Snooping) Missing VLAN(s) On Device | VLAN(s): {sorted(missing_vlans)}"
			)
	if extra_vlans: 
		failures.append(
				f"(DHCP Snooping) Drift: Extra VLAN on Device | VLAN(s): {sorted(extra_vlans)}"
			)
	exp_interfaces = expected_snooping.get("interfaces", {})
	act_interfaces = actual_config.get("interfaces", {})

	exp_int = set(exp_interfaces.keys())
	act_int = set(act_interfaces.keys())

	extra_int = act_int - exp_int
	if extra_int:
		for e in extra_int:  
			failures.append(
					f"(DHCP Snooping) Extra Interface Configured with DHCP Snooping | "
					f"Interface: {e}"
				)
	for interface, int_value in exp_interfaces.items():
		actual = act_interfaces.get(interface)
		if not actual: 
			failures.append(
					f"(DHCP Snooping) Missing Interface Configured w DHCP Snooping | "
					f"Interface: {interface}"
				)
			continue
		if actual.get("rate_limit") != int_value.get("rate_limit"): 
			failures.append(
					f"(DCHP Snooping) Rate Limit Mismatch | "
					f"Expected: {int_value.get('rate_limit')} | "
					f"Actual: {actual.get('rate_limit')}"
				)
		if actual.get("trusted") != int_value.get("trusted"): 
			failures.append(
					f"(DHCP Snooping) Trusted Interface Config Mismatched | "
					f"Expected: {int_value.get('trusted')} | "
					f"Actual: {actual.get('trusted')}"
				)
	if actual_config.get("option82") != expected_snooping.get("option82"):
		failures.append(
				f"(DHCP Snooping) Mismatched Option 82 Config | "
				f"Expected: {int_value.get('option82')} | "
				f"Actual: {actual.get('option82')}"
			)
	return len(failures) == 0, failures
def check_dai(expected_dai, actual_config): 
	failures = []
	exp_arp = expected_dai.get("arp_inspection")
	if exp_arp is not None:
	    if exp_arp != actual_config.get("arp_inspection"):
	        failures.append(
	        			f"(DAI) DAI Operational State Mismatch"
	        			f" | Expected: {exp_arp} | Actual: {actual.get('expected')}" 
	        	)
	exp_vlans = set(expected_dai.get("enabled_vlans", []))
	act_vlans = set(actual_config.get("enabled_vlans", []))
	missing_vlans = exp_vlans - act_vlans
	extra_vlans = act_vlans - exp_vlans

	if missing_vlans:
			failures.append(
					f"(DAI) Missing VLAN(s) | VLAN(s): {sorted(missing_vlans)}"
				)
	if extra_vlans:
			failures.append(
					f"(DAI) Drift: Extra VLAN(s) Found | VLAN: {sorted(extra_vlans)}"
				)
	
	exp_buffer = expected_dai.get("log_buffer", {})
	act_buffer = actual_config.get("log_buffer", {})

	if exp_buffer.get("enabled") != act_buffer.get("enabled"):
	    failures.append(
	        f"(DAI) Log Buffer State Mismatch | "
	        f"Expected: {exp_buffer.get('enabled')} | "
	        f"Actual: {act_buffer.get('enabled')}"
	    )
	if exp_buffer.get("enabled") and act_buffer.get("enabled"): 
		if exp_buffer.get("entries") != act_buffer.get("entries"):
			failures.append(
					f"(DAI) Log Buffer Entries Mismatch | "
					f"Expected: {exp_buffer.get('entries')} | "
					f"Actual: {act_buffer.get('entries')}"
				)
	exp_interfaces = expected_dai.get("interfaces", {})
	act_interfaces = actual_config.get("interfaces", {})

	extra_int = act_interfaces.keys() - exp_interfaces.keys()

	if extra_int:
		for e in extra_int:
			failures.append(
					f"(DAI) Drift: Extra Interface Configured with DAI | "
					f"Interface: {e}"
				)
	for interface_name, int_value in exp_interfaces.items():
		actual = act_interfaces.get(interface_name)
		if not actual: 
			failures.append(
					f"(DAI) Missing Interface Not Configured with DAI | "
					f"Interface: {interface_name}"
				)
			continue
		if actual.get("rate_limit") != int_value.get("rate_limit"):
			failures.append(
					f"(DAI) Misatched Rate Limit Configuration | "
					f"Expected: {int_value.get('rate_limit')} | "
					f"Actual: {actual.get('rate_limit')}"
				)
		if actual.get("trusted") != int_value.get("trusted"):
			failures.append(
					f"(DAI) Mismatched Trusted Interface Configuration | "
					f"Expected: {int_value.get('trusted')} | "
					f"Actual: {actual.get('trusted')}"
				)	      
	return len(failures) == 0, failures
def check_cdp(expected_cdp, actual_config, transport): 
	failures = []
	exp_enabled = expected_cdp.get("enabled", False) 
	act_enabled = actual_config.get("enabled", False)

	if act_enabled is not None: 
		if exp_enabled != act_enabled: 
			failures.append(
					f"(CDP) Operational State Mismatch | "
					f"Expected: {exp_enabled} | Actual: {act_enabled}"
				)
	exp_timer = expected_cdp.get("timer", None)
	act_timer = actual_config.get("timer", None)
	if exp_timer != act_timer: 
		failures.append(
				f"(CDP) Timer Mismath | Expected: {exp_timer} | "
				f"Actual: {act_timer}"
			)
	exp_hold = expected_cdp.get("holdtime", None)
	act_hold = actual_config.get("holdtime", None)
	if exp_hold != act_hold: 
		failures.append(
				f"(CDP) HoldTime Mismatch | Expected: {exp_hold} | "
				f"Actual: {act_hold}"
			)
	exp_interfaces = expected_cdp.get("interfaces", {})
	act_interfaces = actual_config.get("interfaces", {})
 
	for interface, int_value in exp_interfaces.items(): 
		actual = act_interfaces.get(interface)
		exp_enabled = int_value.get("enabled", False)
		if transport == "NETMIKO":
			if exp_enabled: 
				if not actual: 
					failures.append(
							f"(CDP) Interface Not Configured w/ CDP | Interface: {interface}"
						)
					continue
				if actual.get("enabled") != int_value.get("enabled"):
					failures.append(
							f"(CDP) Interface CDP Configuration Mismatch | "
							f"Expected: {int_value.get('enabled')} | "
							f"Actual: {actual.get('enabled')}"
						)
			else: 
				if actual: 
					failures.append(
							f"(CDP) Interface CDP Operational State Mismatch | "
							f"Expected: {int_value.get('enabled')} | "
							f"Actual: {actual.get('enabled')}"
						)
		else: 
			if not actual: 
				failures.append(
						f"(CDP) Interface Not Configured w/ CDP | Interface: {interface}"
					)
				continue
			if actual.get("enabled") != int_value.get("enabled"):
				failures.append(
						f"(CDP) Interface CDP Configuration Mismatch | "
						f"Expected: {int_value.get('enabled')} | "
						f"Actual: {actual.get('enabled')}"
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
def configure_global_stp(conn, device_ip, stp_data, log): 
	mode = stp_data.get("mode", "")
	vlan_priorities = stp_data.get("vlan_priorities", {})
	vlan_log = " | ".join(
			f"VLAN: {v} Priority: {p}" 
			for v, p in vlan_priorities.items()
		)
	try: 
		template = template_env.get_template("STP_GLOBAL.j2")
		commands = template.render(
				mode=mode,
				vlan_priorities=vlan_priorities
			).splitlines().strip()
		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure STP Gloabally  | "
						f"Mode: {mode} | "
						f"VLAN/Priority: {vlan_log}"
				)
			}
		conn.send_config_set(commands)

		log.info(
            "stp_config",
            extra={
                "device_ip": device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "status": StepStatus.SUCCESS.value,
                "stp_mode": mode, 
                "vlan_priorities": vlan_priorities,
                "message": (f"STP Successfully Configured | "
						    f"Mode: {mode} | "
						    f"VLAN/Priority: {vlan_log}"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
						f"STP Successfully Configured | "
						f"Mode: {mode} | "
						f"VLAN/Priority: {vlan_log}"
                	)
			}
	except Exception as e: 
		log.error(
            "stp_config",
            extra={
                "device_ip": device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "status": StepStatus.ERROR.value,
                "stp_mode": mode, 
                "vlan_priorities": vlan_priorities,
                "message": (f"Try/Exception Error | STP Global Configuration | "
                			f"Mode: {mode} | "
						    f"VLAN/Priority: {vlan_log} | Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(f"Try/Exception Error | STP Global Configuration | "
                			f"Mode: {mode} | "
						    f"VLAN/Priority: {vlan_log} | Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_stp_int(conn, device_ip, stp_data, log): 
	interface = stp_data.get("interface", "")
	stp_int = stp_data.get("stp", {})
	stp_log = " | ".join(
		f"{s}:{b}"
			for s, b in stp_int.items()
		)
	try: 
		template = template_env.get_template("STP_INTERFACES.j2")
		commands = template.render(
				interface=interface,
				stp_int=stp_int
			).splitlines()
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure (STP) Interface Feature | "
						f"Interface: {interface} | Feature: {stp_log}"
				)
			}
		conn.send_config_set(commands)
		log.info(
            "stp_config",
            extra={
                "device_ip": device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "status": StepStatus.SUCCESS.value,
                "interface": interface, 
                "features": stp_log,
                "message": (f"STP Interface Feature Successfully Configured | "
						    f"Interface: {interface} | Feature: {stp_log}"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
							f"STP Interface Feature Successfully Configured | "
						    f"Interface: {interface} | Feature: {stp_log}"
                	)
			}
	except Exception as e: 
		log.error(
            "stp_config",
            extra={
                "device_ip": device_ip,
                "component": "stp_automation",
                "event_type": "stp_config",
                "status": StepStatus.ERROR.value,
                "interface": interface, 
                "features": stp_log,
                "message": (f"Try/Exception Error | STP Interface Configuration | "
                			f"Interface: {interface} | Feature: {stp_log} | "
                			f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(f"Try/Exception Error | STP Interface Configuration | "
                			f"Interface: {interface} | Feature: {stp_log} | "
                			f"Error: {str(e)}"
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
def configure_hsrp(session, device_ip, hsrp_data, log): 
	interface = hsrp_data.get("interface", "")
	match = re.match(r"([A-Za-z]+)(.+)", interface)
	interface_type = match.group(1) if match else ""
	int_num = match.group(2) if match else ""
	version = hsrp_data.get("version", "")
	group = hsrp_data.get("group", "")
	vip = hsrp_data.get("vip", "")
	priority = hsrp_data.get("priority", "")
	preempt = hsrp_data.get("preempt", "")
	router_vlan = hsrp_data.get("router_vlan", "")
	try: 
		template = template_env.get_template("HSRP_NETCONF.j2")
		commands = template.render(
				interface_type=interface_type,
				int_num=int_num,
				version=version,
				group=group,
				vip=vip,
				preempt=preempt,
				priority=priority
			)
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure HSRP | "
						f"Interface: {interface} | Version: {version} | "
						f"Group: {group} | VLAN: {router_vlan} | "
						f"VIP: {vip} | Preempt: {preempt} | Transport: NETCONF"
				)
			}

		
		session.edit_config(
			target="running",
			config=commands
		)
		
		log.info(
			"hsrp_automation",
            extra={
                "device_ip": device_ip,
                "component": "hsrp_config",
                "event_type": "hsrp_config",
                "status": StepStatus.SUCCESS.value,
                "interface": interface,
                "group": group,
                "vlan_id": router_vlan,
                "vip": vip,
                "version": version,
                "message": (
                		f"HSRP Configuration Successful | "
                		f"Interface: {interface} | Version: {version} | "
						f"Group: {group} | VLAN: {router_vlan} | "
						f"VIP: {vip} | Preempt: {preempt} | Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"HSRP Configuration Successful | "
	                		f"Interface: {interface} | Version: {version} | "
							f"Group: {group} | VLAN: {router_vlan} | "
							f"VIP: {vip} | Preempt: {preempt} | Transport: NETCONF"
                	)
			}
	
	except Exception as e: 
		log.info(
            "hsrp_config",
            extra={
                "device_ip": device_ip,
                "component": "hsrp_automation",
                "event_type": "hsrp_config",
                "status": StepStatus.ERROR.value,
                "interface": interface,
                "group": group,
                "vlan_id": router_vlan,
                "vip": vip,
                "version": version,
                "error": str(e),
                "message": (f"Try/Exception Error | HSRP Configuration | "
                			f"Interface: {interface} | Version: {version} | "
							f"Group: {group} | VLAN: {router_vlan} | "
							f"VIP: {vip} | Preempt: {preempt} | Transport: NETCONF | "
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | HSRP Configuration | "
                			f"Interface: {interface} | Version: {version} | "
							f"Group: {group} | VLAN: {router_vlan} | "
							f"VIP: {vip} | Preempt: {preempt} | Transport: NETCONF | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_nat(session, device_ip, nat_data, log):
	dynamic = nat_data.get("dynamic", [])
	pat = nat_data.get("pat", {})
	static = nat_data.get("static", [])
	nat_interfaces = nat_data.get("interfaces", {})
	inside_list = nat_interfaces.get("inside", [])
	outside_list = nat_interfaces.get("outside", [])
	interface_log = (
			f"Interfaces | "
			f"Inside: {','.join(inside_list)} | "
			f"Outside: {','.join(outside_list)}"
		)
	nat_model = {
        "pat": pat,
        "dynamic": dynamic,
        "static": static,
        "interfaces": {
            "inside": inside_list,
            "outside": outside_list
        }
    }
	
	log_parts = []
	if pat:
		log_parts.append(
				f"PAT NAT Overload | "
				f"ACL: {pat.get('acl', '')} | "
				f"Interface: {pat.get('interface', '')} | "
				f"Overload: {pat.get('overload')}"
			)
	if dynamic:
		dynamic_log = " | ".join(
				f"Dynamic NAT | "
				f"Pool: {d.get('pool_name','')} | ACL: {d.get('acl', '')} | "
				f"Start IP: {d.get('start_ip', '')} | End IP: {d.get('end_ip', '')}"
				for d in dynamic
			)
		log_parts.append(dynamic_log)
	if static: 
		static_log = " | ".join(
				f"Static NAT | "
				f"Inside Local: {s.get('inside_ip')} | "
				f"Outside Global: {s.get('outside_ip')}"
				for s in static
			)
		log_parts.append(static_log)
	nat_log = " | ".join(log_parts) if log_parts else "No NAT Configuration"
	try: 
		template_dynamic = template_env.get_template("NAT_POOL_NC.j2")
		template_pat = template_env.get_template("PAT_NC.j2")
		template_static = template_env.get_template("NAT_STATIC_NC.j2")
		template_interface = template_env.get_template("NAT_INT_NC.j2")
		
		all_commands = []
		interface_commands = []

		if nat_model.get("pat"):
			all_commands.append(
					template_pat.render(nat=nat_model)
				)
		if nat_model.get("dynamic"):
			all_commands.append(
					template_dynamic.render(
							nat=nat_model
						)
				)
		if nat_model.get("static"):
			all_commands.append(
					template_static.render(
							nat=nat_model
						)
				)
		for i in nat_model.get("interfaces", {}).get("inside", []):
			match = re.match(r"([A-Za-z]+)(.+)", i)
			interface_type = match.group(1) if match else ""
			interface_num = match.group(2) if match else ""
		    interface_commands.append(
		        template_interface.render(
		            interface_type=interface_type,
		            interface_num=interface_num,
		            role="inside"
		        )
		    )

		for o in nat_model.get("interfaces", {}).get("outside", []):
			match = re.match(r"([A-Za-z]+)(.+)", o)
			interface_type = match.group(1) if match else ""
			interface_num = match.group(2) if match else ""
		    interface_commands.append(
		        template_interface.render(
		            interface_type=interface_type,
		            interface_num=interface_num,
		            role="outside"
		        )
		    )
		if DRY_RUN:
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure NAT | "
						f"{nat_log} | {interface_log} | Transport: NETCONF"
				)
			}	
		for commands in all_commands:
			session.edit_config(
					target="running",
					config=commands
				)
		for c in interface_commands: 
			session.edit_config(
					target="running",
					config=c
				)
		log.info(
			"nat_config",
            extra={
                "device_ip": device_ip,
                "component": "nat_automation",
                "event_type": "nat_config",
                "status": StepStatus.SUCCESS.value,
                "nat": nat_log,
                "interfaces": interface_log,
                "message": (
                		f"NAT Configuration Successful | "
                		f"{nat_log} | {interface_log} | Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"NAT Configuration Successful | "
	                		f"{nat_log} | {interface_log} | Transport: NETCONF"
                	)
			}
	
	except Exception as e: 
		log.info(
            "nat_config",
            extra={
                "device_ip": device_ip,
                "component": "nat_automation",
                "event_type": "nat_config",
                "status": StepStatus.ERROR.value,
                "nat": nat_log,
                "interfaces": interface_log,
                "error": str(e),
                "message": (f"Try/Exception Error | NAT Configuration | "
                			f"{nat_log} | {interface_log} | Transport: NETCONF"
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | NAT Configuration | "
                			f"{nat_log} | {interface_log} | Transport: NETCONF | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_dhcp(session, device_ip, dhcp_data, log): 
	excluded_addresses = dhcp_data.get("excluded_addresses", [])
	pools = dhcp_data.get("pools", [])
	helper = dhcp_data.get("helper", {}).get("interfaces", [])

	excluded_log = " | ".join(
			f"Excluded IPs | Start IP: {e.get('start_ip')} | End IP: {e.get('end_ip', '')}"
			for e in excluded_addresses
		)
	pool_log = " | ".join(
			f"Pool: {p.get('pool_name')} | IP: {p.get('pool_ip')}/{p.get('pool_mask')} |"
			f"Default Gateway: {p.get('default_gateway')} "
			for p in pools
		)
	helper_log = " | ".join(
			f"Helper IP: {h.get('helper_ip')} | Interface: {h.get('interface_name')}"
			for h in helper
		)
	try: 
		template_excl = template_env.get_template("DHCP_EXCL_NC.j2")
		template_help = template_env.get_template("DHCP_HELP_NC.j2")
		template_pool = template_env.get_template("DHCP_POOL_NC.j2")

		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure DHCP | "
						f"{excluded_log} | {pool_log} | {helper_log}"
				)
			}
		if excluded_addresses:
			commands = template_excl.render(excluded_addresses=excluded_addresses)
			session.edit_config(
					target="running",
					config=commands
				)
		if pools:
			commands = template_pool.render(pools=pools)
			session.edit_config(
						target="running",
						config=commands
					)
		for h in helper:
			helper_ip = h.get("helper_ip")
			if not helper_ip:
				continue

			interface_name = h.get("interface_name", "")
			match = re.match(r"([A-Za-z]+)(.+)", interface_name)
			if not match: 
				continue
			interface_type = match.group(1) if match else "" 
			interface_num = match.group(2) if match else ""
			commands = template_help.render(
					interface_type=interface_type,
					interface_num=interface_num,
					helper_ip=helper_ip
				)
			session.edit_config(
					target="running",
					config=commands
				)

		log.info(
			"dhcp_config",
            extra={
                "device_ip": device_ip,
                "component": "dhcp_automation",
                "event_type": "dhcp_config",
                "status": StepStatus.SUCCESS.value,
                "pool": pool_log,
                "helper": helper_log,
                "excluded_addresses": excluded_log,
                "message": (
                		f"DHCP Configuration Successful | "
                		f"{excluded_log} | {pool_log} | {helper_log} | "
                		f"Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"DHCP Configuration Successful | "
                			f"{excluded_log} | {pool_log} | {helper_log} | "
                			f"Transport: NETCONF"
                	)
			}
	
	except Exception as e: 
		log.info(
            "dhcp_config",
            extra={
                "device_ip": device_ip,
                "component": "dhcp_automation",
                "event_type": "dhcp_config",
                "status": StepStatus.ERROR.value,
                "pool": pool_log,
                "helper": helper_log,
                "excluded_addresses": excluded_log,
                "error": str(e),
                "message": (f"Try/Exception Error | DHCP Configuration | "
                			f"{excluded_log} | {pool_log} | {helper_log} | "
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | DHCP Configuration | "
                			f"{excluded_log} | {pool_log} | {helper_log} | "
                			f"Transport: NETCONF | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_snmp_netmiko(conn,device_ip,snmp_data, log):
	communities = snmp_data.get("communities", [])
	contact = snmp_data.get("contact", "")
	hosts = snmp_data.get("hosts", [])
	location = snmp_data.get("location", "")
	traps = snmp_data.get("traps", {})

	communities_log = " | ".join(
			f"SNMP Name: {c.get('snmp_name')} | SNMP Permission: {c.get('permission')}"
			for c in communities
		)
	hosts_log = " | ".join(
			f"SNMP IP: {h.get('snmp_ip')} | Version: {h.get('version')}"
			for h in hosts
		)
	try: 
		template = template_env.get_template("SNMP_NETMIKO.j2")

		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SNMP | "
						f"{communities_log} | {hosts_log} | "
						f"Location: {location} | Contact: {contact} | "
						f"Traps: {traps} | Transport: NETMIKO"
				)
			}
		commands = template.render(
				communities=communities,
				traps=traps,
				hosts=hosts,
				contact=contact,
				location=location

			).splitlines()
		
		conn.send_config_set(commands)
		
		log.info(
			"snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "status": StepStatus.SUCCESS.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "message": (
                		f"SNMP (Switch) Configuration Successful | "
                		f"{communities_log} | {hosts_log} | "
						f"Location: {location} | Contact: {contact} | "
						f"Traps: {traps} | Transport: NETMIKO"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"SNMP (Switch) Configuration Successful | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: NETMIKO"
                	)
			}
	
	except Exception as e: 
		log.info(
            "snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "status": StepStatus.ERROR.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "error": str(e),
                "message": (f"Try/Exception Error | SNMP (Switch) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: NETMIKO | "
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | SNMP (Switch) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: NETMIKO | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_snmp(session, device_ip, snmp_data, log): 
	communities = snmp_data.get("communities", [])
	contact = snmp_data.get("contact", "")
	hosts = snmp_data.get("hosts", [])
	location = snmp_data.get("location", "")
	traps = snmp_data.get("traps", {})

	communities_log = " | ".join(
			f"SNMP Name: {c.get('snmp_name')} | SNMP Permission: {c.get('permission')}"
			for c in communities
		)
	hosts_log = " | ".join(
			f"SNMP IP: {h.get('snmp_ip')} | Version: {h.get('snmp_version')}"
			for h in hosts
		)
	try: 
		template_netconf = template_env.get_template("SNMP_NC.j2")

		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SNMP | "
						f"{communities_log} | {hosts_log} | "
						f"Location: {location} | Contact: {contact} | "
						f"Traps: {traps} | Transport: NETCONF"
				)
			}
		commands = template_netconf.render(
				communities=communities,
				traps=traps,
				hosts=hosts,
				contact=contact,
				location=location

			)
		session.edit_config(
				target="running", 
				config=commands
			)
		log.info(
			"snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "status": StepStatus.SUCCESS.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "message": (
                		f"SNMP (Router) Configuration Successful | "
                		f"{communities_log} | {hosts_log} | "
						f"Location: {location} | Contact: {contact} | "
						f"Traps: {traps} | Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"SNMP (Router) Configuration Successful | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: NETCONF"
                	)
			}
	
	except Exception as e: 
		log.info(
            "snmp_config",
            extra={
                "device_ip": device_ip,
                "component": "snmp_automation",
                "event_type": "snmp_config",
                "status": StepStatus.ERROR.value,
                "contact": contact,
                "location": location,
                "hosts": hosts_log,
                "communities": communities_log,
                "traps": traps,
                "error": str(e),
                "message": (f"Try/Exception Error | SNMP (Router) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: NETCONF | "
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | SNMP (Router) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: NETCONF | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def cofnigure_syslog_netmiko(conn, device_ip, syslog_data, log): 
	facility = syslog_data.get("facility", "")
	hosts = syslog_data.get("hosts", [])
	source_interface = syslog_data.get("source_interface", "")
	timestamps = syslog_data.get("timestamps", False)
	trap_level = syslog_data.get("trap_level", "")

	hosts_log = " | ".join(
			f"IP: {h}"
			for h in hosts
		)

	try: 
		template_syslog = template_env.get_template("SYSLOG_NETMIKO.j2")

		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SYSLOG | "
						f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level} | Transport: NEMIKO"
				)
			}

		commands_syslog = template_syslog.render(
				facility=facility,
				trap_level=trap_level,
				hosts=hosts,
				source_interface=source_interface,
				timestamps=timestamps
			).splitlines()

		conn.send_command(commands_syslog)
		
		log.info(
			"syslog_config",
            extra={
                "device_ip": device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "status": StepStatus.SUCCESS.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "message": (
                		f"Syslog Configuration Successful | "
                		f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level} | Transport: NETMIKO"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"Syslog Configuration Successful | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: NETMIKO"
                	)
			}
	
	except Exception as e: 
		log.info(
            "syslog_config",
            extra={
                "device_ip": device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "status": StepStatus.ERROR.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "error": str(e),
                "message": (f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: NETMIKO"
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: NETMIKO | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_syslog_nc(session, device_ip, syslog_data, log): 
	facility = syslog_data.get("facility", "")
	hosts = syslog_data.get("hosts", [])
	source_interface = syslog_data.get("source_interface", "")
	timestamps = syslog_data.get("timestamps", False)
	trap_level = syslog_data.get("trap_level", "")

	hosts_log = " | ".join(
			f"IP: {h}"
			for h in hosts
		)

	try: 
		template_timestamps = template_env.get_template("SYS_Time_NC.j2")
		template_syslog = template_env.get_template("SYSLOG_NC.j2")

		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure SYSLOG | "
						f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level} | Transport: NETCONF"
				)
			}

		commands_syslog = template_syslog.render(
				facility=facility,
				trap_level=trap_level,
				hosts=hosts,
				source_interface=source_interface,
			)
		commands_timestamps = template_timestamps.render()
		session.edit_config(
				target="running", 
				config=commands_syslog
			)
		if timestamps: 
			session.edit_config(
					target="running",
					config=commands_timestamps
				)

		log.info(
			"syslog_config",
            extra={
                "device_ip": device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "status": StepStatus.SUCCESS.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "message": (
                		f"Syslog Configuration Successful | "
                		f"Hosts: {hosts_log} | Facility: {facility} | "
						f"Source Interface: {source_interface} | "
						f"service timestamps log datetime msec: {timestamps} | "
						f"Severity: {trap_level} | Transport: NETCONF"
                	)
            }

        )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"Syslog Configuration Successful | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: NETCONF"
                	)
			}
	
	except Exception as e: 
		log.info(
            "syslog_config",
            extra={
                "device_ip": device_ip,
                "component": "syslog_automation",
                "event_type": "syslog_config",
                "status": StepStatus.ERROR.value,
                "timestamps": timestamps,
                "facility": facility,
                "source_interface": source_interface,
                "hosts": hosts_log,
                "severity": trap_level,
                "error": str(e),
                "message": (f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: NETCONF"
							f"Error: {str(e)}"
                	)
            }

        )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Syslog Configuration | "
                			f"Hosts: {hosts_log} | Facility: {facility} | "
							f"Source Interface: {source_interface} | "
							f"service timestamps log datetime msec: {timestamps} | "
							f"Severity: {trap_level} | Transport: NETCONF | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_psecurity(conn, device_ip, ps_data, log): 
	interfaces = ps_data.get("interfaces", {})
	ps_log = " | ".join(
			f"Interface: {i} | Enabled: {v.get('enabled')} | Maximum: {v.get('maximum')} | "
			f"Sticky: {v.get('sticky')} | MAC Addresses: {v.get('mac_addresses')}"
			for i, v in interfaces.items()
		)
	interface_list = [
		{  	"interface": i,
			"enabled": v.get('enabled'),
			"maximum": v.get('maximum'),
			"violation": v.get('violation'),
			"sticky": v.get('sticky'),
			"mac_addresses": v.get('mac_addresses'),
		}
		for i, v in interfaces.items()
	]

	try: 
		template = template_env.get_template("PS_NETMIKO.j2")
		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure Port Security | "
						f"{ps_log}"
				)
			}
		for intf in interface_list: 
			commands = [ 
					line.strip()
					for line in template.render(
					interface=intf.get("interface"),
					enabled=intf.get("enabled"),
					maximum=intf.get("maximum"),
					violation=intf.get("violation"),
					sticky=intf.get("sticky"),
					mac_addresses=intf.get("mac_addresses", [])
				).splitlines()
				if line.strip()
			]
			conn.send_config_set(commands)

		log.info(
			"ps_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "ps_automation",
	            "event_type": "ps_config",
	            "status": StepStatus.SUCCESS.value,
	            "interfaces": interface_log,
	            "message": (
	            		f"Port Security Configuration Successful | "
	            		f"{ps_log} | Transport: NETMIKO"
	            	)
	        }

	    )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"Port Security Configuration Successful | "
	            			f"{ps_log} | Transport: NETMIKO"
	            	)
			}

	except Exception as e: 
		log.info(
	        "ps_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "ps_automation",
	            "event_type": "ps_config",
	            "status": StepStatus.ERROR.value,
	            "interfaces": ps_log,
	            "error": str(e),
	            "message": (f"Try/Exception Error | Port Security Configuration | "
	            			f"{ps_log} | Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Port Security Configuration | "
	            		    f"{ps_log} | Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
def configure_snooping(conn, device_ip, snoop_data, log): 
	enabled_vlans = snoop_data.get("enabled_vlans", [])
	option82 = snoop_data.get("option82", False)
	interfaces = snoop_data.get("interfaces", {})
	interface_list = [
		{	
			"interface": i,
			"rate_limit": v.get("rate_limit", ""),
			"trusted": v.get("trusted", False)

		} for i, v in interfaces.items()
	]
	interface_log = " | ".join(
			f"Interface: {i} | Rate Limit: {v.get('rate_limit')} | Trusted Interface: "
			f"{v.get('trusted')}"
		 	for i, v in interfaces.items()
		)
	try: 
		template = template_env.get_template("SNOOPING_NET.j2")
		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure DHCP Snooping | "
						f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Option 82: {option82} | Transport: NETMIKO"
				)
			}
		global_commands = template.render(
				enabled_vlans=enabled_vlans,
				option82=option82
			)
		conn.send_config_set(global_commands)

		for intf in interface_list: 
			commands = [
				l.strip()
				for l in template.render(
						interface=intf.get("interface"),
						trusted=intf.get("trusted"),
						rate_limit=intf.get("rate_limit")
					).splitlines()
					if l.strip()
			]
			conn.send_config_set(commands)

		log.info(
			"snooping_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "snooping_automation",
	            "event_type": "snooping_config",
	            "status": StepStatus.SUCCESS.value,
	            "VLANs": enabled_vlans,
	            "interfaces": interface_log,
	            "option82": option82,
	            "message": (
	            		f"DHCP Snooping Configuration Successful | "
	            		f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Option 82: {option82} | Transport: NETMIKO"
	            	)
	        }

	    )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"DHCP Snooping Configuration Successful | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Option 82: {option82} | Transport: NETMIKO"
	            	)
			}

	except Exception as e: 
		log.info(
	        "snooping_automation",
	        extra={
	            "device_ip": device_ip,
	            "component": "snooping_automation",
	            "event_type": "snooping_config",
	            "status": StepStatus.ERROR.value,
	           	"VLANs": enabled_vlans,
	            "interfaces": interface_log,
	            "option82": option82,
	            "error": str(e),
	            "message": (f"Try/Exception Error | DHCP Snooping Configuration | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Option 82: {option82} | Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | DHCP Snooping Configuration | "
	            		    f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Option 82: {option82} | Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
def configure_dai(conn, device_ip, dai_data, log): 
	enabled_vlans = dai_data.get("enabled_vlans", [])
	interfaces = dai_data.get("interfaces", {})
	log_buffer = dai_data.get("log_buffer", {})

	interface_log = " | ".join(
			f"Interface: {i} | Rate Limit: {v.get('rate_limit', None)} | "
			f"Trusted: {v.get('trusted', '')}"
			for i, v in interfaces.items()
		)
	buffer_log = " | ".join(
			f"Enabled: {log_buffer.get('enabled')} | Entries: {log_buffer.get('entries')}"
		)
	try: 
		template = template_env.get_template("DAI_NET.j2")

		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure DAI | "
						f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Log Buffer: {buffer_log} | Transport: NETMIKO"
				)
			}
		
		commands = template.render(
				enabled_vlans=enabled_vlans,
				log_buffer=log_buffer,
				interfaces=interfaces
			).splitlines()
		
		conn.send_config_set(commands)


		log.info(
			"dai_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "dai_automation",
	            "event_type": "dai_config",
	            "status": StepStatus.SUCCESS.value,
	            "VLANs": enabled_vlans,
	            "interfaces": interface_log,
	            "buffer_log": buffer_log,
	            "message": (
	            		f"DAI Configuration Successful | "
	            		f"VLANs: {enabled_vlans} | {interface_log} | "
						f"Log Buffer: {buffer_log} | Transport: NETMIKO"
	            	)
	        }

	    )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"DAI Configuration Successful | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Log Buffer: {buffer_log} | Transport: NETMIKO"
	            	)
			}

	except Exception as e: 
		log.info(
	        "dai_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "dai_automation",
	            "event_type": "dai_config",
	            "status": StepStatus.ERROR.value,
	           	"VLANs": enabled_vlans,
	            "interfaces": interface_log,
	            "buffer_log": buffer_log,
	            "error": str(e),
	            "message": (f"Try/Exception Error | DAI Configuration | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Log Buffer: {buffer_log} | Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | DAI Configuration | "
	            			f"VLANs: {enabled_vlans} | {interface_log} | "
							f"Log Buffer: {buffer_log} | Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
def configure_cdp_netmiko(conn, device_ip, cdp_data, log): 
	enabled = cdp_data.get("enabled", False)
	timer = cdp_data.get("timer", None)
	holdtime = cdp_data.get("holdtime", None)
	interfaces = cdp_data.get("interfaces", {})
	int_log = " | ".join(
	     f"Interface/Enabled: {i}/{v.get('enabled')}" 
		 for i, v in interfaces.items()
		)
	try: 
		template = template_env.get_template("CDP_NET.j2")
		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure CDP | "
						f"Enabled: {enabled} | Timer: {timer} | "
						f"HoldTime: {holdtime} | {int_log} | "
						f"Transport: NETMIKO"
				)
			}
		
		commands = template.render(
				timer=timer,
				holdtime=holdtime,
				interfaces=interfaces,
				enabled=enabled
			).splitlines()

		conn.send_config_set(commands)

		log.info(
			"cdp_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "cdp_automation",
	            "event_type": "cdp_config",
	            "status": StepStatus.SUCCESS.value,
	            "globally_enabled": enabled,
	            "timer/holdtime": f"{timer}/{holdtime}",
	            "interfaces": int_log,
	            "message": (
	            		f"CDP Configuration Successful | "
	            		f"Enabled: {enabled} | Timer: {timer} | "
						f"HoldTime: {holdtime} | {int_log} | "
						f"Transport: NETMIKO"
	            	)
	        }

	    )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"CDP Configuration Successful | "
		            		f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: NETMIKO"
	            	)
			}

	except Exception as e: 
		log.info(
	        "cdp_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "cdp_automation",
	            "event_type": "cdp_config",
	            "status": StepStatus.ERROR.value,
	           	"globally_enabled": enabled,
	            "timer/holdtime": f"{timer}/{holdtime}",
	            "interfaces": int_log,
	            "error": str(e),
	            "message": (f"Try/Exception Error | CDP Configuration | "
	            			f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | CDP Configuration | "
	            			f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
def configure_cdp_nc(session, device_ip, cdp_data, log): 
	enabled = cdp_data.get("enabled", False)
	timer = cdp_data.get("timer", None)
	holdtime = cdp_data.get("holdtime", None)
	interfaces = cdp_data.get("interfaces", {})
	int_log = " | ".join(
	     f"Interface/Enabled: {i}/{v.get('enabled')}" 
		 for i, v in interfaces.items()
		)
	try: 
		template_global = template_env.get_template("CDP_NC.j2")
		template_int = template_env.get_template("CDP_INT_NC.j2")
		if DRY_RUN: 
			return {
				"status": OpStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure CDP | "
						f"Enabled: {enabled} | Timer: {timer} | "
						f"HoldTime: {holdtime} | {int_log} | "
						f"Transport: NETCONF"
				)
			}
		global_commands = template_global.render(
				holdtime=holdtime, 
				timer=timer,
				enabled=enabled
			)
		session.edit_config(
				target="running",
				config=global_commands
			)
		for interface, int_value in interfaces.items():
			match = re.match(r"([A-Za-z]+)(.+)", interface)
			interface_type = match.group(1) if match else ""
			interface_num = match.group(2) if match else ""
			enabled = int_value.get("enabled", False)

			int_commands = template_int.render(
					interface_type=interface_type,
					interface_num=interface_num,
					enabled=enabled
				)
			session.edit_config(target="running", config=int_commands)

		log.info(
			"cdp_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "cdp_automation",
	            "event_type": "cdp_config",
	            "status": StepStatus.SUCCESS.value,
	            "globlly_enabled": enabled,
	            "timer/holdtime": f"{timer}/{holdtime}",
	            "interfaces": int_log,
	            "message": (
	            		f"CDP Configuration Successful | "
	            		f"Enabled: {enabled} | Timer: {timer} | "
						f"HoldTime: {holdtime} | {int_log} | "
						f"Transport: NETCONF"
	            	)
	        }

	    )
		return {
				"status": OpStatus.SUCCESS.value,
				"summary": (
					 		f"CDP Configuration Successful | "
		            		f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: NETCONF"
	            	)
			}

	except Exception as e: 
		log.info(
	        "cdp_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "cdp_automation",
	            "event_type": "cdp_config",
	            "status": StepStatus.ERROR.value,
	           	"globlly_enabled": enabled,
	            "timer/holdtime": f"{timer}/{holdtime}",
	            "interfaces": int_log,
	            "error": str(e),
	            "message": (f"Try/Exception Error | CDP Configuration | "
	            			f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: NETCONF | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OpStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | CDP Configuration | "
	            			f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: NETCONF | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}