import pynetbox
from collections import defaultdict
import ipaddress
from netmiko import ConnectHandler
from jinja2 import Environment, FileSystemLoader
from ncclient import manager 
import xmltodict
from ciscoconfparse import CiscoConfParse
from datetime import datetime, UTC
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
from src.transports.session_manager import get_session
from src.collectors.cli import collect_device_state
from src.collectors.netconf import collect_netconf_state
from src.collectors.restconf import collect_restconf_state
from src.pipeline.features import PIPELINE
from src.pipeline.runner import run_pipeline
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
def restconf_get(session, url):
	try: 
		response = session.get(url, timeout=20)
		if response.status_code in [200,201]: 
			return response.json()
		return {}
	except Exception:
		return {}
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
			 f"Mismatched Interface State | Interface: {exp_interface} | "
			 f"Expected Should Be Up/Up: {exp_is_up} | "
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
def check_etherchannel(expected_ether, actual_config): 
	failures = []
	exp_enabled = expected_ether.get("enabled", False)
	act_enabled = actual_config.get("enabled", False)

	if exp_enabled != act_enabled: 
		failures.append(
				f"(Etherchannel) Misconfigured Operation Mode | "
				f"Expected: {exp_enabled} | Actual: {act_enabled}"
			)
	exp_groups = expected_ether.get("groups", {})
	act_groups = actual_config.get("groups", {})

	extra_groups = act_groups.keys() - exp_groups.keys()

	if extra_groups: 
		failures.append(
				f"(Etherchannel) Drift: Unexpected Port Channels | "
				f"{sorted(extra_groups)}"
			)
	for group, g_value in exp_groups.items(): 
		actual = act_groups.get(group)
		if not actual: 
			failures.append(
				f"(Etherchannel) Missing Port Channel Group | "
				f"{group}"
			)
			continue
		exp_set = set(g_value.get("interfaces", []))
		act_set = set(actual.get("interfaces", []))

		missing_int = exp_set - act_set
		extra_int = act_set - exp_set

		if missing_int:
			for m in missing_int: 
				failures.append(
						f"(Etherchannel) Missing Interface | "
						f"Group: {group} | Interface: {m}"
					)
		if extra_int: 
			for e in extra_int: 
				failures.append(
						f"(Etherchannel) Drift: Unexpected Interface | "
						f"Group: {group} | Interface: {e}"
					)
		if actual.get("mode") !=  g_value.get("mode"):
			failures.append(
					f"(Etherchannel) Mode Mismatch | Expected: {g_value.get('mode')} | "
					f"Actual: {actual.get('mode')}"
				)
		if actual.get("switchport_mode") != g_value.get("switchport_mode"): 
			failures.append(
					f"(Etherchannel) Mismatched Switchport Mode | Expected:"
					f" {g_value.get('switchport_mode')} | Actual: {actual.get('switchport_mode')}"

				)
		if actual.get("type") != g_value.get("type"): 
			failures.append(
					f"(Etherchannel) Mismatched Etherchannel Type | "
					f"Expected: {g_value.get('type')} | Actual: {actual.get('type')}"
				)
		if actual.get("description") != g_value.get("description"): 
			failures.append(
					f"(Etherchannel) Mismatched Description | Expected: "
					f"{g_value.get('description')} | Actual: {actual.get('description')}"
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
				"summary":(f"Try/Exception Error | VLAN Configuration | "
                		   f"Interface: {trunk_interface} | "
                			f"Allowed VLANs: {allowed_vlans} | Error: {e}"
                	),
				"error": str(e)
			}
def configure_interface(conn, device_ip, interface_data, log): 
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
                "status": OperationalStatus.CONFIG_FAILED.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
                "status": OperationalStatus.CONFIG_FAILED.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
                "status": OperationalStatus.CONFIG_FAILED.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | DHCP Configuration | "
                			f"{excluded_log} | {pool_log} | {helper_log} | "
                			f"Transport: NETCONF | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_etherchannel(conn, device_ip, eth_data, log): 
	enabled = eth_data.get("enabled", False)
	groups = eth_data.get("groups", {})
	groups_log = " | ".join(
			f"Group #: {g} | Mode: {v.get('mode')} | Type: {v.get('type')} | "
			f"Switchport Mode: {v.get('switchport_mode')} | Interfaces: "
			f"Interfaces: {','.join(v.get('interfaces', []))} | Description: {v.get('description')}"
			for g, v in groups.items()
		)

	try: 
		template = template_env.get_template("etherchannel_net.j2")
		
		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure Etherchannel | "
						f"Enabled: {enabled} | {groups_log} | "
						f"Transport: NETMIKO"
						
				)
			}
		commands = template.render(
				enabled=enabled,
				groups=groups
			).splitlines()

		conn.send_config_set(commands)

		log.info(
			"ether_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "ether_automation",
	            "event_type": "ether_config",
	            "status": StepStatus.SUCCESS.value,
	            "enabled": enabled,
	            "message": (
	            		f"Etherchannel Configuration Successful | "
	            		f"Enabled: {enabled} | {groups_log} | "
						f"Transport: NETMIKO"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"Etherchannel Configuration Successful | "
		            		f"Enabled: {enabled} | {groups_log} | "
							f"Transport: NETMIKO"
	            	)
			}

	except Exception as e: 
		log.info(
	        "ether_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "ether_automation",
	            "event_type": "ether_config",
	            "status": StepStatus.ERROR.value,
	           	"enabled": enabled,
	            "error": str(e),
	            "message": (f"Try/Exception Error | Etherchannel Configuration | "
	            			f"Enabled: {enabled} | {groups_log} | "
							f"Transport: NETMIKO | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Etherchannel Configuration | "
	            			f"Enabled: {enabled} | {groups_log} | "
							f"Transport: NETMIKO | "
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | SNMP (Switch) Configuration | "
                			f"{communities_log} | {hosts_log} | "
							f"Location: {location} | Contact: {contact} | "
							f"Traps: {traps} | Transport: NETMIKO | "
							f"Error: {str(e)}"
                	),
				"error": str(e)
			}
def configure_snmp_nc(session, device_ip, snmp_data, log): 
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
	buffer_log = f"Enabled: {log_buffer.get('enabled')} | Entries: {log_buffer.get('entries')}"
	
	try: 
		template = template_env.get_template("DAI_NET.j2")

		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
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
				"status": OperationalStatus.DRY_RUN.value,
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
				"status": OperationalStatus.SUCCESS.value,
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
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | CDP Configuration | "
	            			f"Enabled: {enabled} | Timer: {timer} | "
							f"HoldTime: {holdtime} | {int_log} | "
							f"Transport: NETCONF | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
def configure_static(session, device_ip, static_data, log): 
	static = static_data.get("static", [])
	static_log = " | ".join(
			f"Network Address: {s.get('network_address')} | Mask: {s.get('mask')} | "
			f"AD: {s.get('AD', 'N/A')} | Exit Interface : {s.get('exit_interface', 'N/A')} | "
			f"Next Hop IP: {s.get('next_hop', 'N/A')}"
			for s in static
		)
	try: 
		temp_recursive = template_env.get_template("RECURSIVE.j2")
		temp_exit_int = template_env.get_template("EXIT_INT.j2")
		temp_full = template_env.get_template("FULLY_SPECIFIC.j2")

		templates = {
			"recursive": temp_recursive,
			"exit-interface": temp_exit_int,
			"fully-specified": temp_full
		}

		
		if DRY_RUN: 
			return {
				"status": OperationalStatus.DRY_RUN.value,
				"summary": (
						f"[DRY_RUN] Would Configure Static Routes | "
						f"{static_log} | Transport: NETCONF"
				)
			}

		for s in static: 
			template = templates.get(s.get("type"))
			if not template: 
				continue
			commands = template.render(
					static=static
				)
			
	        session.edit_config(
	            target="running",
	            config=commands
	        )

		log.info(
			"static_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "static_automation",
	            "event_type": "static_config",
	            "status": StepStatus.SUCCESS.value,
	            "message": (
	            		f"Static Routes Configuration Successful | "
	            		f"{static_log} | Transport: NETCONF"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.SUCCESS.value,
				"summary": (
					 		f"Static Route Configuration Successful | "
		            		f"{static_log} | Transport: NETCONF"
	            	)
			}

	except Exception as e: 
		log.info(
	        "static_config",
	        extra={
	            "device_ip": device_ip,
	            "component": "static_automation",
	            "event_type": "static_config",
	            "status": StepStatus.ERROR.value,
	            "error": str(e),
	            "message": (f"Try/Exception Error | Static Route Configuration | "
	            			f"{static_log} | Transport: NETCONF | "
							f"Error: {str(e)}"
	            	)
	        }

	    )
		return {
				"status": OperationalStatus.ERROR.value,
				"summary":(
							f"Try/Exception Error | Static Route Configuration | "
	            			f"{static_log} | Transport: NETCONF | "
							f"Error: {str(e)}"
	            	),
				"error": str(e)
			}
class SessionContext: 
	def __init__(self, session, base_url, device_ip): 
		self.session = session
		self.base_url = base_url 
		self.device_ip = device_ip 
def restconf_get(session, url):
    try:
        response = session.get(url, verify=False)

        response.raise_for_status()

        return response.json()
    except requests.exceptions.HTTPError as e:
    	raise Exception(f"RESTCONF HTTP error: {e} | URL: {url}")

    except requests.exceptions.RequestException as e:
        raise Exception(f"RESTCONF request failed: {e} | URL: {url}")
def generate_manager_report(report):

    metadata = report["run_metadata"]
    summary = report["summary"]

    with open("network_compliance_report.txt", "w") as f:

        f.write("=" * 60)
        f.write("\nNETWORK COMPLIANCE REPORT\n")
        f.write("=" * 60)

        f.write(
            f"\n\nReport Time: {metadata['timestamp']}"
        )

        f.write(
            f"\nDevices Audited: {metadata['total_devices']}"
        )


        f.write("\n\nSUMMARY")
        f.write("\n----------------")
        f.write(
            f"\n✅ Compliant: {summary['compliant']}"
        )
        f.write(
            f"\n⚠️ Non-Compliant: {summary['non_compliant']}"
        )
        f.write(
            f"\n❌ Failed: {summary['failed']}"
        )


        f.write("\n\nDEVICE DETAILS")
        f.write("\n----------------")


        for device in report["devices"]:

            f.write(
                f"\n\nDevice: {device.get('device_name','Unknown')}"
            )

            f.write(
                f"\nStatus: {device.get('status')}"
            )


            if device.get("critical_issues"):

                f.write("\nIssues:")

                for issue in device["critical_issues"]:
                    f.write(
                        f"\n - {issue}"
                    )

            if device.get("actions_taken"):

                f.write("\nActions Taken:")

                for action in device["actions_taken"]:
                    f.write(
                        f"\n - {action}"
                    )

        f.write("\n")
def main_process(device):
	device_ip = device.get("device_ip")
	adapter = logging.LoggerAdapter(logger, {'dev': device_ip})

	device_result = {
        "device_name": device.get("name"),
        "device_ip": device_ip,
        "hostname": None,

        "status": "COMPLIANT",

        "actions_taken": [],
        "events": [],

        "checks_passed": 0,
        "checks_failed": 0,

        "checks": {
            "vlans": None,
            "access_ports": None,
            "trunk_ports": None,
            "interfaces": None,
            "roas": None,
            "ospf": None,
            "ntp": None,
            "qos": None,
            "stp": None,
            "hsrp": None,
            "nat": None,
            "dhcp": None,
            "snmp": None,
            "syslog": None,
            "port_security": None,
            "dhcp_snooping": None,
            "dai": None,
            "cdp": None,
            "etherchannel": None,
            "static_routes": None
        },

        "initial_issues": [],
        "critical_issues": [],
        "warnings": [],

        "Remediation": {
            "attempted": False,
            "successful": False,
            "changes": []
        },

        "connection": {
            "transport": None,
            "method": None
        },

        "start_time": datetime.utcnow().isoformat(),
        "end_time": None,
        "duration_seconds": None,

        "errors": []
    }


    start = time.time()
	try: 
		with get_session(device) as session:
			device_result["connection"]["transport"] = session.transport 
			if session.transport == "NETMIKO":
				device_state = collect_device_state(
						session, adapter 
					)
			elif session.transport == "NETCONF": 
				device_state = collect_netconf_state(
						session, adapter
					)
			elif session.transport == "RESTCONF": 
				device_state = collect_restconf_state(
						session, adapter
					)
			else: 
				raise ValueError(
						f"Unsupported Transport {session.transport}"
					)

			device_result = run_pipeline(
					PIPELINE,
					device.get("context"),
	                session,
	                device_state,
	                device_result,
	                adapter
				)
	except Exception as e: 
		adapter.exception(
			    f"Main Process Try/Exception Error | {e}"
			)
		device_result["status"] = OperationalStatus.FAILED_VALIDATION.value
		device_result["errors"].append(e)

	finally:
		end = datetime.utcnow()

	    device_result["end_time"] = (
	        end.isoformat()
	    )

	    device_result["duration_seconds"] = (
	        end - datetime.fromisoformat(
	            device_result["start_time"]
	        )
	    ).total_seconds()


	    if device_result["critical_issues"]:
	        device_result["status"] = "NON-COMPLIANT"

	    elif device_result["status"] != "FAILED":
	        device_result["status"] = "COMPLIANT"

	return device_result
def main():

    main_log = logging.LoggerAdapter(
        logger,
        {"dev": "MAIN"}
    )

    main_log.info("----- STARTING HYBRID AUTOMATION -----")

    compliance_results = []

    try:

        inventory, config_data = get_netbox()

        main_log.info(
            "----- NETBOX SYNC SUCCESSFUL -----"
        )


        tasks = []

        for device in inventory:

            ip = device.get("host")

            config = config_data.get(ip)

            tasks.append(
                {
                    "device": device,
                    "context": copy.deepcopy(config) if config else {}
                }
            )


        num_workers = min(len(tasks), 15)


        with ThreadPoolExecutor(
            max_workers=num_workers
        ) as executor:


            run_it = [
                executor.submit(
                    main_process,
                    task
                )
                for task in tasks
            ]


            for future in as_completed(run_it):

                try:

                    result = future.result()

                    compliance_results.append(
                        result
                    )


                except Exception as e:

                    main_log.error(
                        f"Device Thread Failed: {e}"
                    )

                    compliance_results.append(
                        {
                            "status": "FAILED",
                            "error": str(e)
                        }
                    )



        report = {

            "run_metadata": {

                "timestamp": datetime.utcnow().isoformat(),

                "total_devices": len(inventory),

                "successful_runs": len(
                    [
                        r for r in compliance_results
                        if r.get("status") != "FAILED"
                    ]
                )

            },


            "devices": compliance_results,


            "summary": {

                "compliant": len(
                    [
                        r for r in compliance_results
                        if r.get("status") == "COMPLIANT"
                    ]
                ),


                "non_compliant": len(
                    [
                        r for r in compliance_results
                        if r.get("status") == "NON-COMPLIANT"
                    ]
                ),


                "failed": len(
                    [
                        r for r in compliance_results
                        if r.get("status") == "FAILED"
                    ]
                )

            }

        }


        with open(
            "final_compliance_report.json",
            "w"
        ) as f:

            json.dump(
                report,
                f,
                indent=4,
                default=str
            )


        generate_manager_report(report)


        main_log.info(
            "Final Compliance Report Saved Successfully"
        )


    except Exception as e:

        main_log.exception(
            f"Main Automation Failed: {e}"
        )


    finally:

        final_log = logging.LoggerAdapter(
            logger,
            {"dev": "FINAL"}
        )

        final_log.info(
            "----- AUTOMATION COMPLETE -----"
        )
if __name__ == "__main__":
    main()
