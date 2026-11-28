from collections import defaultdict
import ipaddress
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
		}
	return device_interfaces, interface_ip, subnet_ip, ospf_config_by_interface, vlan_by_id