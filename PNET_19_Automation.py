import ipaddress
import requests
import pynetbox
from genie.gre import defaultdict
from typing import Dict, Tuple

from numpy.array_api import arange

netbox_url = "http://localhost:8000"
netbox_token = "nbt_L1ftoLIovB88.ekppmGP1Px2iBdcV01Tc799oH17Zrmip0La1yUKj"
def build_index(interfaces, ip_addresses, vlans):
    interfaces_on_device = defaultdict(list)
    ip_on_interface = defaultdict(list)
    ip_in_subnet = defaultdict(list)
    ospf_config_by_interface = defaultdict(list)
    vlan_by_id = {}

    for interface in interfaces:
        if hasattr(interface, "device") and interface.device:
            interfaces_on_device[interface.device.id].append(interface)
        if interface.custom_fields.get("ospf_enabled"):
        ospf_config_by_interface[interface.id] = {
            "process_id": interface.custom_fields.get("ospf_process_id", 1),
            "area_id": interface.custom_fields.get("ospf_area_id", 0),
            "network_type": interface.custom_fields.get("ospf_network_type", "ospf-broadcast"),
            "hello_interval": interface.custom_fields.get("ospf_hello_interval", 10),
            "dead_interval": interface.custom_fields.get("ospf_dead_interval", 40),
            "auth_type": interface.custom_fields.get("ospf_auth_type", "none"),
            "expected_dr": interface.custom_fields.get("ospf_expected_dr"),
            "expected_bdr": interface.custom_fields.get("ospf_expected_bdr"),
        }
    for ip in ip_addresses:
        if hasattr(ip, "assigned_object_id") and ip.assigned_object_id:
            ip_on_interface[ip.assigned_object_id].append(ip)
        ip_address = ipaddress.ip_interface(str(ip.address))
        subnet = str(ip_address.network.network_address)
        ip_in_subnet[subnet].append(ip)
    for v in vlans:
        vlan_by_id[v.id] = v

        return interfaces_on_device, ip_on_interface, ip_in_subnet, vlan_by_id, ospf_config_by_interface

def get_netbox():
    nb = pynetbox.api(url=netbox_url, token=netbox_token)
    inventory = []
    config_data = {
        "vlans":[],
        "access_ports":[],
        "trunk_ports":[],
        "interface":[],
        "roass":[],
        "ospf":[]
    }
    all_devices = list(nb.dcim.devices.filter(status="active"))
    all_interfaces = list(nb.dcim.interfaces.all())
    all_ip_addresses = list(nb.ipam.ip_addresses.all())
    all_vlans = list(nb.dcim.vlans.all())

    interface_on_device, ip_on_interface, ip_in_subnet, vlan_by_id, ospf_config_by_interface = build_index(
        all_interfaces, all_ip_addresses, all_vlans)

    for device_name in all_devices:
        if not device_name.platform.slug or not device_name.primary_ip:
            continue
        host_ip = str(device_name.primary_ip.address.split('/')[0])
        inventory.append({
            'device':host_ip,
            'device_type':device_name.platform.slug,
            'name':device_name.name,
            'username':'sysadmin',
            'password':'ccna',
            'secret':'ccna'
        })
        is_switch = device_name.role.slug == "switch"
        is_router = device_name.role.slug == "router"
        ospf_process = {}
        device_vlans = {}
        for device_interface in interface_on_device(device_name.id, []):
            tags = [t.slug for t in device_interface.tags]

            if is_switch:
                if device_interface.mode and device_interface.mode.value == "access":
                    if device_interface.untagged_vlan:
                        config_data["access_ports"].append({
                            'device':host_ip,
                            'access_interface':device_interface.name,
                            'access_vlan': int(device_interface.untagged_vlan.vid)
                        })
                        v = device_interface.untagged_vlan
                        device_vlans[v.id] = v
                if device_interface.mode and device_interface.mode.value == "tagged":
                    if device_interface.tagged_vlans:
                        vlan_list = ",".join([str(v.vid) for v in device_interface.tagged_vlans])
                        config_data['trunk_ports'].append({
                            'device':host_ip,
                            'trunk_interface':device_interface.name,
                            'allowed_vlans': vlan_list
                        })
                        for v in device_interface.tagged_vlans:
                            device_vlans[v.vid] = v
            if is_router:
                if device_interface.type and device_interface.type.value not in ["virtual", "lag", "bridge"]
                    config_data['interface'].append({
                        'device':host_ip,
                        'r_interface': device_interface.name
                    })
                router_ips = ip_on_interface(device_interface.id, [])
                for rip in router_ips:
                    r_ip = ipaddress.ip_interface(str(rip.address))
                    if "roas" in tags:
                        if device_interface.type and device_interface.type.value == "virtual":
                            for v in device_interface.tagged_vlans:
                                config_data['roass'].append({
                                    'device':host_ip,
                                    'router_interface':device_interface.name,
                                    'router_vlan': int(v.vid),
                                    'ip': str(r_ip.ip),
                                    'mask': str(r_ip.netmask)
                                })
                    ospf_config = ospf_config_by_interface.get(device_interface.id)
                    if "ospf" in tags and ospf_config:
                        proc_id = ospf_config["process_id"]
                        area_id = ospf_config["area_id"]

                        if proc_id not in ospf_process:
                            ospf_process[proc_id] = {
                                "interfaces": {},
                                "router_id": None,
                                "auth_type": ospf_config["auth_type"],
                            }
                        if device_interface.name not in ospf_process[proc_id]["interfaces"]:
                            ospf_process[proc_id]["interfaces"][device_interface.name] = {
                                "subnet": str(r_ip.network.network_address),
                                "wildcard": str(r_ip.network.hostmask),
                                "area": int (area_id),
                                "ospf_interface": device_interface.name,
                                "expected_dr": ospf_config["expected_dr"],
                                "expected_bdr": ospf_config["expected_bdr"],
                                "network_type": ospf_config["network_type"],
                                "hello_interval": ospf_config["hello_interval"],
                                "dead_interval": ospf_config["dead_interval"],
                                "auth_type": ospf_config["auth_type"],
                                "auth_algorithm": ospf_config["auth_algoritm"],
                                "auth_key_id": ospf_config["ospfv2-crypto-md5"],
                                "expected_neighbors": set(),
                                "actual_neighbors": set()
                            }
                            current_subnet = str(r_ip.network.network_address)
                            ospf_ips = ip_in_subnet.get(current_subnet, [])
                            for ospf_ip in ospf_ips:
                                ospf_ip_add = str(ospf_ip.address).split('/')[0]
                                if str(r_ip.ip) != ospf_ip_add:
                                    ospf_process[proc_id]["interfaces"][device_interface.name]["expected_neighbors"].add(ospf_ip_add)
        if is_router and ospf_process:
            context = device_name.config_context.get("ospf", {})
            for proc_id, data in ospf_process.items():
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
                        "expected_neighbors": interface_data.get("expected_neighbors")
                    }
                    config_data['ospf'].append({
                        'device': host_ip,
                        'process_id': int(proc_id),
                        'router_id': context.get(int(proc_id), {}).get("router_id",""),
                        'auth_type': data.get("auth_type", "none"),
                        'hello_interval': interface_data.get("hello_interval", 10),
                        'dead_interval': interface_data.get("dead_interval", 40 ),
                        'interfaces': interfaces_payload,
                        'network_list': [
                            {
                                "subnet": interface.get("subnet"),
                                "wildcard": interface.get("wildcard"),
                                "area": interface.get("area"),
                                "interface": interface.get("name")
                            }
                            for interface in interfaces_payload.values()
                        ],
                    })
        # if is_switch:
        #     for vlan_id in device_vlans.values():
        #         config_data["vlans"].append({
        #             'device':host_ip,
        #             'vlan_id': int(vlan_id.vid),
        #             'name': vlan_id.name
        #         })





    return inventory, config_data

def collect_device_state(conn):
    device_state = {}
    try:
        device_state["vlans"] = conn.send_command("show vlan", use_genie=True)
    except Exception:
        device_state["vlan"] = {}
    try:
        device_state["switchports"] = conn.send_command("show interfaces switchport", use_genie=True)
    except Exception:
        device_state["switchports"] = {}
    try:
        device_state["interfaces"] = conn.send_command("show ip interface brief", use_genie=True)
    except Exception:
        device_state["interfaces"] = {}
    return device_state
def check_vlan(device_state, vlan_id, name):
    vlan_string = str(vlan_id)
    vlans_device_state = device_state.get("vlans", {}).get("vlans", {})
    vlan_data = vlans_device_state.get(vlan_string, {})
    vlan_name = vlan_data.get("name", "")
    return vlan_name == name
def check_switch_mode(device_state, switch_interface, mode, vlan_or_allowed):
    switchports = device_state.get("switchports", {})
    switchport_data = switchports.get(switch_interface, {})
    operational_mode = switchport_data.get("operational_mode", "")
    access_vlan = switchport_data.get("access_vlan", "")
    trunk_vlans = switchport_data.get("trunk_vlans", "")
    if mode == "access":
        return "access" in operational_mode and str(access_vlan) == str(vlan_or_allowed)
    if mode == "trunk":
        return "trunk" in operational_mode and str(vlan_or_allowed) in str(trunk_vlans)
    return False
def check_interface(device_state, r_interface):
    interfaces = device_state.get("interfaces", {})
    status = interfaces.get(r_interface, {}).get("status", "")
    protocol = interfaces.get(r_interface, {}).get("protocol", "")
    return status == "up" and protocol is "up"
def restconf_state(device_ip, auth, log):
    headers = {"Accept": "application/yang-data+json"}
    session = requests.Session()
    session.auth = auth
    session.verify = False
    session.headers.update(headers)

    state = {}
    try:
        #################### Interfaces ####################
        interface_url = (
            f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/interface"
        )
        response = session.get(interface_url, timeout=20)
        state["interface_restconf"] = (
            response.json()
            if response.status_code in [200,201,204] else {}
        )
        ####################### OSPF CONFIG ###############################
        ospf_url = (
            f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/router"
        )
        response = session.get(ospf_url, timeout=20)
        state["ospf_restconf"] = (
            response.json()
            if response.status_code in [200,201,204] else {}
        )
        ##################### OSPF OPER ##########################
        ospf_oper_url = (
            f"https://{device_ip}/restconf/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data"
        )
        response = session.get(ospf_oper_url, {})
        state["ospf_oper_restconf"] = (
            response.json()
            if response.status_code in [200,201,204] else {}
        )
    except Exception as e:
        log.info(f"ERROR AT RESTCONF Configuration Collection: {e}")
    finally:
        session.close()
    return state
def check_roas(restconf_state, roas_data):
    interface_data = restconf_state.get("interface_restconf", {})
    router_interface = roas_data["router_interface"]
    router_vlan = roas_data["router_vlan"]
    ip = roas_data["ip"]
    n_interface = "".join([c for c in router_interface if c.isdigit() or c == "/" or c =="."])

    GigabitEthernet = interface_data.get("Cisco-IOS-XE-native:interface", {}).get("GigabitEthernet", [])
    for gig in GigabitEthernet:
        if gig.get("name") == n_interface:
            vlan_id = (
                gig.get("encapsulation", {})
                .get("dot1Q", {})
                .get("vlan-id", "")
            )
            ip_add = (
                gig.get("ip", {})
                .get("address", {})
                .get("primary", {})
                .get("address", "")
            )
            return str(vlan_id) == str(router_vlan) and str(ip) == str(ip_add)
    return False
def check_ospf(restconf_state, ospf_data):
    process_id = ospf_data["process_id"]
    router_id = ospf_data["router_id"]
    network_list = ospf_data["network_list"]
    ospf_config = restconf_state.get("ospf_restconf")
    processes = (
        ospf_config.get("Cisco-IOS-XE-native:router", {})
        .get("Cisco-IOS-XE-ospf:router-ospf", {})
        .get("ospf", {})
        .get("process-id", [])
    )
    for process in processes:
        proc_id = process.get("id", "")
        r_id = process.get("router-id", "")

        if str(proc_id) == str(process_id):
            if str(r_id) != str(router_id):
                return False

            network = process.get("network", [])
            for net_list in network_list:
                net_ip = net_list.get("subnet", "")
                net_wildcard = net_list.get("wildcard", "")
                net_area = net_list.get("area", "")
                found = False
                for net in network:
                    ospf_ip = net.get("ip", "")
                    ospf_wildcard = net.get("wildcard", "")
                    ospf_area = net.get("area", "")
                    if (
                        str(net_ip) == str(ospf_ip) and
                        str(net_wildcard) == str(ospf_wildcard) and
                        str(net_area) == str(ospf_area)
                        ):
                        found = True
                        break
                if not found:
                    return False

    return True

class OSPF_Checker:
        def check_ospf_config(self, restconf_state: Dict, ospf_data: Dict)-> bool:
            try:
                process_id = ospf_data.get("process_id")
                router_id = ospf_data.get("area_id")
                network_list = ospf_data.get("network_list")
                ospf_config = restconf_state.get("ospf_restconf", {})
                processes = (
                    ospf_config.get("Cisco-IOS-XE-native:router", {})
                    .get("Cisco-IOS-XE-ospf:router-ospf", {})
                    .get("ospf", {})
                    .get("process-id", [])
                )
                for process in processes:
                    found = None
                    r_id = process.get("router-id", "")
                    if str(process.get("id", "")) != str(process_id):
                        continue
                    if str(r_id) != str(router_id):
                        self.log.warning(
                            f"Router ID mismatch: Expected: {router_id}, Received {r_id} instead."
                        )
                        return False
                    for net_list in network_list:
                        ospf_ip = net_list.get("subnet", "")
                        ospf_wildcard = net_list.get("wildcard", "")
                        ospf_area = net_list.get("area", "")
                        found = False
                        network = process.get("network", [])
                        for net in network:
                            conf_ip = net.get("ip", "")
                            conf_wildcard = net.get("wildcard", "")
                            conf_area = net.get("area", "")
                            if (
                                str(ospf_ip) == str(conf_ip)
                                and str(ospf_wildcard) == str(conf_wildcard)
                                and str(ospf_area) == str(conf_area)
                            ):
                                found = True
                                break
                        if not found:
                            self.log.warning(
                                f"OSPF Network Not Configured. Subnet: {ospf_ip}/{ospf_wildcard} area {ospf_area}"
                            )
                            return False
                    return True
                self.log.warning(f"Process {process_id} not found in OSPF Configuration.")
                return False
            except Exception as e:
                self.log.error(f"OSPF Configuration Check Failed: {e} ...")
                return False
        def check_ospf_operational(self, restconf_state: Dict, ospf_data: Dict) -> bool:
            try:
                process_id = ospf_data.get("process_id", "")
                area_id = ospf_data.get("area_id", "")
                device_ip = ospf_data.get("device", "")
                ospf_oper = (
                    restconf_state.get("ospf_oper_restconf", {})
                    .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})
                )
                ospfv2_instances = ospf_oper.get("ospfv2-instance", [])
                if isinstance(ospfv2_instances, dict):
                    ospfv2_instances = [ospfv2_instances]
                for ospfv2_instance in ospfv2_instances:
                    if ospfv2_instance.get("instance-id") != process_id:
                        continue
                    areas = ospfv2_instance.get("ospfv2-area", [])
                    if isinstance(areas, dict):
                        areas = [areas]

                    r_id = ospfv2_instance.get("router-id", "")
                    if not r_id:
                        self.log.error(f"OSPF Process not initialized (no router-id)")
                        return False
                    try:
                        rid = ipaddress.IPv4Address(int(r_id))
                    except ValueError:
                        rid = ipaddress.IPv4Address(r_id)
                    self.log.info(f"OSPF process running. RID: {rid}")

                    if not areas:
                        self.log.warning(f"No areas are configured.")
                        return False
                    for area in areas:
                        area_id = area.get("area-id", "")
                        lsdb = area.get("ospfv2-lsdb-area", [])

                        ospf_interfaces = area.get("ospfv2-interface", [])
                        if isinstance(ospf_interfaces, dict):
                            ospf_interfaces = [ospf_interfaces]
                        active_interfaces = [
                            interface
                            for interface in ospf_interfaces
                            if not interface.get("passive", False)
                        ]
                        if active_interfaces and not lsdb:
                            self.log.error(
                                f"Area {area_id}: Has {len(active_interfaces)} active interfaces"
                                f"but no LSAs in the database. Neighbors are not forming."
                            )
                            return False
                        if not active_interfaces and not lsdb:
                            self.log.info(
                                f"Area {area_id}: No active interfaces (all passive/stub)"
                                f"No LSAs expected"
                            )
                            return True
                        if lsdb:
                            lsa_count = len(lsdb)
                            self.log.info(f"Area {area_id}: {lsa_count} LSAs in the Link State Database")

                            ages = [
                                int(lsa.get("lsa-age", 0))
                                for lsa in lsdb
                            ]
                            max_age = max(ages) if ages else 0
                            if max_age > 3600:
                                self.log.warning(
                                    f"Device at {device_ip}| Process: {process_id}| Area: {area_id}|"
                                    f"LSA age {max_age}s (very old), Network may be stale."
                                )
                            return True
                    return True
                self.log.warning(f"Process {process_id} not found in operational data.")
                return False
            except Exception as e:
                self.log.error(f"OSPF Operation Check Failed: {e}", exc_info=True)
                return False
        def verify_ospf_neighbors(self, restconf_state: Dict, ospf_data: Dict) -> bool:
            try:
                device_ip = ospf_data.get("device", "")
                process_id = ospf_data.get("process_id", "")
                expected_neighbors = set(ospf_data.get("expected_neighbors", []))
                network_type = ospf_data.get("network_type", "ospf-broadcast").lower()
                if not expected_neighbors:
                    self.log.warning(f"[{device_ip}] No expected Neighbors")
                    return True
                self.log.info(f"[{device_ip}] Expecting {len(expected_neighbors)} neighors: {expected_neighbors}")

                ospf_oper_data = (
                    restconf_state.get("ospf_oper_restconf", {})
                    .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})
                )
                ospfv2_instances = ospf_oper_data.get("ospfv2-instance", [])
                if isinstance(ospfv2_instances, dict):
                    ospfv2_instances = [ospfv2_instances]
                actual_neighbors = {}
                for ospfv2_instance in ospfv2_instances:
                    if str(ospfv2_instance.get("instance-id", "")) != str(process_id):
                        continue
                    areas = ospfv2_instance.get("ospfv2-area", [])
                    if isinstance(areas, dict):
                        areas = [areas]
                    for area in areas:
                        interfaces = area.get("ospfv2-interface", [])

                        if isinstance(interfaces, dict):
                            interfaces = [interfaces]
                        for interface in interfaces:
                            interface_name = interface.get("name", "")
                            dr_ip = interface.get("dr-ip")
                            bdr_ip = interface.get("bdr-ip")

                            neighbors = interface.get("ospfv2-neighbor", [])
                            if isinstance(neighbors, dict):
                                neighbors = [neighbors]
                            for nbr in neighbors:
                                nbr_ip = nbr.get("address")
                                state = str(nbr.get("state", "")).lower()
                                nbr_id = nbr.get("nbr-id", "")
                                if "point-to-point" in network_type:
                                    if "full" not in state:
                                        self.log.error(f"[{device_ip}] {interface_name}: {nbr_ip}"
                                                       f"state= {state} - MUST be FULL on point to point links.")
                                        continue
                                    actual_neighbors[nbr_ip] = {
                                        "role": "peer",
                                        "state": state,
                                        "interface": interface_name,
                                        "nbr_id": nbr_id
                                    }
                                    continue

                                if "full" in state or "two-way" in state:
                                    if "broadcast" in network_type:
                                        if nbr_ip == dr_ip:
                                            role = "DR"
                                        elif nbr_ip == bdr_ip:
                                            role = "BDR"
                                        else:
                                            role = "DROTHER"

                                        if role in ["DR", "BDR"]:
                                            if "full" not in state:
                                                self.log.warning(
                                                    f"[{device_ip}] {interface_name}: {nbr_ip} {role}"
                                                    f"state= {state} - *** SHOULD BE FULL ***"
                                                    f"(MTU/timer/authentication mismatch?)"
                                                )
                                                continue
                                            actual_neighbors[nbr_ip] = {
                                                "role": role,
                                                "state": state,
                                                "interface": interface_name,
                                                "nbr_id": nbr_id
                                            }
                                        elif role in ["DROTHER"]:
                                            if "full" in state or "two-way" in state or "2-way" in state:
                                                actual_neighbors[nbr_ip] = {
                                                "role": role,
                                                "state": state,
                                                "interface": interface_name,
                                                "nbr_id": nbr_id
                                                }
                                            else:
                                                self.log.warning(
                                                    f"[{device_ip}] {interface_name}: {nbr_ip} ({role})"
                                                    f"state= {state} (*** SHOULD BE FULL OR TWO-WAY ***)"
                                                )
                actual_ips = set(actual_neighbors.keys())
                missing = expected_neighbors - actual_ips
                extra = actual_ips - expected_neighbors

                self.log.info(f"[{device_ip}] Found {len(actual_neighbors)} neighbors in proper state.")
                if missing:
                    self.log.error(f"[{device_ip}] x Missing or not fully adjacent neighbors: {missing}")
                    return False
                if extra:
                    self.log.error(f"[{device_ip}] x Found a neighbor not found in Source Of Truth. Neighbrors: {extra}")
                    return False
                self.log.info(f"[{device_ip}] All expected neighbors healthy.")
                return True
            except Exception as e:
                self.log.error(
                    f"[{device_ip}] OSPF Neighbor Validation failed. {e}", exc_info=True
                )
                return False
        def verify_ospf_timers(self, restconf_state: Dict, ospf_data: Dict) -> bool:
            device_ip = ospf_data.get("device", "")
            try:
                interfaces_config = ospf_data.get("interfaces", {})
                if not interfaces_config:
                    return True
                self.log.info(f"[{device_ip}] Validating OSPF Timers for {len(interfaces_config)} interfaces.")
                all_timers_valid = True
                oper_interfaces = {}
                process_id = ospf_data.get("process_id", 1)
                # self.log.info(f"[{device_ip}] Validating Timers:"
                #               f"Expected Hello: {expected_hello}| Expected Dead: {expected_dead}")

                ospf_oper = (
                    restconf_state.get("ospf_oper_restconf", {})
                    .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})
                )
                instances = ospf_oper.get("ospfv2-instance", [])
                if isinstance(instances, dict):
                    instances = [instances]
                for instance in instances:
                    if int(instance.get("instance-id")) != int(process_id):
                        continue
                    areas = instance.get("ospfv2-area", [])
                    if isinstance(areas, dict):
                        areas = [areas]
                    for area in areas:
                        interfaces = area.get("ospfv2-interface", [])
                        if isinstance(interfaces, dict):
                            interfaces = [interfaces]
                        for ospf_interface in interfaces:
                            interface_name = ospf_interface.get("name", "")
                            oper_interfaces [interface_name]= {
                                "actual_hello": int(ospf_interface.get("hello-interval")or 0),
                                "actual_dead": int(ospf_interface.get("dead-interval") or 0),
                                "passive": ospf_interface.get("passive", False )

                            }
                for interface_name, interface_values in interfaces_config.items():
                    expected_hello = int(interface_values.get("hello_interval", 10 ))
                    expected_dead = int(interface_values.get("dead_interval", 40))
                    if interface_name not in oper_interfaces:
                        self.log.error(
                            f"[{device_ip}] {interface_name}: Not found in operational data"
                        )
                        all_timers_valid = False
                        continue
                    oper_interface = oper_interfaces[interface_name]
                    if oper_interface["passive"]:
                        self.log.info(
                            f"[{device_ip}] {interface_name}: Passive Interface (skipping timer check)"
                        )
                        continue
                    actual_hello = oper_interface["actual_hello"]
                    actual_dead = oper_interface["actual_dead"]
                    if (
                        expected_hello != actual_hello or expected_dead != actual_dead
                    ):
                        self.log.error(
                            f"[{device_ip}] {interface_name}: Timer Mismatch|"
                            f"Expected Hello: {expected_hello}| Expected Dead: {expected_dead}|"
                            f"Actual Hello: {actual_hello}| Actual Dead: {actual_dead}"
                        )
                        all_timers_valid = False
                if not all_timers_valid:
                    return False
                self.log.info(f"[{device_ip}] All OSPF Hello/Dead Timers Correct")
                return True
            except Exception as e:
                self.log.error(f"[{device_ip}] Could not verify OSPF Hello/Dead Timers: {e}")
                return False
        def verify_opsf_mtu(self, restconf_state: Dict, ospf_data: Dict) -> bool:
            try:
                interfaces_config = ospf_data.get("interfaces", {})
                device_ip = ospf_data.get("device", "")
                if not interfaces_config:
                    self.log.warning(f"[{device_ip}] No Interfaces Configured")
                    return True
                interfaces_oper = (
                    restconf_state.get("interface_oper_restconf", {})
                    .get("Cisco-IOS-XE-interfaces-oper:interfaces", {})
                )
                operational_interfaces = interfaces_oper.get("interfaces", [])
                if isinstance(operational_interfaces, dict):
                    operational_interfaces = [operational_interfaces]

                mtu_map = {}
                for operational_interface in operational_interfaces:
                    interface_name_oper = operational_interface.get("name", "")
                    interface_mtu_oper = operational_interface.get("mtu", "")
                    if interface_mtu_oper is not None and interface_name_oper:
                        try:
                            mtu_map[interface_name_oper] = int(interface_mtu_oper)
                        except (ValueError, TypeError):
                            self.log.warning(
                                f"[{device_ip}] {interface_name_oper}: Failed To parse MTU value: {interface_mtu_oper}"
                                f"from operational data"
                            )

                ospf_oper = (
                    restconf_state.get("ospf_oper_restconf", {})
                    .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})

                )
                instances = ospf_oper.get("ospfv2-instance", [])
                if isinstance(instances, dict):
                    instances = [instances]
                mtu_mismatch_issues = []
                for instance in instances:
                    areas = instance.get("ospfv2-area", [])
                    if isinstance(areas, dict):
                        areas = [areas]
                    for area in areas:
                        interfaces = area.get("ospfv2-interface", [])
                        if isinstance(interfaces, dict):
                            interfaces = [interfaces]
                        for interface in interfaces:
                            interface_name = interface.get("name")
                            mtu_ignore = interface.get("mtu-ignore", False)

                            if interface_name not in interfaces_config:
                                continue
                            expected_mtu = interfaces_config[interface_name].get("expected_mtu")
                            actual_mtu = mtu_map.get(interface_name)

                            if expected_mtu is None:
                                self.log.debug(
                                    f"[{device_ip}] {interface_name}: No Expected MTU in SOT"
                                    f"skipping MTU Validation"
                                )
                            elif actual_mtu is None:
                                self.log.warning(
                                    f"[{device_ip}] {interface_name}: Expected MTU: {expected_mtu}"
                                    f"but can't find actual MTU in operational data"
                                )
                            else:
                                mtu_match = expected_mtu == actual_mtu

                                if not mtu_match:
                                    self.log.warning(
                                        f"[{device_ip}] {interface_name}: MTU Mismatch|"
                                        f"Expected MTU: {expected_mtu}| Actual MTU: {actual_mtu}"
                                    )
                                    if mtu_ignore:
                                        self.log.warning(
                                            f"[{device_ip}] {interface_name}: Mismatch allowed"
                                            f"(mtu-ignore enabled) - monitor for packet loss"
                                        )
                                    else:
                                        self.log.error(
                                            f"[{device_ip}] {interface_name}: x MTU Mismatch"
                                            f"and (mtu-ignore) DISABLED - adjacency will fail"
                                        )
                                        mtu_mismatch_issues.append(interface_name)
                                else:
                                    self.log.debug(
                                        f"[{device_ip}] {interface_name}: MTU Matches|"
                                        f"Expected MTU: {expected_mtu}| Actual MTU: {actual_mtu}"
                                    )
                if mtu_mismatch_issues:
                    self.log.error(
                        f"[{device_ip}] MTU Mismatches Found|"
                        f"Interfaces: {','.join(mtu_mismatch_issues)}"
                    )
                    return False
                self.log.info(f"[{device_ip}] MTU Validation Test Successfully Finished.")
                return True
            except Exception as e:
                self.log.error(f"[{device_ip}] x MTU Validation Tests via RESTCONF Failed: {e}")
                return False
        def veify_ospf_auth(self, device_ip: str, restonf_state: Dict, ospf_data: Dict) -> bool:
            try:
                interfaces_config = ospf_data.get("interfaces", {})
                if not interfaces_config:
                    self.log.warning(f"[{device_ip}] No interfaces found on NetBox...")
                    return True
                ospf_oper = (
                    restconf_state.get("ospf_oper_restconf", {})
                    .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})
                )
                ospf_instances = ospf_oper.get("ospfv2-instance", [])
                if isinstance(ospf_instances, dict):
                    ospf_instances = [ospf_instances]

                critical_issues = []
                degraded_issues = []
                info_messages = []
                sot_interfaces_found = set()
                for ospf_instance in ospf_instances:
                    ospf_areas = ospf_instance.get("ospfv2-area", [])
                    if isinstance(ospf_areas, dict):
                        ospf_areas = [ospf_areas]
                    for ospf_area in ospf_areas:
                        oper_interfaces = ospf_area.get("ospfv2-interface", [])
                        if isinstance(oper_interfaces, dict):
                            oper_interfaces = [oper_interfaces]
                        for oper_interface in oper_interfaces:
                            interface_name = oper_interface.get("name", "")
                            is_passive = oper_interface.get("passive", False)

                            if interface_name in interfaces_config:
                                sot_interfaces_found.add(interface_name)

                                auth_issues = self.validate_interface_auth(
                                    device_ip,
                                    interface_name,
                                    oper_interface,
                                    interfaces_config[interface_name]
                                )
                                if auth_issues:
                                    critical_issues.extend(auth_issues)
                            else:
                                if is_passive:
                                    info_messages.append(
                                        f"{interface_name}: (ROGUE INTERFACE) Passive OSPF interface not documented in NetBox"
                                    )
                                else:
                                    critical_issues.append(
                                        f"{interface_name}: (ROGUE INTERFACE): Active OSPF interfaace not found in NetBox"
                                    )
                missing_interfaces = set(interfaces_config.keys()) - sot_interfaces_found
                if missing_interfaces:
                    for missing_interface in missing_interfaces:
                        degraded_issues.append(
                            f"{missing_interface}: (MISSING INTERFACE) Interface configured in NetBox"
                            f"but not found in OSPF Operational Data"
                        )
                if info_messages:
                    self.log.info(f"[{device_ip}] Informational Messages:")
                    for msg in info_messages:
                        self.log.info(f"[{device_ip}] {msg}")
                if degraded_issues:
                    self.log.warning(f"[{device_ip}] Degraded State:")
                    for issue in degraded_issues:
                        self.log.warning(f"[{device_ip}] Issue: {issue}")
                if critical_issues:
                    self.log.error(f"[{device_ip}] x Critical Authentication Issues:")
                    for issue in critical_issues:
                        self.log.error(f"[{device_ip}] Issue: {issue}")
                    return False
                self.log.info(f"[{device_ip}] Authentication Validation Test Passed. No issues found.")
                return True
            except Exception as e:
                self.log.exception(f"[{device_ip}] OSPF Authentication Validation Check Failed")
                return False
        def validate_interface_auth(self, device_ip: str, interface_name: str, oper_interface: Dict,
                                    interfaces_config: Dict
                                    ) -> list:
            issues = []
            expected_auth_type = interfaces_config.get("auth_type", "none")
            expected_key_id = interfaces_config.get("auth_key_id")

            auth_val = oper_interface.get("auth-val", {})
            auth_key = auth_val.get("auth-key", {})

            if expected_auth_type == "none":
                if auth_key:
                    issues.append(f"{interface_name}: Expected NO authentication, but auth-key is configured."
                                  f"Please check authentication on device.")
                return issues
            if expected_auth_type not in ["md5", "sha256"]:
                self.log.warning(
                    f"[{device_ip}] {interface_name}: Unknown Authentication Type Found in NetBox|"
                    f"Auth Type: {expected_auth_type}"
                )
                return []
            if not auth_key:
                issues.append(
                    f"{interface_name}: Not auth-key found (meaning potentially no authentication configured.)"
                    f"Expected Auth: {expected_auth_type}"

                )
                return issues

            actual_algo = auth_key.get("crypto-algo", "").lower()
            if expected_auth_type == "md5":
                if "md5" not in actual_algo:
                    issues.append(f"{interface_name}: Authentication Mismatch|"
                                  f"Expected: MD5| Actual: {actual_algo}")
                    return issues
            elif expected_auth_type == "sha256":
                if "sha256" not in actual_algo and "sha-256" not in actual_algo:
                    issues.append(f"{interface_name}: Authentication Mismatch|"
                                  f"Expected: SHA265| Actual: {actual_algo}")
                    return issues
            actual_key_id = auth_key.get("key-id")
            if expected_key_id is not None:
                if actual_key_id is None:
                    issues.append(
                        f"{interface_name}: No key-id found in operational data|"
                        f"Expected Key-ID: {expected_key_id}"
                    )
                    return issues
                try:
                    if int(actual_key_id) != int(expected_key_id):
                        issues.append(
                            f"{interface_name}: Key-ID mismatch|"
                            f"Expected Key-ID: {expected_key_id}| Actual Key-ID: {actual_key_id} "
                        )
                except (ValueError, TypeError):
                    issues.append(
                        f"{interface_name} TRY Failure: Could not parse integer (Value Error or Type Error"
                    )
                    return issues
            return issues
        def check_lsa_age(self,device_ip, restconf_state: Dict, ospf_data: Dict) -> Tuple[str, int]:
            try:
                all_ages = []
                ospf_oper = (
                    restconf_state.get("ospf_oper_restconf", {})
                    .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})
                )
                instances = ospf_oper.get("ospfv2-instance", [])
                if isinstance(instances, dict):
                    instances = [instances]
                for instance in instances:
                    areas = instance.get("ospfv2-area", [])
                    if isinstance(areas, dict):
                        areas = [areas]
                    for area in areas:
                        lsdbs = area.get("ospfv2-lsdb-area", [])
                        for lsdb in lsdbs:
                            ls_age = lsdb.get("lsa-age")
                            try:
                                if ls_age is None:
                                    continue
                                all_ages.append(int(ls_age))
                            except (ValueError, TypeError):
                                self.log.warning(f"[{device_ip}] Try Exception Error|"
                                                 f"LS Age| Code: all_ages.append(ls_age)")
                                continue
                if not all_ages:
                    return "unknown", 0
                max_age = max(all_ages)
                if max_age < 300:
                    self.log.info(f"[{device_ip}] OSPF LSAs Healthy|"
                                  f"Max Age in LSDB: {max_age}")
                    return "healthy", max_age
                elif max_age < 3600:
                    self.log.warning(f"[{device_ip}] OSPF LSAs are degraded|"
                                     f"Max Age in LSDB: {max_age}")
                    return "degraded", max_age
                self.log.warning(f"[{device_ip}] OSPF LSAs are older/stale|"
                                 f"Max Age in LSDB: {max_age}")
                return "stale", max_age
            except Exception as e:
                self.log.error(f"[{device_ip}] Try Exception Error|"
                               f"Function: check_lsa_age", exc_info=True)
                return "error", 0







