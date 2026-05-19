import ipaddress
import requests
import pynetbox
from genie.gre import defaultdict
from typing import Dict, Tuple
import graypy
import logging
from numpy.array_api import arange
from dataclasses import dataclass
from typing import Literal

from websocket import continuous_frame

logger = logging.getLogger("Networkautomation")
logger.setLevel(logging.DEBUG)
handler = graypy.GELFUDPHandler("127.0.0.1", 12201)
logger.addHandler(handler)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
logger.addHandler(console)
netbox_url = "http://localhost:8000"
netbox_token = "*****"
@dataclass
class ValidationIssue:
    device_ip: str
    interface: str
    severity: Literal["CRITICAL", "WARN", "INFO"]
    message: str
    code: str | None = None
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
def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
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
    def validate_device_ospf(self, device_ip: str, restconf_state: Dict, ospf_data: Dict) -> Dict:
        results = {
            "device": device_ip,
            "status": "HEALTHY",
            "checks":{
                "ospf_config_check": False,
                "lsdb_check": False,
                "ospf_neighbor_check": False,
                "timers_check": False,
                "authentication_check": False,
                "mtu_check": False,
                "lsa_age_check": False
            },
            "citical_issues": [],
            "warnings": [],
            "lsa_age_seconds": None

        }
        try:
            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "ospf_config_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Operational vs NetBox"
                }
            )
            try:
                config_ok = self.check_ospf_config(device_ip,restconf_state,ospf_data)
                results["checks"]["ospf_config_check"] = config_ok

                if config_ok:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "ospf_config_check",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF config Expected matches actual"
                        }
                    )
                else:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "config_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Config mismatch"
                        }
                    )
                    results["critical_issues"].append("config_mismatch")
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "check_name": "config_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "error": str(e),
                        "message": "Exception occurred during OSPF config validation"
                    },
                    exc_info=True
                )
                results["checks"]["ospf_config_check"] = False
                results["critical_issues"].append("config_check_exception")

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "lsdb_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF LSDB (not empty) "
                }
            )
            try:
                ospf_oper_ok = self.check_ospf_operational(device_ip, restconf_state, ospf_data)
                results["checks"]["lsdb_check"] = ospf_oper_ok

                if ospf_oper_ok:
                    logger.info(
                        "ospf_check",
                        extra= {
                            "device_ip": device_ip,
                            "check_name": "lsdb_check",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF LSDB is not empty. LSAs Found."
                        }
                    )
                else:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "lsdb_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF LSDB is empty (no LSAs found)"
                        }
                    )
                    results["critical_issues"].append("lsdb_failed")
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra = {
                        "device_ip": device_ip,
                        "check_name": "lsdb_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "error": str(e),
                        "message": "Try/Exception Error| LSDB Check | ospf_oper_ok "
                    },
                    exc_info=True
                )
                results["checks"]["lsdb_check"] = False
                results["critical_issues"].append("lsdb_check_exception")

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "neighbor_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Neighbors are in correct state. "
                }
            )
            try:
                nbr_ok = self.verify_ospf_neighbors(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_neighbor_check"] = nbr_ok

                if nbr_ok:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "neighbor_check",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF Neighbors are in a valid (expected) state."
                        }
                    )
                else:
                    logger.info(
                        "ospf_check",
                        extra = {
                            "device_ip": device_ip,
                            "check_name": "neighbor_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message" "OSPF Neighbor not in the correct (expected) state."
                        }
                    )
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra= {
                        "device_ip": device_ip,
                        "check_name": "neighbor_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "error": str(e),
                        "message": "Try/Exception Error | OSPF Neighbor Check | nbr_ok "
                    },
                    exc_info=True
                )
                results["check"]["ospf_neighbor_check"] = False
                results["critical_issues"].append("neighbor_check_exception")

        logger.info(
            "ospf_check",
            extra={
                "device_ip": device_ip,
                "check_name": "ospf_timer_check",
                "status": "CHECKING",
                "severity": "INFO",
                "component": "ospf_validator",
                "message": "Validating OSPF LSDB (not empty) "
            }
        )
        try:
            timer_ok = self.verify_ospf_timers(device_ip, restconf_state, ospf_data)
            results["check"]["timer_check"] = timer_ok

            if timer_ok:
                logger.info(
                    "ospf_check",
                    extra= {
                        "device_ip": device_ip,
                        "check_name": "ospf_timer_check",
                        "status": "PASS",
                        "severity": "INFO",
                        "component": "ospf_validator",
                        "message": "OSPF Timers (hello/dead) are valid. No mismatches."

                    }
                )
            else:
                logger.info(
                    "ospf_check",
                    extra=
                )


    def check_ospf_config(self, device_ip: str, restconf_state: Dict, ospf_data: Dict)-> bool:
        try:
            expected_process_id = ospf_data.get("process_id")
            if expected_process_id is None:
                self.log.error(
                    f"[{device_ip}] Missing process-id from NetBox"
                )
                return False
            expected_process_id = str(expected_process_id)
            expected_router_id = str(ospf_data.get("router_id"))
            network_list = ospf_data.get("network_list", [])
            ospf_config = restconf_state.get("ospf_restconf", {})
            processes = (
                ospf_config.get("Cisco-IOS-XE-native:router", {})
                .get("Cisco-IOS-XE-ospf:router-ospf", {})
                .get("ospf", {})
                .get("process-id", [])
            )
            if isinstance(processes, dict):
                processes = [processes]
            device_process = set()
            oper_network = []
            rogue_process = []
            validation_issues = []
            matching_process = None
            for oper_process in processes:
                oper_process_id = str(oper_process.get("id"))
                device_process.add(oper_process_id)
                if oper_process_id == expected_process_id:
                    matching_process = oper_process
            if not matching_process:
                self.log.error(
                    f"[{device_ip}] Expected OSPF process missing|"
                    f"Expected: {expected_process_id}"
                    )
                return False
            for oper_proc_id in device_process:
                if oper_proc_id != expected_process_id:
                    rogue_process.append(oper_proc_id)
            if rogue_process:
                validation_issues.append(
                    f"Rogue OSPF Process: {rogue_process}"
                )
            r_id = matching_process.get("router-id", "")
            if str(r_id) != str(expected_router_id):
                validation_issues.append(
                    f"Router-ID Mismatch|"
                    f"Expected: {expected_router_id}| Actual: {r_id}"
                    )
            network = matching_process.get("network", [])
            actual_networks = {
                (
                    str(n.get("ip", "")).strip(),
                    str(n.get("wildcard", "")).strip(),
                    str(n.get("area", "")).strip()
                )
                for n in network
            }
            expected_networks = {
                (
                    str(n.get("subnet", "")).strip(),
                    str(n.get("wildcard", "")).strip(),
                    str(n.get("area", "")).strip()
                )
                for n in network_list
            }
            missing_networks = expected_networks - actual_networks
            extra_networks = actual_networks - expected_networks

            for ip, wildcard, area in missing_networks:
                validation_issues.append(
                    f"Missing OSPF Network | "
                    f"Expected: {ip}/{wildcard} Area: {area}"
                )
            for ip, wildcard, area in extra_networks:
                validation_issues.append(
                    f"Undocumented OSPF Network: "
                    f"Actual: {ip}/{wildcard} Area: {area}"
                )
            if validation_issues:
                self.log.error(
                    f"[{device_ip}] OSPF Configuration Validation failed."
                )
                for issue in validation_issues:
                    self.log.error(
                        f"[{device_ip}] Issue: {issue}"
                    )
                return False
            self.log.info(
                f"[{device_ip}] OSPF Configuration Validation: Passed"
            )
            return True
        except Exception as e:
            self.log.exception(
                f"[{device_ip}] Try Exception Error|"
                f"Function: check_ospf_config| OSPF Configuration Validation"
            )
            return False
    def check_ospf_operational(self, device_ip: str, restconf_state: Dict, ospf_data: Dict) -> bool:
        try:
            process_id = ospf_data.get("process_id", "")
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
                        self.log.warning(
                            f"Area {area_id}: No active interfaces and no LSAs detectedd "
                            f"(could be all passive/stub OR misconfiguration)"
                        )
                        continue
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
                self.log.info(f"[{device_ip}] OSPF Process {process_id} is fully operational.")
                return True
            self.log.warning(f"Process {process_id} not found in operational data.")
            return False
        except Exception as e:
            self.log.error(f"OSPF Operation Check Failed: {e}", exc_info=True)
            return False
    def verify_ospf_neighbors(self, device_ip, restconf_state: Dict, ospf_data: Dict) -> bool:
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
            healthy_neighbors = {}
            degraded_neighbors = {}
            failed_neighbors = {}
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
                            role = "UNKNOWN"

                            nbr_record = {
                                "role": role,
                                "state":state,
                                "interface": interface_name,
                                "nbr_id": nbr_id,
                                "ip": nbr_ip
                            }
                            if "point-to-point" in network_type:
                                role = "PEER"
                                nbr_record["role"] = role
                                if "full" in state:
                                    healthy_neighbors[nbr_ip] = nbr_record
                                else:
                                    self.log.error(
                                        f"[{device_ip}] {interface_name}| IP: {nbr_ip}| "
                                        f"State: {state}| Fail: State should be FULL"
                                    )
                                    failed_neighbors[nbr_ip] = {
                                        **nbr_record,
                                        "reason": "ptp_not_full",
                                        "status": "FAILED"
                                    }
                                    continue
                            elif nbr_ip == dr_ip:
                                role = "dr"
                            elif nbr_ip == bdr_ip:
                                role = "bdr"
                            else:
                                role = "drother"
                            nbr_record["role"] = role

                            if role in ["dr", "bdr"]:
                                if "full" in state:
                                    healthy_neighbors[nbr_ip] = nbr_record
                                else:
                                    self.log.error(
                                        f"[{device_ip}] {interface_name}: {nbr_ip} {role}"
                                        f"state= {state} - *** SHOULD BE FULL ***"
                                        f"(MTU/timer/authentication mismatch?)"
                                    )
                                    failed_neighbors[nbr_ip] = {
                                        **nbr_record,
                                        "reason": "dr_bdr_not_full",
                                        "status": "FAILED"
                                    }
                            elif role in ["DROTHER"]:
                                if state in ["full", "2-way", "two-way"]:
                                    healthy_neighbors[nbr_ip] = nbr_record
                                else:
                                    self.log.error(
                                        f"[{device_ip}] {interface_name}: {nbr_ip} ({role})"
                                        f"state= {state} (*** SHOULD BE FULL OR TWO-WAY ***)"
                                    )
                                    failed_neighbors[nbr_ip] = {
                                        **nbr_record,
                                        "reason": "drother_not_full_or_2way",
                                        "status": "FAILED"
                                    }
            actual_ips = (
                set(healthy_neighbors.keys())
                | set(failed_neighbors.keys())
                | set(degraded_neighbors.keys())

            )
            missing = expected_neighbors - actual_ips
            extra = actual_ips - expected_neighbors

            self.log.info(f"[{device_ip}] Found {len(actual_ips)} neighbors.")
            if missing:
                self.log.error(f"[{device_ip}] x Missing or not fully adjacent neighbors: {missing}")
                return False
            if extra:
                self.log.error(f"[{device_ip}] x Found a neighbor not found in NetBox. Neighbors: {extra}")
                return False
            if not failed_neighbors and not degraded_neighbors:
                self.log.info(f"[{device_ip}] All expected neighbors healthy.")
                return True
            else:
                self.log.error(
                    f"[{device_ip}] OSPF Neighbor Validation Failed| "
                    f"Failed Neighbors: {list(failed_neighbors.keys())}"
                )
                return False
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
            ospf_oper = (
                restconf_state.get("ospf_oper_restconf", {})
                .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})
            )
            instances = ospf_oper.get("ospfv2-instance", [])
            if isinstance(instances, dict):
                instances = [instances]
            for instance in instances:
                if str(instance.get("instance-id", "")) != str(process_id):
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
                        oper_interfaces[interface_name]= {
                            "actual_hello": safe_int(ospf_interface.get("hello-interval")),
                            "actual_dead": safe_int(ospf_interface.get("dead-interval")),
                            "passive": ospf_interface.get("passive", False )

                        }
            if not oper_interfaces:
                self.log.error(
                    f"[{device_ip}] No OSPF operational interfaces found."
                )
                return False
            for interface_name, interface_values in interfaces_config.items():
                expected_hello = safe_int(interface_values.get("hello_interval"))
                expected_dead = safe_int(interface_values.get("dead_interval"))
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
                self.log.error(
                    f"[{device_ip}] OSPF Timer Validation Failed."
                )
                return False
            self.log.info(f"[{device_ip}] OSPF Timer Validation Passed.")
            return True
        except Exception as e:
            self.log.error(f"[{device_ip}] Could not verify OSPF Hello/Dead Timers: {e}")
            return False
    def verify_ospf_mtu(self, device_ip, restconf_state: Dict, ospf_data: Dict) -> bool:
        try:
            process_id = ospf_data.get("process-id", 1)
            interfaces_config = ospf_data.get("interfaces", {})
            if not interfaces_config:
                self.log.warning(f"[{device_ip}] No Interfaces Configured")
                return True
            interfaces_oper = (
                restconf_state.get("interface_oper_restconf", {})
                .get("Cisco-IOS-XE-interfaces-oper:interfaces", {})
            )
            operational_interfaces = interfaces_oper.get("interface", [])
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
                            f"[{device_ip}] Try/Except Error:"
                            f" ValueError or TypeError| MTU| Code: int(interface_mtu_oper)"
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
                if safe_int(instance.get("instance-id")) != safe_int(process_id):
                    continue
                if isinstance(areas, dict):
                    areas = [areas]
                for area in areas:
                    interfaces = area.get("ospfv2-interface", [])
                    if isinstance(interfaces, dict):
                        interfaces = [interfaces]
                    for interface in interfaces:
                        interface_name = interface.get("name")
                        mtu_ignore = interface.get("mtu-ignore", False)
                        passive = interface.get("passive", False)
                        if passive:
                            self.log.debug(
                                f"[{device_ip}] {interface_name}: Passive Interface skipped MTU Check."
                            )
                            continue
                        if interface_name not in interfaces_config:
                            self.log.warning(
                                f"[{device_ip}] {interface_name}: (potential rogue) "
                                f"Interface Not found in NetBox."
                            )
                            continue
                        expected_mtu = safe_int(
                            interfaces_config[interface_name].get("expected_mtu")
                        )
                        actual_mtu = mtu_map.get(interface_name)

                        if expected_mtu is None:
                            self.log.debug(
                                f"[{device_ip}] {interface_name}: No Expected MTU in SOT"
                                f"skipping MTU Validation"
                            )
                            mtu_mismatch_issues.append(interface_name)
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
            self.log.info(f"[{device_ip}] OSPF MTU Validation Passed.")
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
            ospf_interfaces_seen = set()
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
                        if not interface_name:
                            continue
                        is_passive = oper_interface.get("passive", False)
                        ospf_interfaces_seen.add(interface_name)
                        if is_passive:
                            if interface_name not in interfaces_config:
                                info_messages.append(
                                    f"[{device_ip}] {interface_name}: (ROGUE INTERFACE) Passive OSPF interface not documented in NetBox"
                                )
                            continue
                        config = interfaces_config.get(interface_name)
                        if not config:
                            info_messages.append(
                                f"[{device_ip}] {interface_name}: (ROGUE INTERFACE): Active OSPF interface not found in NetBox"
                            )
                            continue
                        auth_issues = self.validate_interface_auth(
                            device_ip,
                            interface_name,
                            oper_interface,
                            config
                        )
                        if auth_issues:
                            for issue in auth_issues:
                                severity = issue.severity.upper()
                                msg = issue.message

                                if severity == "CRITICAL":
                                    critical_issues.append(msg)
                                elif severity == "WARN":
                                    degraded_issues.append(msg)
                                else:
                                    info_messages.append(msg)
            missing_interfaces = set(interfaces_config.keys()) - ospf_interfaces_seen
            if missing_interfaces:
                for missing_interface in missing_interfaces:
                    degraded_issues.append(
                        f"[{device_ip}] {missing_interface}: (MISSING INTERFACE) Interface configured in NetBox"
                        f"but not found in OSPF Operational Data"
                    )
            if info_messages:
                self.log.info(f"[{device_ip}] Informational Messages:")
                for msg in info_messages:
                    self.log.info(f"{msg}")
            if degraded_issues:
                self.log.warning(f"[{device_ip}] Degraded State:")
                for issue in degraded_issues:
                    self.log.warning(f"{issue}")
            if critical_issues:
                self.log.error(f"[{device_ip}] x Critical Authentication Issues:")
                for issue in critical_issues:
                    self.log.error(f"{issue}")
                return False
            self.log.info(f"[{device_ip}] Authentication Validation Test Passed. No issues found.")
            return True
        except Exception as e:
            self.log.exception(f"[{device_ip}] OSPF Authentication Validation Check Failed")
            return False
    def validate_interface_auth(self, device_ip: str, interface_name: str, oper_interface: Dict,
                                interfaces_config: Dict
                                ) -> list[ValidationIssue]:
        issues = []
        expected_auth_type = str(interfaces_config.get("auth_type", "none")).lower()
        expected_key_id = safe_int(interfaces_config.get("auth_key_id"))

        auth_val = oper_interface.get("auth-val", {})
        auth_key = auth_val.get("auth-key", {})

        if expected_auth_type == "none":
            if auth_key:
                issues.append(self.issue(
                    device_ip,
                    interface_name,
                    "CRITICAL",
                    "Expected NO authentication, but auth-key is configured. "
                    f"Please check authentication on device.",
                    "AUTH_UNEXPECTED"
                ))
            return issues
        if expected_auth_type not in ["md5", "sha256"]:
            issues.append(self.issue(
                device_ip,
                interface_name,
                "WARN",
                "Unknown Authentication Type Found in NetBox| "
                f"Auth Type: {expected_auth_type}",
                "AUTH_UNKNOWN_TYPE"
            ))
            return issues
        if not auth_key:
            issues.append(self.issue(
                device_ip,
                interface_name,
                "CRITICAL",
                f"No auth-key found (meaning potentially no authentication configured.) "
                f"Expected Auth: {expected_auth_type}",
                "NO_AUTH_KEY"
            ))
            return issues

        actual_algo = str(auth_key.get("crypto-algo" or "")).lower()
        if expected_auth_type == "md5":
            if "md5" not in actual_algo:
                issues.append(self.issue(
                    device_ip,
                    interface_name,
                    "CRITICAL",
                    f"Authentication Mismatch|"
                    f"Expected: MD5| Actual: {actual_algo}",
                    "AUTH_ALGO_MISMATCH"
                ))
        elif expected_auth_type == "sha256":
            if "sha256" not in actual_algo and "sha-256" not in actual_algo:
                issues.append(self.issue(
                    device_ip,
                    interface_name,
                    "CRITICAL",
                    f"Authentication Mismatch|"
                    f"Expected: SHA256| Actual: {actual_algo}",
                    "AUTH_ALGO_MISMATCH"
                ))
        actual_key_id = safe_int(auth_key.get("key-id"))
        if expected_key_id is not None:
            if actual_key_id is None:
                issues.append(self.issue(
                    device_ip,
                    interface_name,
                    "CRITICAL",
                    f"No key-id found in operational data|"
                    f"Expected Key-ID: {expected_key_id}",
                    "AUTH_KEYID_MISSING"
                ))
            else:
                if actual_key_id != expected_key_id:
                    issues.append(self.issue(
                        device_ip,
                        interface_name,
                        "CRITICAL",
                        f"Key-ID mismatch|"
                        f"Expected Key-ID: {expected_key_id}| Actual Key-ID: {actual_key_id}",
                        "AUTH_KEYID_MISMATCH"
                    ))
        return issues
    def check_lsa_age(self,device_ip: str, restconf_state: Dict) -> Tuple[str, int]:
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
                    if isinstance(lsdbs, dict):
                        lsdbs = [lsdbs]
                    for lsdb in lsdbs:
                        ls_age = safe_int(lsdb.get("lsa-age"))
                        if ls_age is None:
                            continue
                        all_ages.append(ls_age)


            if not all_ages:
                return "unknown", 0
            max_age = max(all_ages)
            if max_age < 300:
                self.log.info(f"[{device_ip}] LSA Health Check | State: healthy | "
                              f"Max Age: {max_age}")
                return "healthy", max_age
            elif max_age < 3600:
                self.log.warning(f"[{device_ip}] LSA Health Check | State: degraded | "
                              f"Max Age: {max_age}")
                return "degraded", max_age
            self.log.warning(f"[{device_ip}] LSA Health Check | State: stale | "
                              f"Max Age: {max_age}")
            return "stale", max_age
        except Exception:
            self.log.error(f"[{device_ip}] Try Exception Error|"
                           f"Function: check_lsa_age", exc_info=True)
            return "error", 0







