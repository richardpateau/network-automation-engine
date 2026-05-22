import ipaddress
from logging import critical, exception
from sys import exc_info
import json
import requests
import pynetbox
from genie.gre import defaultdict
from typing import Dict, Tuple
import graypy
import logging
from numpy.array_api import arange
from dataclasses import dataclass
from typing import Literal
from jinja2 import Environment, FileSystemLoader
template_env = Environment(
    loader=FileSystemLoader("/run/media/rich/HDD/Templates/"),
    trim_blocks=True,
    lstrip_blocks=True
)
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
                        'r_interface': device_interface.name,
                        "description": "- configured via Network Automation"
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
def safe_send_config(conn, commands):
    try:
        conn.send_config_set(commands.splitlines())
        return True, None
    except Exception as e:
        return False, str(e)
def create_restconf_session(auth):

    headers = {
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json"
    }

    session = requests.Session()

    session.auth = auth
    session.verify = False
    session.headers.update(headers)

    return session
def safe_restconf_patch(session, url, data):

    try:
        response = session.patch(url, data=payload, timeout=20)

        if response.status_code in [200, 201, 204]:
            return True, None

        return False, response.text

    except Exception as e:
        return False, str(e)
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
    return status == "up" and protocol == "up"
def restconf_state(device_ip, auth):
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
    n_interface = "".join([c for c in router_interface if c.isdigit() or c == "/" or c == "."])

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
class OSPF_Checker:
    def validate_device_ospf(self, device_ip: str, restconf_state: Dict, ospf_data: Dict) -> Dict:
        results = {
            "device": device_ip,
            "status": "HEALTHY",
            "checks":{
                "ospf_config_check": False,
                "ospf_lsdb_check": False,
                "ospf_neighbor_check": False,
                "ospf_timers_check": False,
                "ospf_auth_check": False,
                "ospf_mtu_check": False,
                "lsa_age_check": False
            },
            "critical_issues": [],
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
                            "check_name": "ospf_config_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Config mismatch"
                        }
                    )
                    results["critical_issues"].append("ospf_config_check")
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "check_name": "ospf_config_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "component": "ospf_validator",
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
                    "check_name": "ospf_lsdb_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF LSDB (not empty) "
                }
            )
            try:
                ospf_oper_ok = self.check_ospf_operational(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_lsdb_check"] = ospf_oper_ok

                if ospf_oper_ok:
                    logger.info(
                        "ospf_check",
                        extra= {
                            "device_ip": device_ip,
                            "check_name": "ospf_lsdb_check",
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
                            "check_name": "ospf_lsdb_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF LSDB is empty (no LSAs found)"
                        }
                    )
                    results["critical_issues"].append("ospf_lsdb_check")
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra = {
                        "device_ip": device_ip,
                        "check_name": "ospf_lsdb_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error| LSDB Check | ospf_oper_ok "
                    },
                    exc_info=True
                )
                results["checks"]["ospf_lsdb_check"] = False
                results["critical_issues"].append("lsdb_check_exception")

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "ospf_neighbor_check",
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
                            "check_name": "ospf_neighbor_check",
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
                            "check_name": "ospf_neighbor_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Neighbor not in the correct (expected) state."
                        }
                    )
                    results["critical_issues"].append("ospf_neighbor_check")
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra= {
                        "device_ip": device_ip,
                        "check_name": "ospf_neighbor_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error | OSPF Neighbor Check | nbr_ok "
                    },
                    exc_info=True
                )
                results["checks"]["ospf_neighbor_check"] = False
                results["critical_issues"].append("neighbor_check_exception")

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "ospf_timer_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Timers (hello/dead) "
                }
            )
            try:
                timer_ok = self.verify_ospf_timers(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_timer_check"] = timer_ok

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
                        extra={
                            "device_ip": device_ip,
                            "check_name": "ospf_timer_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Timers (hello/dead) Validation Failed."
                         }
                    )
                    results["critical_issues"].append("ospf_timer_check")

            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "check_name": "ospf_timer_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error | OSPF Timer Validation |"
                                   " timer_ok"
                    }
                )
                results["checks"]["ospf_timer_check"] = False
                results["critical_issues"].append("timer_check_exception")

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "ospf_auth_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Authentication."
                }
            )

            try:
                authentication_ok = self.veify_ospf_auth(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_auth_check"] = authentication_ok

                if authentication_ok:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "ospf_auth_check",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF Authentication Validation Passed."
                        }
                    )
                else:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "ospf_auth_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Authentication Validation Failed."
                        }
                    )
                    results["critical_issues"].append("ospf_auth_check")
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "check_name": "ospf_auth_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error | OSPF Authentication Validation |"
                                   " authentication_ok"
                    }
                )
                results["checks"]["ospf_auth_check"] = False
                results["critical_issues"].append("auth_check_exception")
            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "ospf_mtu_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Checking OSPF MTU Validation."
                }
            )
            try:
                mtu_ok = self.verify_ospf_mtu(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_mtu_check"] = mtu_ok

                if mtu_ok:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "ospf_mtu_check",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF MTU Validation Passed."
                        }
                    )
                else:
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "ospf_mtu_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF MTU Validation Failed."
                        }
                    )
                    results["critical_issues"].append("ospf_mtu_check")
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "check_name": "ospf_mtu_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "component": "ospf_validator",
                        "error": str(e),
                        "message": "Try/Exception Error | OSPF MTU Validation  | "
                                   "mtu_ok"
                    }
                )
                results["checks"]["ospf_mtu_check"] = False
                results["critical_issues"].append("mtu_check_exception")

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "lsa_age_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF LSA Ages"
                }
            )
            try:
                lsa_status, lsa_age = self.check_lsa_age(device_ip, restconf_state)
                results["lsa_age_seconds"] = lsa_age

                if lsa_status == "healthy":
                    results["checks"]["lsa_age_check"] = True
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "lsa_age_check",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF LSA Age Validation Passed."
                        }
                    )
                elif lsa_status == "degraded":
                    results["checks"]["lsa_age_check"] = True
                    results["warnings"].append("lsa_age_degraded")

                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "lsa_age_check",
                            "status": "DEGRADED",
                            "severity": "WARNING",
                            "component": "ospf_validator",
                            "message": f"OSPF LSA Age Degraded | Max Age: {lsa_age}"
                        }
                    )

                elif lsa_status == "stale":
                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "lsa_age_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": f"OSPF LSA Age Validation Failed. Max Age: {lsa_age}"
                        }
                    )
                    results["checks"]["lsa_age_check"] = False
                    results["critical_issues"].append("lsa_age_check")
                else:
                    results["checks"]["lsa_age_check"] = False

                    logger.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "check_name": "lsa_age_check",
                            "status": "ERROR",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "Unable to determine OSPF LSA state"
                        }
                    )
            except Exception as e:
                logger.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "check_name": "lsa_age_check",
                        "status": "ERROR",
                        "severity": "CRITICAL",
                        "component": "ospf_validator",
                        "error": str(e),
                        "message": "Try/Exception Error | OSPF LSA Age Validation | "
                                   "lsa_age_check"
                    }
                )
                results["checks"]["lsa_age_check"] = False
                results["critical_issues"].append("age_check_exception")

            if results["critical_issues"]:
                results["status"] = "FAILED"
            elif results["warnings"]:
                results["status"] = "DEGRADED"
            else:
                results["status"] = "HEALTHY"

            checks_passed = sum(1 for v in results["checks"].values() if v)
            checks_total = len(results["checks"])

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "overall",
                    "status": results["status"],
                    "message": "OSPF Validation Complete.",
                    "checks_passed": f"{str(checks_passed)} out of {str(checks_total)}",
                    "critical_issues": len(results["critical_issues"]),
                    "warnings": len(results["warnings"]),
                    "component": "ospf_validator"

                }
            )
            return results
        except Exception as e:
            self.log.error(
                f"[{device_ip}] Try/Exception Error | OSPF Validation |"
                f" Function: def validate_device_ospf | Error: {e}", exc_info=True
            )
            results["status"] = "ERROR"
            results["critical_issues"].append("validation_exception")

            logger.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "overall",
                    "status": "ERROR",
                    "severity": "CRITICAL",
                    "component": "ospf_validator",
                    "error": str(e),
                    "message": f"Try/Exception Error | Total OSPF Validation | "
                               f"Function: def validate_device_ospf | Error: {e}"
                }
            )
            return results
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
    def veify_ospf_auth(self, device_ip: str, restconf_state: Dict, ospf_data: Dict) -> bool:
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
def configure_vlan(conn, device_ip, vlan_data):
    vlan_id, name = vlan_data["vlan_id"], vlan_data["name"]
    results = {
        "device_ip": device_ip,
        "vlan_id": vlan_id,
        "name": name,
        "configured": False,
        "validated": False,
        "status": "PENDING",
        "component": "vlan_automation"
    }
    try:
        logger.info(
            "vlan_check",
            extra={
                "device_ip": device_ip,
                "check_name": "vlan_config",
                "severity": "INFO",
                "component": "vlan_automation",
                "message": f"**** Configuring VLAN {vlan_id} for {name} ****"
            }
        )
        template = template_env.get_template("vlan.j2")
        commands = template.render(
            vlan_id=vlan_id,
            name=name
        )

        configured, error = safe_send_config(conn, commands)
        results["configured"] = configured
        if not configured:
            results["status"] = "FAILED_CONFIG"
            results["error"] = error
            return results

        logger.info(
            "vlan_check",
            extra = {
                "device_ip": device_ip,
                "check_name": "vlan_config",
                "status": "CONFIGURED",
                "severity": "INFO",
                "component": "vlan_automation",
                "message": f"VLAN {vlan_id} for {name} successfully configured."

            }
        )
        device_state = collect_device_state(conn)

        vlan_ok = check_vlan(device_state, vlan_id, name)

        results["validated"] = vlan_ok

        if vlan_ok:
            logger.info(
                "vlan_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "vlan_validation",
                    "status": "PASS",
                    "severity": "INFO",
                    "component": "vlan_automation",
                    "message": f"VLAN {vlan_id} for {name} validated successfully."
                }
            )
            results["status"] = "SUCCESS"
        else:
            logger.info(
                "vlan_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "vlan_validation",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "component": "vlan_automation",
                    "message": f"VLAN Validation Failed  | VLAN: {vlan_id} | Name: {name}"
                }
            )
            results["status"] = "FAILED_VALIDATION"
    except Exception as e:
        logger.info(
            "vlan_check",
            extra={
                "device_ip": device_ip,
                "check_name": "vlan_config",
                "status": "ERROR",
                "severity": "CRITICAL",
                "error": str(e),
                "component": "vlan_automation",
                "message": "Try/Exception Error | VLAN Configuration | "
                           "Function: def configure_vlan",
            },                 exc_info=True

        )
        results["error"] = str(e)
        results["status"] = "ERROR"
        results["configured"] = False
        results["validated"] = False
        return results
    return results
def configure_access_ports(conn, device_ip, access_data):
    access_interface,  access_vlan = access_data["access_interface"], access_data["access_vlan"]
    results = {
        "device_ip": device_ip,
        "interface": access_interface,
        "vlan_id": access_vlan,
        "configured": False,
        "validated": False,
        "status": "PENDING",
        "component": "access_port_automation"
    }
    try:
        logger.info(
            "access_port_check",
            extra={
                "device_ip": device_ip,
                "check_name": "access_port_config",
                "severity": "INFO",
                "component": "access_port_automation",
                "message": f"**** Configuring Access Port {access_interface} "
                           f"for VLAN {access_vlan} ****"
            }
        )
        template = template_env.get_template("access_port.j2")
        commands = template.render(
            access_interface=access_interface,
            access_vlan=access_vlan
        )
        configured, error = safe_send_config(conn, commands)

        results["configured"] = configured

        if not configured:
            results["status"] = "FAILED_CONFIG"
            results["error"] = error
            return results

        logger.info(
            "access_port_check",
            extra = {
                "device_ip": device_ip,
                "check_name": "access_port_config",
                "status": "CONFIGURED",
                "severity": "INFO",
                "component": "vlan_automation",
                "message": f"Access Port {access_interface} for VLAN {access_vlan} successfully conigured."

            }
        )

        device_state = collect_device_state(conn)

        access_port_ok = check_switch_mode(
            device_state,
            access_interface,
            "access",
            access_vlan
        )

        results["validated"] = access_port_ok

        if access_port_ok:
            logger.info(
                "access_port_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "access_port_validation",
                    "status": "PASS",
                    "severity": "INFO",
                    "component": "access_port_automation",
                    "message": f"Access Port Validation Passed. | VLAN: {access_vlan} | "
                               f"Interface: {access_interface}"
                }
            )
            results["status"] = "SUCCESS"
        else:
            logger.info(
                "access_port_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "access_port_validation",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "component": "access_port_automation",
                    "message": f"Access Port Validation Failed. | VLAN: {access_vlan} | "
                               f"Interface: {access_interface}"
                }
            )
            results["status"] = "FAILED_VALIDATION"

    except Exception as e:
        logger.info(
            "access_port_check",
            extra={
                "device_ip": device_ip,
                "check_name": "access_port_config",
                "status": "ERROR",
                "severity": "CRITICAL",
                "component": "access_port_automation",
                "error": str(e),
                "message": "Try/Exception Error | Access Port | Function: "
                           "def configurd_access_ports"
            }, exc_info=True
        )
        results["status"] = "ERROR"
        results["error"] = str(e)
        results["configured"] = False
        results["validated"] = False
    return results
def configure_trunk_ports(conn, device_ip, trunk_data):
    trunk_interface, allowed_vlans = trunk_data["trunk_interface"], trunk_data["allowed_vlans"]
    results = {
        "device_ip": device_ip,
        "interface": trunk_interface,
        "allowed_vlans": allowed_vlans,
        "configured": False,
        "validated": False,
        "status": "PENDING",
        "component": "trunk_port_automation"
    }
    try:
        logger.info(
            "trunk_port_check",
            extra={
                "device_ip": device_ip,
                "check_name": "trunk_port_config",
                "severity": "INFO",
                "component": "trunk_port_automation",
                "message": f"**** Configuring Trunk Port for {trunk_interface} | "
                           f"Allowed VLANs: {allowed_vlans} ****"
            }
        )
        template = template_env.get_template("trunk.j2")
        commands = template.render(
            trunk_interface=trunk_interface,
            allowed_vlans=allowed_vlans
        )

        configured, error = safe_send_config(conn, commands)

        results["configured"] = configured

        if not configured:
            results["status"] = "FAILED_CONFIG"
            results["error"] = error
            return results

        logger.info(
            "trunk_port_check",
            extra={
                "device_ip": device_ip,
                "check_name": "trunk_port_config",
                "status": "CONFIGURED",
                "severity": "INFO",
                "component": "trunk_port_automation",
                "message": f"Trunk Port Successfully Configured | Interface: {trunk_interface} | "
                           f"Allowed VLANs: {allowed_vlans}"
            }
        )

        device_state = collect_device_state(conn)

        trunk_ok = check_switch_mode(
            device_state,
            trunk_interface,
            "trunk",
            allowed_vlans
        )

        results["validated"] = trunk_ok

        if trunk_ok:
            logger.info(
                "trunk_port_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "trunk_port_validation",
                    "status": "PASS",
                    "severity": "INFO",
                    "component": "trunk_port_automation",
                    "message": f"Trunk Port Validation Passed | Interface: {trunk_interface} | "
                               f"Allowed VLANs: {allowed_vlans}"
                }
            )
            results["status"] = "SUCCESS"
        else:
            logger.info(
                "trunk_port_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "trunk_port_validation",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "component": "trunk_port_automation",
                    "message": f"Trunk Port Validation Failed | Expected Interface: {trunk_interface} | "
                               f"Expected Allowed VLANs: {allowed_vlans}"
                }
            )
            results["status"] = "FAILED_VALIDATION"

    except Exception as e:
        logger.info(
            "trunk_port_check",
            extra={
                "device_ip": device_ip,
                "check_name": "trunk_port_config",
                "status": "ERROR",
                "severity": "CRITICAL",
                "component": "trunk_port_automation",
                "error": str(e),
                "message": "Try/Exception Error | Trunk Port Config | "
                           "Function: def configure_trunk_ports"
            }
        )
        results["configured"] = False
        results["validated"] = False
        results["error"] = str(e)
        results["status"] = "ERROR"
        return results
    return results
def configure_interface(conn, device_ip, interface_data):
    interface = interface_data["interface"]
    description = interface_data["description"]
    results = {
        "device_ip": device_ip,
        "interface": interface,
        "configured": False,
        "validated": False,
        "status": "PENDING",
        "component": "interface_automation"
    }
    try:
        logger.info(
            "interface_check",
            extra={
                "device_ip": device_ip,
                "check_name": "interface_config",
                "severity": "INFO",
                "component": "interface_automation",
                "message": f"**** Configuring Interface {interface} ****"
            }
        )

        template = template_env.get_template("interface.j2")
        commands = template.render(interface=interface,
                                   description=description)

        configured, error = safe_send_config(conn, commands)

        results["configured"] = configured
        if not configured:
            results["status"] = "FAILED_CONFIG"
            results["error"] = error
            return results

        logger.info(
            "interface_check",
            extra={
                "device_ip": device_ip,
                "check_name": "interface_config",
                "status": "CONFIGURED",
                "severity": "INFO",
                "component": "interface_automation",
                "message": f"Interface {interface} successfully configured."
            }
        )

        device_state = collect_device_state(conn)

        interface_ok = check_interface(device_state, interface)

        results["validated"] = interface_ok

        if interface_ok:
            logger.info(
                "interface_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "interface_validation",
                    "status": "PASS",
                    "severity": "INFO",
                    "component": "interface_automation",
                    "message": f"Interface Validation Passed. | Interface: {interface}"
                }
            )
            results["status"] = "SUCCESS"
        else:
            logger.info(
                "interface_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "interface_validation",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "component": "interface_automation",
                    "message": f"Interface Validation Failed. | Interface: {interface}"
                }
            )
            results["status"] = "FAILED_VALIDATION"
    except Exception as e:
        logger.info(
            "interface_check",
            extra={
                "device_ip": device_ip,
                "check_name": "interface_config",
                "status": "ERROR",
                "error": str(e),
                "component": "interface_automation",
                "severity": "CRITICAL",
                "message": "Try/Exception Error | Interface Config | "
                           "Function: def configure_interface"
                }, exc_info=True
        )
        results["configured"] = False
        results["validated"] = False
        results["error"] = str(e)
        results["status"] = "ERROR"
        return results
    return results

def configure_roas(device_ip, roas_data, session):
    router_interface = roas_data["router_interface"]
    router_vlan = roas_data["router_vlan"]
    ip = roas_data["ip"]
    mask = roas_data["mask"]
    new_interface = "".join([c for c in router_interface if c.isdigit() or c == "/" or c == "."])
    url = f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/interface/GigabitEthernet={new_interface}"
    results = {
        "device_ip": device_ip,
        "router_interface": router_interface,
        "router_vlan": router_vlan,
        "ip": f"{ip}/{mask}",
        "configured": False,
        "validated": False,
        "status": "PENDING",
        "component": "roas_automation"

    }

    try:
        logger.info(
            "roas_check",
            extra={
                "device_ip": device_ip,
                "check_name": "roas_config",
                "severity":"INFO",
                "component": "roas_automation",
                "message": f"**** Configuring ROAS | Interface: {router_interface}.{router_vlan} |"
                           f" VLAN: {router_vlan} | IP: {ip}/{mask}"

            }
        )
        template = template_env.get_template("roas.j2")
        commands = template.render(
            new_interface=new_interface,
            router_vlan=router_vlan,
            ip=ip,
            mask=mask
        )

        configured, error = safe_restconf_patch(session, url, commands)

        results["configured"] = configured

        if not configured:
            results["status"] = "FAILED_CONFIG"
            results["error"] = error
            return results

        logger.info(
            "roas_check",
            extra={
                "device_ip": device_ip,
                "check_name": "roas_config",
                "status": "CONFIGURED",
                "severity": "INFO",
                "component": "roas_automation",
                "message": f"ROAS Successfully Configured | Interface: {router_interface}.{router_vlan} | "
                           f"VLAN: {router_vlan} | IP: {ip}/{mask}"
            }
        )

        state = restconf_state(device_ip, session.auth)
        roas_ok = check_roas(state, roas_data)
        results["validated"] = roas_ok

        if roas_ok:
            results["status"] = "SUCCESS"
            logger.info(
                "roas_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "roas_validation",
                    "status": "PASS",
                    "severity": "INFO",
                    "component": "roas_automation",
                    "message": f"ROAS Validation Passed | Interface: {router_interface}.{router_vlan} | "
                               f"IP: {ip}/{mask}"
                }
            )
        else:
            results["status"] = "FAILED_VALIDATION"
            logger.info(
                "roas_check",
                extra={
                    "device_ip": device_ip,
                    "check_name": "roas_validation",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "component": "roas_automation",
                    "message": f"ROAS Validation Failed | Interface: {router_interface}.{router_vlan} | "
                               f"IP: {ip}/{mask}"
                }
            )
    except Exception as e:
        logger.info(
            "roas_check",
            extra={
                "device_ip": device_ip,
                "check_name": "roas_config",
                "status": "ERROR",
                "severity": "CRITICAL",
                "component": "roas_automation",
                "error": str(e),
                "message": "Try/Exception Error | ROAS Config | Function: def configured_roas"
            }, exc_info=True
        )
        results["configured"] = False
        results["validated"] = False
        results["status"] = "ERROR"
        results["error"] = str(e)
        return results
    return results
def configure_ospf(session, device_ip, ospf_data):
    process_id = ospf_data["process_id"]
    router_id = ospf_data["router_id"]
    network_list = ospf_data["network_list"]
    for network in network_list:
        subnet = network.get("subnet", "")
        wildcard = network.get("wildcard", "")
        area = network.get("area", "")
    url = f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/router"
    results = {
        "device_ip": device_ip,
        "process_id": process_id,
        "router_id": router_id,
        "configured": False,
        "validated": False,
        "status": "PENDING",
        "component": "ospf_automation"
    }
    try:
        logger.info(
            "ospf_check",
            extra={
                "device_ip": device_ip,
                "check_name": "ospf_config",
                "severity": "INFO",
                "component": "ospf_automation",
                "message": f"Configuring OSPF | Process ID: {process_id} | RID: {router_id} | "
                           f"Network: {subnet}/{wildcard} | Area: {area}"
            }
        )

        template = template_env.get_template("Cisco_Router_OSPF")
        commands = template.render(
            process_id=process_id,
            router_id=router_id,
            subnet=subnet,
            wildcard=wildcard,
            area=area
        )
        configured, error = safe_restconf_patch(session,url, commands)

        results["configured"] = configured
