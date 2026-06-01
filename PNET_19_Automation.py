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
from ncclient import manager

template_env = Environment(
    loader=FileSystemLoader("/run/media/rich/HDD/Templates/"),
    trim_blocks=True,
    lstrip_blocks=True
)
from websocket import continuous_frame
from datetime import datetime, timezone
from netmiko import ConnectHandler
from enum import Enum
logger = logging.getLogger("Networkautomation")
logger.setLevel(logging.DEBUG)
handler = graypy.GELFUDPHandler("127.0.0.1", 12201)
logger.addHandler(handler)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
logger.addHandler(console)
netbox_url = "http://localhost:8000"
netbox_token = "*****"
DRY_RUN = True
timestamp = datetime.utcnow().isoformat()
class OpStatus(Enum):
    SUCCESS="SUCCESS"
    CONFIG_FAILED= "FAILED_CONFIG"
    VALIDATION_FAILED= "FAILED_VALIDATION"
    ERROR="ERROR"
    PENDING="PENDING"
    CONFIGURED="CONFIGURED"
    DRY_RUN="DRY_RUN"
class StepStatus(Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ERROR = "ERROR"
    DRY_RUN= "DRY_RUN"
    SKIPPED = "SKIPPED"
def get_severity(status):
    if status in {
        OpStatus.ERROR.value,
        OpStatus.CONFIG_FAILED.value,
        OpStatus.VALIDATION_FAILED.value
    }:
        return "CRITICAL"
    return "INFO"
@dataclass
class ValidationIssue:
    device_ip: str
    interface: str
    severity: Literal["CRITICAL", "WARN", "INFO"]
    message: str
    code: str | None = None
def build_event(
        device_ip: str,
        component: str,
        event_type: str,
        status: str,
        severity: str = "INFO",
        **kwargs
):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "device_ip": device_ip,
        "component": component,
        "event_type": event_type,
        "status": status,
        "severity": severity,
        **kwargs
    }
def emit_event(
    device_ip,
    component,
    event_type,
    outcome,
    vlan_id,
    name,
    timestamp,
    error=None,
    reason=None,
    **kwargs
):
    status_map = {
        "SUCCESS": StepStatus.SUCCESS.value,
        "FAIL": StepStatus.FAILED.value,
        "ERROR": StepStatus.ERROR.value,
        "DRY_RUN": StepStatus.DRY_RUN.value
    }

    default_reason = f"{event_type} - {outcome}"

    return build_event(
        device_ip=device_ip,
        component=component,
        event_type=event_type,
        status=status_map[outcome],
        severity=(
            "CRITICAL" if outcome in ["FAIL", "ERROR"] else "INFO"
        ),
        vlan=vlan_id,
        name=name,
        timestamp=timestamp,
        error=error,
        reason=reason or default_reason,
        **kwargs
    )
def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
def normalize_acl(device_ip, acl_context):
    acl_list = []

    for acl_name, rules in acl_context.items():
        normalized_rules = []
        for rule in rules:
            normalized_rules.append({
                "sequence": safe_int(rule["sequence"]),
                "action": rule["action"].lower(),
                "protocol": rule["protocol"].lower(),

                "source": {
                    "source_ip": rule.get("source_ip", ""),
                    "source_mask": rule.get("source_mask", "")
                },
                "destination": {
                    "dest_ip": rule.get("dest_ip", ""),
                    "dest_mask": rule.get("dest_mask")
                },
                "port": rule.get("port", "")
            })
            acl_list.append({
                "device_ip": device_ip,
                "acl_name": acl_name,
                "rules": sorted(normalized_rules, key=lambda x:x["sequence"])
            })
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
        "ospf":[],
        "ACL": [],
        "acl_bindings": [],
        "ntp": {
            "keys": [],
            "servers": []
        }
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
        context = device_name.config_context or {}
        acl_bindings = context.get("acl_bindings", [])
        acl_context = device_name.config_context.get("acl", {})
        ntp_context = context.get("ntp", {})
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
                if device_interface.type and device_interface.type.value not in ["virtual", "lag", "bridge"]:
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

        if acl_context:
            config_data["ACL"].extend(
                normalize_acl(host_ip, acl_context)
            )
        for binding in acl_bindings:
            config_data["acl_bindings"].append({
                "device": host_ip,
                "interface": binding.get("interface", ""),
                "acl_name": binding.get("acl_name", ""),
                "direction": binding.get("direction", "")
            })
        #ntp
        ntp_keys = ntp_context.get("keys", [])
        ntp_servers = ntp_context.get("servers", [])

        if isinstance(ntp_keys, dict):
            ntp_keys = [ntp_keys]
        if isinstance(ntp_servers, dict):
            ntp_servers = [ntp_servers]

        config_data["ntp"]["keys"].extend(ntp_keys)
        config_data["ntp"]["servers"].extend(ntp_servers)

    return inventory, config_data
def safe_send_config(conn, commands):
    try:
        conn.send_config_set(commands.splitlines())
        return True, None
    except Exception as e:
        return False, str(e)
def safe_netconf_edit(m, payload):
    try:
        m.edit_config(
            target="running",
            config=payload
        )
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
        response = session.patch(url, data=data, timeout=20)

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
def fetch_netconf_raw(device_ip, auth, log):
    username, password = auth

    filter_xml = """
      <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"/>
    """

    with manager.connect(
        host=device_ip,
        port=830,
        username=username,
        password=password,
        hostkey_verify=False,
        timeout=30
    ) as m:

        response = m.get_config(source="running", filter=("subtree", filter_xml))
        return response.data_xml
def collect_netconf_state(session):
    filter_xml = """
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"/>
    """

    response = session.get_config(
        source="running",
        filter=("subtree", filter_xml)
    )

    return parse_netconf_state(response.data_xml)
def parse_netconf_state(xml_data):
    import xmltodict

    full_dict = xmltodict.parse(xml_data)

    return full_dict.get("rpc-reply", {}).get("data", {}).get("native", {})
def netconf_state(device_ip, auth, log):
    xml_data = fetch_netconf_raw(device_ip, auth, log)
    return parse_netconf_state(xml_data)
def build_acl_state(native):
    actual_acls = []

    ip = native.get("ip", {})
    access_list = ip.get("access-list", {})

    extended = access_list.get("extended", [])

    if isinstance(extended, dict):
        extended = [extended]

    for acl_obj in extended:

        seq_rules = acl_obj.get("access-list-seq-rule", [])

        if isinstance(seq_rules, dict):
            seq_rules = [seq_rules]

        rules = []

        for r in seq_rules:
            ace = r.get("ace-rule", {})

        rules = [
            {
                "seq": int(r.get("sequence", 0)),
                "action": ace.get("action"),
                "protocol": ace.get("protocol"),
                "source_ip": ace.get("ipv4-address", "any"),
                "source_mask": ace.get("mask"),
                "dest_ip": ace.get("dest-ipv4-address", "any"),
                "dest_mask": ace.get("dest-mask"),
                "port": ace.get("dst-eq")
            }
            for r in seq_rules
        ]

        actual_acls.append({
            "acl_name": acl_obj.get("name"),
            "rules": sorted(rules, key=lambda x: x["seq"])
        })

    return actual_acls
def build_acl_bindings_state(native):
    actual = []

    interfaces = native.get("interface", {}).get("GigabitEthernet", [])

    if isinstance(interfaces, dict):
        interfaces = [interfaces]

    for intf in interfaces:
        name = intf.get("name")

        ip = intf.get("ip", {})
        access_group = ip.get("access-group", {})

        if not access_group:
            continue

        # can be list or dict depending on device
        if isinstance(access_group, dict):
            access_group = [access_group]

        for ag in access_group:
            actual.append({
                "interface": name,
                "acl_name": ag.get("acl-name"),
                "direction": ag.get("direction")
            })

    return actual
def build_ntp_state(native):
    ntp = native.get("ntp", {})

    # -------- KEYS --------
    keys = ntp.get("authentication-key", [])
    if isinstance(keys, dict):
        keys = [keys]

    actual_keys = [
        {
            "id": int(k.get("number", 0)),
            "md5": k.get("md5")   # keep for debugging ONLY
        }
        for k in keys
    ]

    # -------- SERVERS --------
    servers = ntp.get("server", {}).get("server-list", [])
    if isinstance(servers, dict):
        servers = [servers]

    actual_servers = [
        {
            "ip": s.get("ip-address"),
            "key": int(s.get("key", 0))
        }
        for s in servers
    ]

    return {
        "keys": sorted(actual_keys, key=lambda x: x["id"]),
        "servers": sorted(actual_servers, key=lambda x: x["ip"])
    }
def check_ntp(expected_ntp, actual_ntp):

    failures = []

    # ---------------- KEYS (ONLY ID) ----------------
    expected_keys = sorted(
        [{"id": k["id"]} for k in expected_ntp.get("keys", [])],
        key=lambda x: x["id"]
    )

    actual_keys = sorted(
        [{"id": k["id"]} for k in actual_ntp.get("keys", [])],
        key=lambda x: x["id"]
    )

    if expected_keys != actual_keys:
        failures.append("NTP authentication keys mismatch (id only)")

    # ---------------- SERVERS (IP + KEY ID) ----------------
    expected_servers = sorted(
        [(s["ip"], s["key"]) for s in expected_ntp.get("servers", [])],
        key=lambda x: x[0]
    )

    actual_servers = sorted(
        [(s["ip"], s["key"]) for s in actual_ntp.get("servers", [])],
        key=lambda x: x[0]
    )

    if expected_servers != actual_servers:
        failures.append("NTP servers mismatch (ip + key)")

    return len(failures) == 0, failures
def check_acl(expected_acls, actual_acls):

    actual_lookup = {
        acl["acl_name"]: acl["rules"]
        for acl in actual_acls
    }

    failures = []

    for expected_acl in expected_acls:

        acl_name = expected_acl["acl_name"]

        if acl_name not in actual_lookup:
            failures.append(
                f"ACL {acl_name} missing from device"
            )
            continue

        if expected_acl["rules"] != actual_lookup[acl_name]:
            failures.append(
                f"ACL {acl_name} rules mismatch"
            )

    return len(failures) == 0, failures
def check_acl_binding(expected_bindings, actual_bindings):
    failures = []

    # build lookup from actual device state
    actual_lookup = {
        (b["interface"], b["acl_name"], b["direction"])
        for b in actual_bindings
    }

    for exp in expected_bindings:
        key = (exp["interface"], exp["acl_name"], exp["direction"])

        if key not in actual_lookup:
            failures.append(
                f"Missing ACL binding: {exp['acl_name']} on {exp['interface']} {exp['direction']}"
            )

    return len(failures) == 0, failures
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
    interface = interfaces.get(r_interface)
    if not interface:
        return False

    status = interface.get("status", "")
    protocol = interface.get("protocol", "")
    return status == "up" and protocol == "up"
def restconf_state(device_ip, session, log):
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
    def validate_device_ospf(self, device_ip: str, restconf_state: Dict, ospf_data: Dict, log) -> Dict:
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
            "lsa_age_seconds": None,

            "events": [],
            "metrics":  {
                "neighbor_count": 0,
                "full_neighbors": 0,
                "lsa_count": 0,
                "max_lsa_age": 0,
                "mtu_mismatches": 0,
                "checks_run": 0,

                "checks_passed": 0,
                "checks_failed": 0,

                "config_checks_passed": 0,
                "config_checks_failed": 0,

                "lsdb_check_passed": 0,
                "lsdb_check_failed":0,

                "neighbor_check_passed": 0,
                "neighbor_check_failed": 0,

                "ospf_timers_passed": 0,
                "ospf_timers_failed": 0,

                "ospf_auth_passed": 0,
                "ospf_auth_failed": 0,

                "ospf_mtu_passed": 0,
                "ospf_mtu_failed": 0,

                "lsa_age_passed": 0,
                "lsa_age_failed": 0
            },
            "timestamp": datetime.utcnow().isoformat(),


        }
        timestamp = datetime.utcnow().isoformat()
        try:
            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "ospf_config_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Operational vs NetBox"
                }
            )
            try:
                results["metrics"]["checks_run"] += 1
                config_ok = self.check_ospf_config(device_ip,restconf_state,ospf_data)
                results["checks"]["ospf_config_check"] = config_ok

                if config_ok:
                    results["metrics"]["config_checks_passed"] +=1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_config_check",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF config Expected matches actual config"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_config_check",
                            outcome="SUCCESS",
                            timestamp=timestamp,
                            reason="OSPF config Expected matches actual config"
                        )
                    )
                else:
                    results["metrics"]["config_checks_failed"] +=1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_config_check",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Config mismatch"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_config_check",
                            outcome="FAIL",
                            reason="Operational state does not match intended NetBox config"
                        )
                    )
                    results["critical_issues"].append({
                        "check": "ospf_config_check",
                        "reason": "Operational state does not match intended NetBox config"
                    })
            except Exception as e:
                log.exception(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "ospf_config_check",
                        "status": StepStatus.ERROR.value,
                        "severity": "CRITICAL",
                        "component": "ospf_validator",
                        "error": str(e),
                        "message": "Exception occurred during OSPF config validation"
                    },

                )
                results["checks"]["ospf_config_check"] = False
                results["critical_issues"].append({
                    "check": "ospf_config_check",
                    "reason": "Python Try/Exception Error",
                    "details": str(e)
                })
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_validator",
                        event_type="ospf_config_check",
                        outcome="ERROR",
                        error= str(e),

                    )
                )
            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "ospf_lsdb_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF LSDB (not empty) "
                }
            )
            try:
                results["metrics"]["checks_run"] += 1
                ospf_oper_ok = self.check_ospf_operational(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_lsdb_check"] = ospf_oper_ok

                if ospf_oper_ok:
                    results["metrics"]["lsdb_check_passed"] += 1
                    log.info(
                        "ospf_check",
                        extra= {
                            "device_ip": device_ip,
                            "event_type": "ospf_lsdb_check",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF LSDB is not empty. LSAs Found."
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_lsdb_check",
                            status="PASS",
                            timestamp=timestamp,
                            reason="OSPF LSDB is not empty. LSAs Found."
                        )
                    )
                else:
                    results["metrics"]["lsdb_check_failed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_lsdb_check",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF LSDB is empty (no LSAs found)"
                        }
                    )
                    results["critical_issues"].append({
                        "event_type": "ospf_lsdb_check",
                        "reason": "OSPF LSDB is empty (no LSAs found)"
                    })
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_lsdb_check",
                            outcome="FAIL",
                            reason="OSPF LSDB is empty (no LSAs found)"
                        )
                    )
            except Exception as e:
                log.exception(
                    "ospf_check",
                    extra = {
                        "device_ip": device_ip,
                        "event_type": "ospf_lsdb_check",
                        "status": StepStatus.ERROR.value,
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error | LSDB Check | ospf_oper_ok "
                    },
                )
                results["checks"]["ospf_lsdb_check"] = False
                results["critical_issues"].append({
                    "event_type": "lsbd_check_exception",
                    "reason": "Try/Exception Error| LSDB Check | ospf_oper_ok",
                    "details": str(e)
                })
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_validator",
                        event_type="ospf_lsdb_check",
                        outcome="ERROR",
                        error= str(e),
                        timestamp=timestamp,
                        reason="Try/Exception Error| LSDB Check | ospf_oper_ok"
                    )
                )
            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "ospf_neighbor_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Neighbors are in correct state. "
                }
            )
            try:
                nbr_ok = self.verify_ospf_neighbors(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_neighbor_check"] = nbr_ok
                results["metrics"]["checks_run"] += 1
                if nbr_ok:
                    results["metrics"]["neighbor_check_passed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_neighbor_check",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF Neighbors are in a valid (expected) state."
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_neighbor_check",
                            status="PASS",
                            timestamp=timestamp,
                            reason="OSPF Neighbors are in a valid (expected) state."
                        )
                    )
                else:
                    results["metrics"]["neighbor_check_failed"] += 1
                    log.info(
                        "ospf_check",
                        extra = {
                            "device_ip": device_ip,
                            "event_type": "ospf_neighbor_check",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Neighbor not in the correct (expected) state"
                        }
                    )
                    results["critical_issues"].append({
                        "event_type": "ospf_neighbor_check",
                        "reason": "OSPF Neighbor not in the correct (expected) state"
                    })
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_neighbor_check",
                            outcome="FAIL",
                            timestamp=timestamp,
                            reason="OSPF Neighbor not in the correct (expected) state"
                        )
                    )
            except Exception as e:
                log.exception(
                    "ospf_check",
                    extra= {
                        "device_ip": device_ip,
                        "event_type": "ospf_neighbor_check",
                        "status": StepStatus.ERROR.value,
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error | OSPF Neighbor Check | nbr_ok "
                    },
                )
                results["checks"]["ospf_neighbor_check"] = False
                results["critical_issues"].append({
                    "event_type": "ospf_neighbor_check",
                    "reason": "Try/Exception Error | OSPF Neighbor Check | nbr_ok ",
                    "details": str(e)
                })
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_validator",
                        event_type="ospf_neighbor_check",
                        status="ERROR",
                        error= str(e),
                        timestamp=timestamp,
                        reason="Try/Exception Error | OSPF Neighbor Check | nbr_ok "
                    )
                )
            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "ospf_timer_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Timers (hello/dead) "
                }
            )
            try:
                timer_ok = self.verify_ospf_timers(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_timer_check"] = timer_ok
                results["metrics"]["checks_run"] += 1
                if timer_ok:
                    results["metrics"]["ospf_timers_passed"] += 1
                    log.info(
                        "ospf_check",
                        extra= {
                            "device_ip": device_ip,
                            "event_type": "ospf_timer_check",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF Timers (hello/dead) are valid. No mismatches."

                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_timer_check",
                            status="PASS",
                            timestamp=timestamp,
                            reason="OSPF Timers (hello/dead) are valid. No mismatches."
                        )
                    )
                else:
                    results["metrics"]["ospf_timers_failed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_timer_check",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Timers (hello/dead) Validation Failed"
                         }
                    )
                    results["critical_issues"].append({
                        "event_type": "ospf_timer_check",
                        "reason": "OSPF Timers (hello/dead) Validation Failed"
                    })
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_timer_check",
                            status="FAIL",
                            timestamp=timestamp,
                            reason="OSPF Timers (hello/dead) Validation Failed"
                        )
                    )

            except Exception as e:
                log.exception(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "ospf_timer_check",
                        "status": StepStatus.ERROR.value,
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error | OSPF Timer Validation |"
                                   " timer_ok"
                    }
                )
                results["checks"]["ospf_timer_check"] = False
                results["critical_issues"].append({
                    "event_type": "ospf_timer_check",
                    "reason": "Try/Exception Error | OSPF Timer Validation | timer_ok ",
                    "details": str(e)
                })
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_validator",
                        event_type="ospf_timer_check",
                        status="ERROR",
                        timestamp=timestamp,
                        error=str(e),
                        reason="Try/Exception Error | OSPF Timer Validation | timer_ok "
                    )
                )

            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "ospf_auth_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF Authentication."
                }
            )

            try:
                authentication_ok = self.veify_ospf_auth(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_auth_check"] = authentication_ok
                results["metrics"]["checks_run"] += 1
                if authentication_ok:
                    results["metrics"]["ospf_auth_passed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_auth_check",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF Authentication Validation Passed."
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_auth_check",
                            status="PASS",
                            timestamp=timestamp,
                            reason="OSPF Authentication Validation Passed."
                        )
                    )
                else:
                    results["metrics"]["ospf_auth_failed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_auth_check",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF Authentication Validation Failed"
                        }
                    )
                    results["critical_issues"].append({
                        "event_type": "ospf_auth_check",
                        "reason": "OSPF Authentication Validation Failed"
                    })
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_auth_check",
                            status="FAIL",
                            timestamp=timestamp,
                            reason="OSPF Authentication Validation Failed"
                        )
                    )
            except Exception as e:
                log.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "ospf_auth_check",
                        "status": StepStatus.ERROR.value,
                        "severity": "CRITICAL",
                        "error": str(e),
                        "component": "ospf_validator",
                        "message": "Try/Exception Error | OSPF Authentication Validation |"
                                   " authentication_ok"
                    }
                )
                results["checks"]["ospf_auth_check"] = False
                results["critical_issues"].append({
                    "event_type": "ospf_auth_check",
                    "reason": "Try/Exception Error | OSPF Authentication Validation |"
                                   " authentication_ok",
                    "details": str(e)
                })
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_validator",
                        event_type="ospf_auth_check",
                        status="ERROR",
                        error=str(e),
                        reason="Try/Exception Error | OSPF Authentication Validation |"
                                   " authentication_ok"
                    )
                )
            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "ospf_mtu_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Checking OSPF MTU Validation."
                }
            )
            try:
                mtu_ok = self.verify_ospf_mtu(device_ip, restconf_state, ospf_data)
                results["checks"]["ospf_mtu_check"] = mtu_ok
                results["metrics"]["checks_run"] += 1
                if mtu_ok:
                    results["ospf_mtu_passed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_mtu_check",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF MTU Validation Passed."
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_mtu_check",
                            status="PASS",
                            timestamp=timestamp,
                            reason="OSPF MTU Validation Passed."
                        )
                    )
                else:
                    results["metrics"]["ospf_mtu_failed"]  += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "ospf_mtu_check",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "OSPF MTU Validation Failed"
                        }
                    )
                    results["critical_issues"].append({
                        "event_type": "ospf_mtu_check",
                        "reason": "OSPF MTU Validation Failed"
                    })
                    results["events"].append(
                        build_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="ospf_mtu_check",
                            status="FAIL",
                            timestamp=timestamp,
                            reason= "OSPF MTU Validation Failed"
                        )
                    )
            except Exception as e:
                log.exception(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "ospf_mtu_check",
                        "status": StepStatus.ERROR.value,
                        "severity": "CRITICAL",
                        "component": "ospf_validator",
                        "error": str(e),
                        "message": "Try/Exception Error | OSPF MTU Validation  | "
                                   "mtu_ok"
                    }
                )
                results["checks"]["ospf_mtu_check"] = False
                results["critical_issues"].append({
                    "event_type": "ospf_mtu_check",
                    "reason": "Try/Exception Error | OSPF MTU Validation  | "
                                   "mtu_ok",
                    "detail": str(e)
                })

                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_validator",
                        event_type="ospf_mtu_check",
                        status="ERROR",
                        timestamp=timestamp,
                        error=str(e),
                        reason="Try/Exception Error | OSPF MTU Validation  | "
                                   "mtu_ok"
                    )
                )

            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "lsa_age_check",
                    "status": "CHECKING",
                    "severity": "INFO",
                    "component": "ospf_validator",
                    "message": "Validating OSPF LSA Ages"
                }
            )
            try:
                lsa_status, lsa_age = self.check_lsa_age(device_ip, restconf_state)
                results["lsa_age_seconds"] = lsa_age
                results["metrics"]["checks_run"] += 1
                if lsa_status == "healthy":
                    results["checks"]["lsa_age_check"] = True
                    results["metrics"]["lsa_age_passed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "lsa_age_check",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "ospf_validator",
                            "message": "OSPF LSA Age Validation Passed."
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="lsa_age_check",
                            status="PASS",
                            timestamp=timestamp,
                            reason= "OSPF LSA Age Validation Passed."
                        )
                    )
                elif lsa_status == "degraded":
                    results["checks"]["lsa_age_check"] = True
                    results["warnings"].append({
                        "event_type": "las_age_check",
                        "reason": f"OSPF LSA Age Degraded | Max Age: {lsa_age}"
                    })

                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "lsa_age_check",
                            "status": "DEGRADED",
                            "severity": "WARNING",
                            "component": "ospf_validator",
                            "message": f"OSPF LSA Age Degraded | Max Age: {lsa_age}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="lsa_age_check",
                            status="DEGRADED",
                            severity="WARNING",
                            lsa_age=lsa_age
                        )
                    )

                elif lsa_status == "stale":
                    results["metrics"]["lsa_age_failed"] += 1
                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "lsa_age_check",
                            "status": "FAIL",
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": f"OSPF LSA Age Validation Failed. Max Age: {lsa_age}"
                        }
                    )
                    results["checks"]["lsa_age_check"] = False
                    results["critical_issues"].append({
                        "event_type": "lsa_age_check",
                        "reason": f"OSPF LSA Age Validation Failed. Max Age: {lsa_age}"
                    })
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="lsa_age_check",
                            status="FAIL",
                            reason="OSPF LSA Age Validation Failed",
                            timestamp=timestamp,
                            lsa_age=lsa_age
                        )
                    )
                else:
                    results["checks"]["lsa_age_check"] = False

                    log.info(
                        "ospf_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "lsa_age_check",
                            "status": StepStatus.ERROR.value,
                            "severity": "CRITICAL",
                            "component": "ospf_validator",
                            "message": "Unable to determine OSPF LSA state"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="ospf_validator",
                            event_type="lsa_age_check",
                            status="ERROR",
                            timestamp=timestamp,
                            reason="Unable to determine OSPF LSA state"

                        )
                    )
            except Exception as e:
                log.exception(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "lsa_age_check",
                        "status": StepStatus.ERROR.value,
                        "severity": "CRITICAL",
                        "component": "ospf_validator",
                        "error": str(e),
                        "message": "Try/Exception Error | OSPF LSA Age Validation | "
                                   "lsa_age_check"
                    }
                )
                results["checks"]["lsa_age_check"] = False
                results["critical_issues"].append({
                    "event_type": "lsa_age_check",
                    "reason": "Try/Exception Error | OSPF LSA Age Validation | "
                                   "lsa_age_check",
                    "details": str(e)
                })
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_validator",
                        event_type="lsa_age_check",
                        status="ERROR",
                        timestamp=timestamp,
                        error=str(e),
                        reason=("Try/Exception Error | OSPF LSA Age Validation | "
                                   "lsa_age_check")
                    )
                )

            if results["critical_issues"]:
                results["status"] = "FAILED"
                severity = "CRITICAL"
            elif results["warnings"]:
                results["status"] = "DEGRADED"
                severity = "WARNING"
            else:
                results["status"] = "HEALTHY"
                severity = "INFO"

            checks_passed = sum(1 for v in results["checks"].values() if v)
            checks_total = len(results["checks"])

            results["metrics"]["checks_passed"] = checks_passed
            results["metrics"]["checks_failed"] = (
                checks_total - checks_passed
            )
            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "ospf_overall_validation",
                    "status": results["status"],
                    "severity": severity,
                    "component": "ospf_validator",
                    "message": "OSPF Validation Complete.",
                    "checks_passed": checks_passed,
                    "checks_total": checks_total,
                    "critical_issues": len(results["critical_issues"]),
                    "warnings": len(results["warnings"]),

                }
            )
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="ospf_validator",
                    event_type="ospf_overall_validation",
                    status=results["status"],
                    severity=severity,
                    checks_passed=checks_passed,
                    checks_total=checks_total
                )
            )

            return results
        except Exception as e:
            log.exception(
                f"[{device_ip}] Try/Exception Error | OSPF Validation |"
                f" Function: def validate_device_ospf | Error: {e}"
            )
            results["status"] = "ERROR"
            results["critical_issues"].append({
                "event_type": "overall_validation",
                "reason": f"[{device_ip}] Try/Exception Error | OSPF Validation |"
                f" Function: def validate_device_ospf,",
                "details": str(e)
            })

            log.exception(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "overall",
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
def configure_vlan(conn, device_ip, vlan_data, log):
    vlan_id, name = vlan_data.get("vlan_id", ""), vlan_data.get("name", "")
    timestamp = datetime.utcnow().isoformat()
    results = {
        "device_ip": device_ip,
        "vlan_id": vlan_id,
        "name": name,
        "configured": False,
        "validated": False,
        "status": OpStatus.PENDING.value,
        "component": "vlan_automation",

        "timestamp": timestamp,
        "summary": None,
        "summary_config": None,
        "summary_validation": None,
        "events": []
    }
    try:
        log.info(
            "vlan_check",
            extra={
                "device_ip": device_ip,
                "event_type": "vlan_config",
                "severity": "INFO",
                "component": "vlan_automation",
                "message": f"Configuring VLAN | VLAN: {vlan_id} | Name: {name}"
            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.DRY_RUN.value
            results["summary_config"] = (f"[DRY-RUN] Would Configure VLAN "
                                         f"| VLAN {vlan_id} | {name}")

            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="vlan_automation",
                    event_type="vlan_config",
                    outcome="DRY_RUN",
                    vlan_id=vlan_id,
                    name=name,
                    timestamp=timestamp,
                    reason=(f"[DRY-RUN] Would Configure VLAN "
                            f"| VLAN {vlan_id} | {name}")

                )
            )
        else:
            template = template_env.get_template("vlan.j2")
            commands = template.render(
                vlan_id=vlan_id,
                name=name
            )

            configured, error = safe_send_config(conn, commands)
            results["configured"] = configured

            if not configured:
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = f"VLAN Config Failed | VLAN: {vlan_id} | Name: {name}"

                log.info(
                    "vlan_check",
                    extra={
                        "device_ip": device_ip,
                        "component": "vlan_automation",
                        "event_type": "vlan_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "CRITICAL",
                        "timestamp": timestamp,
                        "message":f"VLAN Config Failed | VLAN: {vlan_id} | Name: {name}"
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="vlan_automation",
                        event_type="vlan_config",
                        outcome="FAIL",
                        vlan_id=vlan_id,
                        name=name,
                        timestamp=timestamp,
                        error=error
                    )
                )
            else:
                results["summary_config"] = f"VLAN Successfully Configured | VLAN: {vlan_id} | Name: {name}"
                results["status"] = OpStatus.CONFIGURED.value
                log.info(
                    "vlan_check",
                    extra = {
                        "device_ip": device_ip,
                        "event_type": "vlan_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "INFO",
                        "component": "vlan_automation",
                        "message": f"VLAN Successfully Configured | VLAN: {vlan_id} | Name: {name}",
                        "timestamp": timestamp

                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="vlan_automation",
                        event_type="vlan_config",
                        outcome="SUCCESS",
                        vlan_id=vlan_id,
                        name=name,
                        reason=f"VLAN Successfully Configured | VLAN: {vlan_id} | Name: {name}",
                        timestamp=timestamp
                    )
                )
                device_state = collect_device_state(conn)

                vlan_ok = check_vlan(device_state, vlan_id, name)

                results["validated"] = vlan_ok

                if vlan_ok:
                    results["status"] = OpStatus.SUCCESS.value
                    results["summary_validation"] = f"VLAN Validation Successful | VLAN: {vlan_id} | Name: {name}"
                    log.info(
                        "vlan_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "vlan_validation",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "vlan_automation",
                            "message": f"VLAN Validation Successful | VLAN: {vlan_id} | Name: {name}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="vlan_automation",
                            event_type="vlan_validation",
                            outcome="SUCCESS",
                            vlan_id=vlan_id,
                            name=name,
                            timestamp=timestamp,
                            reason=f"VLAN Validation Successful | VLAN: {vlan_id} | Name: {name}",
                        )
                    )
                else:
                    results["status"] = OpStatus.VALIDATION_FAILED.value
                    results["summary_validation"] = f"VLAN Validation Failed | VLAN: {vlan_id} | Name: {name}"
                    log.info(
                        "vlan_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "vlan_validation",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "vlan_automation",
                            "message": f"VLAN Validation Failed  | VLAN: {vlan_id} | Name: {name}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="vlan_automation",
                            event_type="vlan_validation",
                            outcome="FAIL",
                            vlan_id=vlan_id,
                            name=name,
                            reason=f"VLAN Validation Failed  | VLAN: {vlan_id} | Name: {name}",
                            timestamp=timestamp
                        )
                    )

    except Exception as e:
        results["error"] = str(e)
        results["status"] = OpStatus.ERROR.value
        log.exception(
            "vlan_check",
            extra={
                "device_ip": device_ip,
                "event_type": "vlan_config",
                "status": StepStatus.ERROR.value,
                "severity": "CRITICAL",
                "error": str(e),
                "component": "vlan_automation",
                "message": "Try/Exception Error | VLAN Configuration | "
                           "Function: def configure_vlan",
            },

        )
        results["events"].append(
            emit_event(
                device_ip=device_ip,
                component="vlan_automation",
                event_type="vlan_config",
                outcome="ERROR",
                vlan_id=vlan_id,
                name=name,
                error=str(e),
                timestamp=timestamp,
                reason="Exception Error"
            )
        )

    results["summary"] = (
            results["summary_validation"]
            or results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="vlan_automation",
            event_type="vlan_overall",
            outcome=(
                "DRY_RUN" if DRY_RUN else "SUCCESS"
                if results["status"] == OpStatus.SUCCESS.value
                else "FAIL"
            ),
            vlan_id=vlan_id,
            name=name,
            timestamp=timestamp,
            reason="VLAN Automation completed"
        )
    )

    return results
def configure_access_ports(conn, device_ip, access_data, log):
    access_interface,  access_vlan = access_data["access_interface"], access_data["access_vlan"]
    timestamp = datetime.utcnow().isoformat()
    results = {
        "device_ip": device_ip,
        "interface": access_interface,
        "vlan_id": access_vlan,
        "configured": False,
        "validated": False,
        "status": OpStatus.PENDING.value,
        "component": "access_port_automation",

        "timestamp": timestamp,
        "summary": None,
        "summary_config": None,
        "summary_validation": None,
        "events": []
    }
    try:
        log.info(
            "access_port_check",
            extra={
                "device_ip": device_ip,
                "event_type": "access_port_config",
                "severity": "INFO",
                "component": "access_port_automation",
                "message": f"Configuring Access Port | Interface: {access_interface} |"
                           f" VLAN: {access_vlan}"
            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.SUCCESS.value
            results["summary_config"] = (f"[DRY-RUN] Would Configure Access Port | "
                                         f"Interface: {access_interface} | VLAN: {access_vlan}")
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="access_port_automation",
                    event_type="access_port_config",
                    outcome="DRY_RUN",
                    vlan_id=access_vlan,
                    interface=access_interface,
                    timestamp=timestamp,
                    reason=(f"[DRY-RUN] Would Configure Access Port | "
                                         f"Interface: {access_interface} | VLAN: {access_vlan}")
                )
            )
            return results
        else:
            template = template_env.get_template("access_port.j2")
            commands = template.render(
                access_interface=access_interface,
                access_vlan=access_vlan
            )
            configured, error = safe_send_config(conn, commands)

            results["configured"] = configured

            if not configured:
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = (f"Access Port Config Failed | "
                                             f"Interface: {access_interface} | VLAN: {access_vlan} ")
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="access_port_automation",
                        event_type="access_port_config",
                        outcome="FAIL",
                        vlan_id=access_vlan,
                        interface=access_interface,
                        timestamp=timestamp,
                        error=error
                    )
                )
            else:
                results["summary_config"] = (f"Access Port Successfully Configured | "
                                             f"Interface: {access_interface} | VLAN: {access_vlan} ")
                results["status"] = OpStatus.CONFIGURED.value
                log.info(
                    "access_port_check",
                    extra = {
                        "device_ip": device_ip,
                        "event_type": "access_port_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "INFO",
                        "component": "access_port_automation",
                        "message": f"Access Port Successfully Configured | "
                                   f"Interface: {access_interface} | VLAN: {access_vlan}"

                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="access_port_automation",
                        event_type="access_port_config",
                        outcome="SUCCESS",
                        vlan_id=access_vlan,
                        interface=access_interface,
                        timestamp=timestamp,
                        reason=f"Access Port Successfully Configured | "
                                   f"Interface: {access_interface} | VLAN: {access_vlan}"

                    )
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
                    log.info(
                        "access_port_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "access_port_validation",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "access_port_automation",
                            "message": f"Access Port Validation Passed | VLAN: {access_vlan} | "
                                       f"Interface: {access_interface}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="access_port_automation",
                            event_type="access_port_validation",
                            outcome="SUCCESS",
                            vlan_id=access_vlan,
                            interface=access_interface,
                            timestamp=timestamp,
                            reason=f"Access Port Validation Passed | VLAN: {access_vlan} | "
                                       f"Interface: {access_interface}"
                        )
                    )
                    results["status"] = OpStatus.SUCCESS.value
                    results["summary_validation"] = (f"Access Port Validation Passed | VLAN: {access_vlan} | "
                                       f"Interface: {access_interface}")

                else:
                    log.info(
                        "access_port_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "access_port_validation",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "access_port_automation",
                            "message": f"Access Port Validation Failed | VLAN: {access_vlan} | "
                                       f"Interface: {access_interface}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="access_port_automation",
                            event_type="access_port_validation",
                            outcome="FAIL",
                            vlan_id=access_vlan,
                            interface=access_interface,
                            timestamp=timestamp,
                            reason=f"Access Port Validation Failed | VLAN: {access_vlan} | "
                                       f"Interface: {access_interface}"
                        )
                    )
                    results["status"] = OpStatus.VALIDATION_FAILED.value
                    results["summary_validation"] = (f"Access Port Validation Failed | VLAN: {access_vlan} | "
                                       f"Interface: {access_interface}")

    except Exception as e:
        log.exception(
            "access_port_check",
            extra={
                "device_ip": device_ip,
                "event_type": "access_port_config",
                "status": OpStatus.ERROR.value,
                "severity": "CRITICAL",
                "component": "access_port_automation",
                "error": str(e),
                "message": "Try/Exception Error | Access Port | Function: "
                           "def configure_access_ports"
            },
        )
        results["events"].append(
            emit_event(
                device_ip=device_ip,
                component="access_port_automation",
                event_type="access_port_config",
                outcome="ERROR",
                vlan_id=access_vlan,
                interface=access_interface,
                error=str(e),
                timestamp=timestamp,
                reason=f"Try/Exception Error | def configure_access_ports"
            )
        )
        results["status"] = OpStatus.ERROR.value
        results["error"] = str(e)

    results["summary"] = (
            results["summary_validation"]
            or results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="access_port_validation",
            event_type="access_port_overall",
            outcome=("DRY_RUN" if DRY_RUN
                     else "SUCCESS" if results["status"] == OpStatus.SUCCESS.value else "FAIL"),
            vlan_id=access_vlan,
            interface=access_interface,
            timestamp=timestamp,
            reason=f"Access Port Automation Completed."

        )
    )
    return results
def configure_trunk_ports(conn, device_ip, trunk_data, log):
    trunk_interface, allowed_vlans = (trunk_data.get("trunk_interface"),
                                      trunk_data.get("allowed_vlans"))
    timestamp = datetime.utcnow().isoformat()
    results = {
        "device_ip": device_ip,
        "interface": trunk_interface,
        "allowed_vlans": allowed_vlans,
        "configured": False,
        "validated": False,
        "status": OpStatus.PENDING.value,
        "component": "trunk_port_automation",

        "timestamp": timestamp,
        "summary": None,
        "summary_config": None,
        "summary_validation": None,
        "events": []
    }
    try:
        log.info(
            "trunk_port_check",
            extra={
                "device_ip": device_ip,
                "event_type": "trunk_port_config",
                "severity": "INFO",
                "component": "trunk_port_automation",
                "message": f"Configuring Trunk Port | Trunk: {trunk_interface} | "
                           f"Allowed VLANs: {allowed_vlans}"
            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.SUCCESS.value
            results["summary_config"] = (f"[DRY-RUN] Would Configure Trunk Port | "
                                         f"Interface: {trunk_interface} | Allowed VLANs: "
                                         f"{allowed_vlans}")
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="trunk_port_automation",
                    event_type="trunk_port_config",
                    outcome="DRY_RUN",
                    interface=trunk_interface,
                    allowed_vlans=allowed_vlans,
                    timestamp=timestamp,
                    reason=f"[DRY-RUN] Would Configure Trunk Port | "
                            f"Interface: {trunk_interface} | Allowed VLANs: "
                            f"{allowed_vlans}"
                )
            )
        else:
            template = template_env.get_template("trunk.j2")
            commands = template.render(
                trunk_interface=trunk_interface,
                allowed_vlans=allowed_vlans
            )

            configured, error = safe_send_config(conn, commands)

            results["configured"] = configured

            if not configured:
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = (f"Trunk Port Configuration Failed | Interface: "
                                             f"{trunk_interface} | Allowed VLANs: {allowed_vlans}")
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="trunk_port_automation",
                        event_type="trunk_port_config",
                        outcome="FAIL",
                        interface=trunk_interface,
                        allowed_vlans=allowed_vlans,
                        timestamp=timestamp,
                        error=error
                    )
                )
            else:
                results["summary_config"] =( f"Trunk Port Successfully Configured | Interface: {trunk_interface} | "
                                             f"Allowed VLANs: {allowed_vlans}")
                results["status"] = OpStatus.CONFIGURED.value
                log.info(
                    "trunk_port_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "trunk_port_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "INFO",
                        "component": "trunk_port_automation",
                        "message": f"Trunk Port Successfully Configured | Interface: {trunk_interface} | "
                                   f"Allowed VLANs: {allowed_vlans}"
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="trunk_port_automation",
                        event_type="trunk_port_config",
                        outcome="SUCCESS",
                        interface=trunk_interface,
                        allowed_vlans=allowed_vlans,
                        timestamp=timestamp,
                        reason=f"Trunk Port Successfully Configured | Interface: {trunk_interface} | "
                                   f"Allowed VLANs: {allowed_vlans}"
                    )
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
                    log.info(
                        "trunk_port_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "trunk_port_validation",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "trunk_port_automation",
                            "message": f"Trunk Port Validation Passed | Interface: {trunk_interface} | "
                                       f"Allowed VLANs: {allowed_vlans}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="trunk_port_automation",
                            event_type="trunk_port_validation",
                            outcome="SUCCESS",
                            interface=trunk_interface,
                            allowed_vlans=allowed_vlans,
                            timestamp=timestamp,
                            reason=f"Trunk Port Successfully Configured | Interface: {trunk_interface} | "
                                   f"Allowed VLANs: {allowed_vlans}"
                        )
                    )
                    results["status"] = OpStatus.SUCCESS.value
                    results["summary_validation"] = (f"Trunk Port Successfully Configured | Interface: {trunk_interface} | "
                                                    f"Allowed VLANs: {allowed_vlans}")
                else:
                    log.info(
                        "trunk_port_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "trunk_port_validation",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "trunk_port_automation",
                            "message": f"Trunk Port Validation Failed | Expected Interface: {trunk_interface} | "
                                       f"Expected Allowed VLANs: {allowed_vlans}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="trunk_port_automation",
                            event_type="trunk_port_validation",
                            outcome="FAIL",
                            interface=trunk_interface,
                            allowed_vlans=allowed_vlans,
                            timestamp=timestamp,
                            reason=f"Trunk Port Validation Failed | Expected Interface: {trunk_interface} | "
                                    f"Expected Allowed VLANs: {allowed_vlans}"
                        )
                    )
                    results["status"] = OpStatus.VALIDATION_FAILED.value
                    results["summary_validation"] = (f"Trunk Port Validation Failed | Expected Interface: {trunk_interface} | "
                                                    f"Expected Allowed VLANs: {allowed_vlans}")

    except Exception as e:
        log.exception(
            "trunk_port_check",
            extra={
                "device_ip": device_ip,
                "event_type": "trunk_port_config",
                "status": StepStatus.ERROR.value,
                "severity": "CRITICAL",
                "component": "trunk_port_automation",
                "error": str(e),
                "message": "Try/Exception Error | Trunk Port Config | "
                           "Function: def configure_trunk_ports"
            }
        )
        results["events"].append(
            emit_event(
                device_ip=device_ip,
                component="trunk_port_automation",
                event_type="trunk_port_config",
                outcome="ERROR",
                interface=trunk_interface,
                allowed_vlans=allowed_vlans,
                timestamp=timestamp,
                reason="Try Exception Error | def configure_trunk_ports"
            )
        )
        results["error"] = str(e)
        results["status"] = OpStatus.ERROR.value

    results["summary"] = (
        results["summary_validation"]
        or results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="trunk_port_automation",
            event_type="trunk_port_overall",
            outcome=("DRY_RUN"
                    if DRY_RUN
                    else "SUCCESS"
                    if results["status"] == OpStatus.SUCCESS.value
                    else "FAIL"),
            interface=trunk_interface,
            allowed_vlans=allowed_vlans,
            timestamp=timestamp,
            reason="Trunk Port Automation Complete"
        )
    )
    return results
def configure_interface(conn, device_ip, interface_data, log):
    interface = interface_data["interface"]
    description = interface_data["description"]
    timestamp = datetime.utcnow().isoformat()
    results = {
        "device_ip": device_ip,
        "interface": interface,
        "description": description,
        "configured": False,
        "validated": False,
        "status": OpStatus.PENDING.value,
        "component": "interface_automation",

        "timestamp": timestamp,
        "summary": None,
        "summary_config": None,
        "summary_validation": None,
        "events": []
    }
    try:
        log.info(
            "interface_check",
            extra={
                "device_ip": device_ip,
                "event_type": "interface_config",
                "severity": "INFO",
                "component": "interface_automation",
                "message": f"Configuring Interface Status/Protocol to Up/Up | Interface"
                           f": {interface}"
            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.DRY_RUN.value
            results["summary_config"] = (f"[DRY_RUN] Would Configure Interface Status/Protocol to"
                                         f" Up/Up | Interface: {interface}")
            log.info(
                "interface_check",
                extra={
                    "device_ip": device_ip,
                    "component": "interface_automation",
                    "event_type": "interface_config",
                    "severity": "INFO",
                    "message": (f"[DRY_RUN] Would Configure Interface Status/Protocol to"
                                 f" Up/Up | Interface: {interface}")
                }
            )
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="interface_automation",
                    event_type="interface_config",
                    outcome="DRY_RUN",
                    interface=interface,
                    timestamp=timestamp,
                    reason= (f"[DRY_RUN] Would Configure Interface Status/Protocol to"
                             f" Up/Up | Interface: {interface}")
                )
            )
        else:
            template = template_env.get_template("interface.j2")
            commands = template.render(interface=interface,
                                       description=description)

            configured, error = safe_send_config(conn, commands)

            results["configured"] = configured
            if not configured:
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = (f"[DRY_RUN] Would Configure Interface Status/Protocol to"
                                             f" Up/Up | Interface: {interface}")
                log.info(
                    "interface_check",
                    extra={
                        "device_ip": device_ip,
                        "component": "interface_automation",
                        "event_type": "interface_config",
                        "status": StepStatus.FAILED.value,
                        "severity": "CRITICAL",
                        "error": error,

                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="interface_automation",
                        event_type="interface_config",
                        outcome="FAIL",
                        interface=interface,
                        timestamp=timestamp,
                        reason=(f"[DRY_RUN] Would Configure Interface Status/Protocol to"
                                f" Up/Up | Interface: {interface}")
                    )
                )
            else:
                results["summary_config"] = f"Interface Successfully Configured | Interface: {interface}"
                results["status"] = OpStatus.CONFIGURED.value
                log.info(
                    "interface_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "interface_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "INFO",
                        "component": "interface_automation",
                        "message": f"Interface Successfully Configured | Interface: {interface}"
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="interface_automation",
                        event_type="interface_config",
                        outcome="SUCCESS",
                        interface=interface,
                        timestamp=timestamp,
                        reason=f"Interface Successfully Configured | Interface: {interface}"

                    )
                )

                device_state = collect_device_state(conn)

                interface_ok = check_interface(device_state, interface)

                results["validated"] = interface_ok

                if interface_ok:
                    results["status"] = OpStatus.SUCCESS.value
                    results["summary_validation"] = (f"Interface (Status/Protocol) Validation Passed "
                                                     f"| Interface: {interface}")
                    log.info(
                        "interface_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "interface_validation",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "interface_automation",
                            "message":  (f"Interface (Status/Protocol) Validation Passed "
                                                     f"| Interface: {interface}")
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="interface_automation",
                            event_type="interface_validation",
                            outcome="SUCCESS",
                            interface=interface,
                            timestamp=timestamp,
                            reeason=  (f"Interface (Status/Protocol) Validation Passed "
                                                     f"| Interface: {interface}")
                        )
                    )
                else:
                    results["status"] = OpStatus.VALIDATION_FAILED.value
                    results["summary_validation"] =  (f"Interface (Status/Protocol) Validation Failed "
                                                     f"| Interface: {interface}")
                    log.info(
                        "interface_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "interface_validation",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "interface_automation",
                            "message": f"Interface (Status/Protocol) Validation Failed "
                                       f"| Interface: {interface}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="interface_automation",
                            event_type="interface_validation",
                            outcome="FAIL",
                            interface=interface,
                            timestamp=timestamp,
                            reason= (f"Interface (Status/Protocol) Validation Failed "
                                                     f"| Interface: {interface}")
                        )
                    )
    except Exception as e:
        results["error"] = str(e)
        results["status"] = OpStatus.ERROR.value
        log.exception(
            "interface_check",
            extra={
                "device_ip": device_ip,
                "event_type": "interface_config",
                "status": StepStatus.ERROR.value,
                "error": str(e),
                "component": "interface_automation",
                "severity": "CRITICAL",
                "message": "Try/Exception Error | Interface Config | "
                           "Function: def configure_interface"
                },
        )
        results["events"].append(
            emit_event(
                device_ip=device_ip,
                component="interface_automation",
                event_type="inteface_config",
                outcome="ERROR",
                interface=interface,
                timestamp=timestamp,
                reason="Try/Exception Error | def configure_interface"
            )
        )
        return results

    results["summary"] = (
        results["summary_validation"]
        or results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="interface_automation",
            event_type="interface_overall",
            outcome=(
                "DRY_RUN" if DRY_RUN else "SUCCESS"
                if results["status"] == OpStatus.SUCCESS.value else "FAIL"),
            interface=interface,
            timestamp=timestamp,
            reason="Interface (Status/Protocol) Automation Complete"
        )
    )
    return results
def configure_roas(device_ip, roas_data, session, log):
    router_interface = roas_data["router_interface"]
    router_vlan = roas_data["router_vlan"]
    ip = roas_data["ip"]
    mask = roas_data["mask"]
    timestamp = datetime.utcnow().isoformat()
    new_interface = "".join([c for c in router_interface if c.isdigit() or c == "/" or c == "."])
    url = (f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/"
           f"interface/GigabitEthernet={new_interface}")
    results = {
        "device_ip": device_ip,
        "router_interface": router_interface,
        "router_vlan": router_vlan,
        "ip": f"{ip}/{mask}",
        "configured": False,
        "validated": False,

        "status": "PENDING",
        "summary_config": None,
        "summary_validation": None,
        "summary": None,
        "events": [],
        "component": "roas_automation"

    }

    try:
        log.info(
            "roas_check",
            extra={
                "device_ip": device_ip,
                "event_type": "roas_config",
                "severity":"INFO",
                "component": "roas_automation",
                "message": f"Configuring ROAS | Interface: {router_interface}.{router_vlan} |"
                           f" VLAN: {router_vlan} | IP: {ip}/{mask}"

            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.DRY_RUN.value
            results["summary_config"] = (f"[DRY_RUN] Would Configure ROAS | Interface: "
                                         f"{router_interface}.{router_vlan} | VLAN: {router_vlan} | "
                                         f"IP: {ip}/{mask}")
            log.info(
                "roas_check",
                extra={
                    "device_ip": device_ip,
                    "component": "roas_automation",
                    "event_type": "roas_config",
                    "severity": "INFO",
                    "message": f"[DRY_RUN] Would Configure ROAS | Interface: "
                               f"{router_interface}.{router_vlan} | VLAN: {router_vlan} | "
                               f"IP: {ip}/{mask}"
                }
            )
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="roas_automation",
                    event_type="roas_config",
                    outcome="DRY_RUN",
                    interface=router_interface,
                    vlan_id=router_vlan,
                    ip=f"{ip}/{mask}",
                    timestamp=timestamp,
                    reason=(f"[DRY_RUN] Would Configure ROAS | Interface: "
                            f"{router_interface}.{router_vlan} | VLAN: {router_vlan} | "
                            f"IP: {ip}/{mask}")
                )
            )
        else:
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
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = (f"ROAS Configuration Failed | Interface: {router_interface}.{router_vlan} |"
                                             f" VLAN: {router_vlan} | IP: {ip}/{mask}")
                log.info(
                    "roas_check",
                    extra={
                        "device_ip": device_ip,
                        "component": "roas_automation",
                        "event_type": "roas_config",
                        "status": StepStatus.FAILED.value,
                        "severity": "CRITICAL",
                        "message": (f"ROAS Configuration Failed | Interface: {router_interface}.{router_vlan} |"
                                             f" VLAN: {router_vlan} | IP: {ip}/{mask}")
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="roas_automation",
                        event_type="roas_config",
                        outcome="FAIL",
                        interface=router_interface,
                        vlan=router_vlan,
                        ip=f"{ip}/{mask}",
                        error=error,
                        timestamp=timestamp,
                        reason= (f"ROAS Configuration Failed | Interface: {router_interface}.{router_vlan} |"
                                             f" VLAN: {router_vlan} | IP: {ip}/{mask}")
                    )

                )
            else:
                results["summary_config"] = (f"ROAS Successfully Configured | Interface: {router_interface}.{router_vlan} | "
                                             f"VLAN: {router_vlan} | IP: {ip}/{mask}")
                results["status"] = OpStatus.CONFIGURED.value
                log.info(
                    "roas_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "roas_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "INFO",
                        "component": "roas_automation",
                        "message": f"ROAS Successfully Configured | Interface: {router_interface}.{router_vlan} | "
                                   f"VLAN: {router_vlan} | IP: {ip}/{mask}"
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="roas_automation",
                        event_type="roas_config",
                        outcome="SUCCESS",
                        severity="INFO",
                        interface=router_interface,
                        vlan=router_vlan,
                        ip=f"{ip}/{mask}",
                        timestamp=timestamp,
                        reason=(f"ROAS Successfully Configured | Interface: {router_interface}.{router_vlan} | "
                                      f"VLAN: {router_vlan} | IP: {ip}/{mask}")
                    )
                )

                state = restconf_state(device_ip, session)
                roas_ok = check_roas(state, roas_data)
                results["validated"] = roas_ok

                if roas_ok:
                    results["status"] = OpStatus.SUCCESS.value
                    results["summary_validation"] = (f"ROAS Validation Passed | Interface: {router_interface}.{router_vlan} | "
                                                     f"IP: {ip}/{mask}")
                    log.info(
                        "roas_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "roas_validation",
                            "status": "PASS",
                            "severity": "INFO",
                            "component": "roas_automation",
                            "message": f"ROAS Validation Passed | Interface: {router_interface}.{router_vlan} | "
                                       f"IP: {ip}/{mask}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="roas_automation",
                            event_type="roas_validation",
                            outcome="SUCCESS",
                            interface=router_interface,
                            vlan=router_vlan,
                            ip=f"{ip}/{mask}",
                            timestamp=timestamp,
                            reason=(f"ROAS Validation Passed | Interface: {router_interface}.{router_vlan} | "
                                          f"IP: {ip}/{mask}")
                        )
                    )
                else:
                    results["status"] = OpStatus.VALIDATION_FAILED.value
                    results["summary_validation"] = (f"ROAS Validation Failed | Interface: {router_interface}.{router_vlan} | "
                                                 f"IP: {ip}/{mask}")
                    log.info(
                        "roas_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "roas_validation",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "roas_automation",
                            "message": f"ROAS Validation Failed | Interface: {router_interface}.{router_vlan} | "
                                       f"IP: {ip}/{mask}"
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="roas_automation",
                            event_type="roas_validation",
                            status="FAIL",
                            interface=router_interface,
                            vlan=router_vlan,
                            ip=f"{ip}/{mask}",
                            reason=(f"ROAS Validation Failed | Interface: {router_interface}.{router_vlan} | "
                                          f"IP: {ip}/{mask}")
                        )
                    )

    except Exception as e:
        results["status"] = OpStatus.ERROR.value
        results["error"] = str(e)
        log.exception(
            "roas_check",
            extra={
                "device_ip": device_ip,
                "event_type": "roas_config",
                "status": "ERROR",
                "severity": "CRITICAL",
                "component": "roas_automation",
                "error": str(e),
                "message": "Try/Exception Error | ROAS Config | Function: def configured_roas"
            },
        )
        results["events"].append(
            build_event(
                device_ip=device_ip,
                component="roas_automation",
                event_type="roas_config",
                status=StepStatus.ERROR.value,
                interface=router_interface,
                vlan=router_vlan,
                ip=f"{ip}/{mask}",
                error=str(e)
            )
        )
        return results

    results["summary"] = (
        results["summary_validation"]
        if results["validated"] else results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="roas_automation",
            event_type="roas_overall",
            outcome=(
                "DRY_RUN" if DRY_RUN else "SUCCESS"
                if results["status"] == OpStatus.SUCCESS.value
                else "FAIL"
            ),
            interface=router_interface,
            vlan_id=router_vlan,
            ip=f"{ip}/{mask}",
            timestamp=timestamp,
            reason="ROAS Automation Complete"
        )
    )
    return results
def configure_ospf(device_ip, ospf_data, session, log):
    process_id = ospf_data["process_id"]
    router_id = ospf_data["router_id"]
    network_list = ospf_data["network_list"]
    network_log = []
    timestamp = datetime.utcnow().isoformat()
    for network in network_list:
        subnet = network.get("subnet", "")
        wildcard = network.get("wildcard", "")
        area = network.get("area", "")

        network_log.append(
            f"{subnet}/{wildcard} Area: {area}"
        )
    network = " | ".join(network_log)
    url = f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/router"
    results = {
        "device_ip": device_ip,
        "process_id": process_id,
        "router_id": router_id,
        "configured": False,
        "validated": "PENDING",
        "status": "PENDING",

        "timestamp": timestamp,
        "summary_config": None,
        "summary_validation": None,
        "summary": None,
        "event": [],
        "component": "ospf_automation"
    }
    try:
        log.info(
            "ospf_check",
            extra={
                "device_ip": device_ip,
                "event_type": "ospf_config",
                "severity": "INFO",
                "component": "ospf_automation",
                "timestamp": timestamp,
                "message": f"Configuring OSPF | Process ID: {process_id} | "
                           f"RID: {router_id} | Networks: {network}"
            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.DRY_RUN.value
            results["summary_config"] = (f"[DRY_RUN] Would Configure OSPF | Process ID: {process_id} | "
                                        f"RID: {router_id} | Networks: {network}")
            log.info(
                "ospf_check",
                extra={
                    "device_ip": device_ip,
                    "component": "ospf_automation",
                    "event_type": "ospf_config",
                    "status": StepStatus.DRY_RUN.value,
                    "severity": "INFO",
                    "timestamp": timestamp,
                    "message": (f"[DRY_RUN] Would Configure OSPF | Process ID: {process_id} | "
                                f"RID: {router_id} | Networks: {network}")
                }
            )
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="ospf_automation",
                    event_type="ospf_config",
                    outcome="DRY_RUN",
                    proces_id=process_id,
                    router_id=router_id,
                    network_count=len(network_list),
                    networks= [n["subnet"] for n in network_list],
                    timestamp=timestamp,
                    reason=(f"[DRY_RUN] Would Configure OSPF | Process ID: {process_id} | "
                            f"RID: {router_id} | Networks: {network}")
                )
            )
        else:
            template = template_env.get_template("Cisco_Router_OSPF.j2")
            commands = template.render(
                process_id=process_id,
                router_id=router_id,
                network_list=network_list
            )
            configured, error = safe_restconf_patch(session,url, commands)

            results["configured"] = configured

            if not configured:
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = (
                    f"OSPF Configuration Failed | Process ID: {process_id} | "
                               f"RID: {router_id} | Networks: {network}"
                )
                log.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "component": "ospf_automation",
                        "event_type": "ospf_config",
                        "status": StepStatus.FAILED.value,
                        "severity": "CRITICAL",
                        "timestamps": timestamp,
                        "message": (
                               f"OSPF Configuration Failed | Process ID: {process_id} | "
                               f"RID: {router_id} | Networks: {network}"
                )
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="ospf_automation",
                        event_type="ospf_config",
                        outcome="FAIL",
                        process_id=process_id,
                        router_id=router_id,
                        network_count=len(network_list),
                        networks=[n["subnet"] for n in network_list],
                        error=error,
                        timestamp=timestamp,
                        reason="OSPF configuration failed"
                    )
                )
            else:
                results["status"] = OpStatus.CONFIGURED.value
                results["summary_config"] = (
                    f"OSPF Successfully Configured | Process ID: {process_id} | "
                    f"RID: {router_id} | Networks: {network}"
                )
                log.info(
                    "ospf_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "ospf_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "INFO",
                        "component": "ospf_automation",
                        "timestamp": timestamp,
                        "message": f"OSPF Successfully Configured | Process ID: {process_id} | "
                               f"RID: {router_id} | Networks: {network}"
                    }
                )
                results["events"].append(
                    build_event(
                        device_ip=device_ip,
                        component="ospf_automation",
                        event_type="ospf_config",
                        outcome=StepStatus.SUCCESS.value,
                        process_id=process_id,
                        router_id=router_id,
                        network_count=len(network_list),
                        networks=[n["subnet"] for n in network_list],
                        timestamp=timestamp,
                        reason=(f"OSPF Successfully Configured")
                    )
                )
    except Exception as e:
        log.exception(
            "ospf_check",
            extra={
                "device_ip": device_ip,
                "event_type": "ospf_config",
                "status": "ERROR",
                "severity": "CRITICAL",
                "component": "ospf_automation",
                "error": str(e),
                "timestamp": timestamp,
                "message": f"Try/Exception Error | OSPF Config Failed | Function: "
                           f"def configure_ospf"
            },)
        results["events"].append(
            build_event(
                device_ip=device_ip,
                component="ospf_automation",
                event_type="ospf_config",
                outcome=StepStatus.ERROR.value,
                process_id=process_id,
                router_id=router_id,
                network_count=len(network_list),
                networks=[n["subnet"] for n in network_list],
                error=str(e),
                timestamp=timestamp,
                reason="Try/Exception Error | def configure_ospf"
            )
        )
        results["configured"] = False
        results["validated"] = False
        results["error"] = str(e)
        results["status"] = OpStatus.ERROR.value
        return results
    results["summary"] = (
        results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="ospf_automation",
            event_type="ospf_overall",
            outcome=(
                "DRY_RUN" if DRY_RUN else "SUCCESS"
                if results["status"] == OpStatus.SUCCESS.value else "FAIL"
            ),
            process_id=process_id,
            router_id=router_id,
            network_count=len(network_list),
            networks=[n["subnet"] for n in network_list],
            timestamp=timestamp,
            reason="OSPF Automation Complete"
        )
    )
    return results
def configure_acl(session, device_ip, acl_data, log):
    acl_name = acl_data.get("acl_name")
    rules = acl_data.get("rules")
    timestamp = datetime.utcnow().isoformat()

    rules_summary = [
        f"{r['sequence']} {r['action']} {r['protocol']}"
        for r in rules
    ]

    results = {
        "device_ip": device_ip,
        "acl_name": acl_name,
        "configured": False,
        "validated": False,
        "status": OpStatus.PENDING.value,
        "component": "acl_automation",
        "timestamp": timestamp,
        "summary": None,
        "summary_config": None,
        "summary_validation": None,
        "events": []
    }
    try:
        log.info(
            "acl_check",
            extra={
                "device_ip": device_ip,
                "event_type": "acl_config",
                "component": "acl_automation",
                "acl_name": acl_name,
                "rule_count": len(rules),
                "rule_list": rules_summary,
                "message": f"Configuring ACLs via NETCONF | Name: {acl_name} | "
                           f"Rules: {len(rules)}"
            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.DRY_RUN.value
            results["summary_config"] = (
                f"[DRY-RUN] Would Configure Extended ACL via NETCONF | Name: {acl_name} "
                f"Rules: {len(rules)}"
            )
            log.info(
                "acl_check",
                extra= {
                    "device_ip": device_ip,
                    "component": "acl_automation",
                    "event_type": "acl_config",
                    "status": StepStatus.DRY_RUN.value,
                    "acl_name": acl_name,
                    "rule_count": len(rules),
                    "rule_list": rules_summary,
                    "message": (
                        f"[DRY-RUN] Would Configure Extended ACL via NETCONF | Name: {acl_name} "
                        f"Rules: {len(rules)}"
                    )
                }
            )
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="acl_automation",
                    event_type="acl_config",
                    outcome=StepStatus.DRY_RUN.value,
                    acl_name=acl_name,
                    rule_count=len(rules),
                    rule_summary=rules_summary,
                    timestamp=timestamp,
                    reason=(
                        f"[DRY-RUN] Would Configure Extended ACL via NETCONF | Name: {acl_name} "
                        f"Rules: {len(rules)}"
                    )
                )
            )
        else:
            template = template_env.get("ACL.j2")
            commands = template.render(
                acl_name=acl_name,
                rules=rules
            )

            configured, error = safe_netconf_edit(
                session, commands
            )
            results["configured"] = configured

            if not configured:
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = (
                    f"Failed to Configure Extended ACL via NETCONF | Name: {acl_name} "
                    f"Rules: {len(rules)}"
                )
                log.info(
                    "acl_check",
                    extra= {
                        "device_ip": device_ip,
                        "component": "acl_automation",
                        "event_type": "acl_config",
                        "status": StepStatus.FAILED.value,
                        "acl_name": acl_name,
                        "rule_count": len(rules),
                        "rule_list": rules_summary,
                        "message": (
                            f"Failed to Configure Extended ACL via NETCONF | Name: {acl_name} "
                            f"Rules: {len(rules)}"
                        )
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="acl_automation",
                        event_type="acl_config",
                        outcome=StepStatus.FAILED.value,
                        acl_name=acl_name,
                        rule_count=len(rules),
                        rule_summary=rules_summary,
                        timestamp=timestamp,
                        reason=(
                            f"Failed to Configure Extended ACL via NETCONF | Name: {acl_name} "
                            f"Rules: {len(rules)}"
                        )
                    )
                )
            else:
                results["status"] = OpStatus.CONFIGURED.value
                results["summary_config"] = (
                    f"Successfully Configured Extended ACL via NETCONF | Name: {acl_name} "
                    f"Rules: {len(rules)}"
                )
                log.info(
                    "acl_check",
                    extra= {
                        "device_ip": device_ip,
                        "component": "acl_automation",
                        "event_type": "acl_config",
                        "status": StepStatus.SUCCESS.value,
                        "acl_name": acl_name,
                        "rule_count": len(rules),
                        "rule_list": rules_summary,
                        "message": (
                            f"Successfully Configured Extended ACL via NETCONF | Name: {acl_name} "
                            f"Rules: {len(rules)}"
                        )
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="acl_automation",
                        event_type="acl_config",
                        outcome=StepStatus.SUCCESS.value,
                        acl_name=acl_name,
                        rule_count=len(rules),
                        rule_summary=rules_summary,
                        timestamp=timestamp,
                        reason=(
                            f"Successfully Configured Extended ACL Name: {acl_name} "
                            f"Rules: {len(rules)} | API: NETCONF"
                        )
                    )
                )
                actual_native = collect_netconf_state(session)

                actual_acls = build_acl_state(actual_native)

                acl_ok, failures = check_acl(
                    actual_acls,
                    [acl_data]
                )

                results["validated"] = acl_ok
                results["failures"] = failures


                if acl_ok:
                    results["status"] = OpStatus.SUCCESS.value
                    results["summary_validation"] = (
                        f"Extended ACL Validation Successful | Name: {acl_name} "
                        f"Rules: {len(rules)} | API: NETCONF"
                    )
                    log.info(
                        "acl_check",
                        extra= {
                            "device_ip": device_ip,
                            "component": "acl_automation",
                            "event_type": "acl_validation",
                            "status": StepStatus.SUCCESS.value,
                            "acl_name": acl_name,
                            "rule_count": len(rules),
                            "rule_list": rules_summary,
                            "message": (
                                 f"Extended ACL Validation Successful | Name: {acl_name} "
                                 f"Rules: {len(rules)} | API: NETCONF"
                            )
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="acl_automation",
                            event_type="acl_validation",
                            outcome=StepStatus.SUCCESS.value,
                            acl_name=acl_name,
                            rule_count=len(rules),
                            rule_summary=rules_summary,
                            timestamp=timestamp,
                            reason=(
                                f"Extended ACL Validation Successful | Name: {acl_name} "
                                f"Rules: {len(rules)} | API: NETCONF"
                            )
                        )
                    )
                else:
                    results["status"] = OpStatus.VALIDATION_FAILED.value
                    results["summary_validation"] = (
                        f"Extended ACL Validation Failed | Name: {acl_name} "
                        f"Rules: {len(rules)} | Failures: {failures} | "
                        f"API: NETCONF"
                    )
                    log.info(
                        "acl_check",
                        extra= {
                            "device_ip": device_ip,
                            "component": "acl_automation",
                            "event_type": "acl_validation",
                            "status": StepStatus.FAILED.value,
                            "acl_name": acl_name,
                            "rule_count": len(rules),
                            "rule_list": rules_summary,
                            "failures": failures,
                            "message": (
                                f"Extended ACL Validation Failed | Name: {acl_name} "
                                f"Rules: {len(rules)} | Failures: {failures} | "
                                f"API: NETCONF"
                            )
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="acl_automation",
                            event_type="acl_validation",
                            outcome=StepStatus.FAILED.value,
                            acl_name=acl_name,
                            rule_count=len(rules),
                            rule_summary=rules_summary,
                            timestamp=timestamp,
                            reason=(
                                f"Extended ACL Validation Failed | Name: {acl_name} "
                                f"Rules: {len(rules)} | Failures: {failures} | "
                                f"API: NETCONF"
                            )
                        )
                    )
    except Exception as e:
        results["status"] = OpStatus.ERROR.value
        results["error"] = str(e)
        log.exception(
            "acl_check",
            extra= {
                "device_ip": device_ip,
                "component": "acl_automation",
                "event_type": "acl_config",
                "status": StepStatus.ERROR.value,
                "acl_name": acl_name,
                "rule_count": len(rules),
                "rule_list": rules_summary,
                "error": str(e),
                "message": (
                    f"Try/Exception Error | Name: {acl_name} "
                    f"Rules: {len(rules)} | API: NETCONF"
                )
            }
        )
        results["events"].append(
            emit_event(
                device_ip=device_ip,
                component="acl_automation",
                event_type="acl_config",
                outcome=StepStatus.ERROR.value,
                acl_name=acl_name,
                rule_count=len(rules),
                rule_summary=rules_summary,
                timestamp=timestamp,
                reason=(
                    f"Try/Exception Error | Name: {acl_name} "
                    f"Rules: {len(rules)} | API: NETCONF"
                )
            )
        )
        return results
    results["summary"] = (
        results["summary_validation"]
        or results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="acl_automation",
            event_type="acl_overall",
            outcome=(
                "DRY_RUN" if DRY_RUN else "SUCCESS"
                if results["status"] == OpStatus.SUCCESS.value
                else "FAIL"
            ),
            acl_name=acl_name,
            rule_count=len(rules),
            rule_summary=rules_summary,
            timestamp=timestamp,
            reason=f"ACL Automation Complete"
        )
    )
    return results
def configure_acl_bindings(session, device_ip, acl_binding_data, log):
    interface = acl_binding_data.get("interface", "")
    acl_name = acl_binding_data.get("acl_name", "")
    direction = acl_binding_data.get("direction", "")

    results = {
        "device_ip": device_ip,
        "interface": interface,
        "acl_name": acl_name,
        "direction": direction,

        "configured": False,
        "validated": False,
        "status": OpStatus.PENDING.value,
        "component": "acl_binding_automation",

        "timestamp": timestamp,
        "summary": None,
        "summary_config": None,
        "summary_validation": None,
        "events": []
    }
    try:
        log.info(
            "acl_binding_check",
            extra={
                "device_ip": device_ip,
                "event_type": "acl_binding_config",
                "severity": "INFO",
                "component": "acl_binding_automation",
                "transport": "NETCONF",
                "message": f"Starting ACL Binding Configuration | Interface: {interface}"
                           f" | Name: {acl_name} | Direction: {direction}"
            }
        )
        if DRY_RUN:
            results["configured"] = False
            results["validated"] = False
            results["status"] = OpStatus.DRY_RUN.value
            results["summary_config"] = (
                               f"[DRY_RUN] Would Configure ACL Binding Configuration "
                               f"| Interface: {interface}"
                               f" | Name: {acl_name} | Direction: {direction}"
            )
            log.info(
                "acl_binding_check",
                extra={
                    "device_ip": device_ip,
                    "event_type": "acl_binding_config",
                    "status": StepStatus.DRY_RUN.value,
                    "severity": "INFO",
                    "component": "acl_binding_automation",
                    "transport": "NETCONF",
                    "message": f"[DRY_RUN] Would Configure ACL Binding Configuration "
                               f"| Interface: {interface}"
                               f" | Name: {acl_name} | Direction: {direction}"
                }
            )
            results["events"].append(
                emit_event(
                    device_ip=device_ip,
                    component="acl_binding_automation",
                    event_type="acl_binding_config",
                    outcome="DRY_RUN",
                    interface=interface,
                    acl_name=acl_name,
                    direction=direction,
                    transport="NETCONF",
                    timestamp=timestamp,
                    reason=(
                        f"[DRY_RUN] Would Configure ACL Binding Configuration "
                        f"| Interface: {interface}"
                        f" | Name: {acl_name} | Direction: {direction}"
                    )
                )
            )
        else:
            template = template_env.get_template("ACL_BINDING.j2")
            commands = template.render(
                interface=interface,
                acl_name=acl_name,
                direction=direction
            )

            configured, error = safe_netconf_edit(session, commands)

            results["configured"] = configured

            if not configured:
                results["status"] = OpStatus.CONFIG_FAILED.value
                results["error"] = error
                results["summary_config"] = (
                    f"ACL Binding Configuration Failed | Interface: {interface}"
                    f" | Name: {acl_name} | Direction: {direction}"
                )
                log.info(
                    "acl_binding_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "acl_binding_config",
                        "status": StepStatus.FAILED.value,
                        "severity": "CRITICAL",
                        "component": "acl_binding_automation",
                        "transport": "NETCONF",
                        "error": error,
                        "message": f"ACL Binding Configuration Failed "
                                   f"| Interface: {interface}"
                                   f" | Name: {acl_name} | Direction: {direction}"
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="acl_binding_automation",
                        event_type="acl_binding_config",
                        outcome="FAIL",
                        interface=interface,
                        acl_name=acl_name,
                        direction=direction,
                        transport="NETCONF",
                        timestamp=timestamp,
                        reason=(
                            f"ACL Binding Configuration Failed "
                            f"| Interface: {interface}"
                            f" | Name: {acl_name} | Direction: {direction}"
                        )
                    )
                )
            else:
                results["status"] = OpStatus.CONFIGURED.value
                results["summary_config"] = (
                    f"Successfully Configured ACL Binding Configuration "
                    f"| Interface: {interface}"
                    f" | Name: {acl_name} | Direction: {direction}"
                )
                log.info(
                    "acl_binding_check",
                    extra={
                        "device_ip": device_ip,
                        "event_type": "acl_binding_config",
                        "status": StepStatus.SUCCESS.value,
                        "severity": "INFO",
                        "component": "acl_binding_automation",
                        "transport": "NETCONF",
                        "message": (
                            f"Successfully Configured ACL Binding Configuration "
                            f"| Interface: {interface}"
                            f" | Name: {acl_name} | Direction: {direction}"
                        )
                    }
                )
                results["events"].append(
                    emit_event(
                        device_ip=device_ip,
                        component="acl_binding_automation",
                        event_type="acl_binding_config",
                        outcome="SUCCESS",
                        interface=interface,
                        acl_name=acl_name,
                        direction=direction,
                        transport="NETCONF",
                        timestamp=timestamp,
                        reason=(
                            f"Successfully Configured ACL Binding Configuration "
                            f"| Interface: {interface}"
                            f" | Name: {acl_name} | Direction: {direction}"
                        )
                    )
                )

                native = collect_netconf_state(session)
                actual_bindings = build_acl_bindings_state(native)

                binding_ok, failures = check_acl_binding(
                    acl_binding_data,
                    actual_bindings
                )

                results["validated"] = binding_ok

                if binding_ok:
                    results["status"] = OpStatus.SUCCESS.value
                    results["summary_validation"] = (
                        f"ACL Binding Validation Successful "
                        f"| Interface: {interface}"
                        f" | Name: {acl_name} | Direction: {direction}"
                    )

                    log.info(
                        "acl_binding_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "acl_binding_validation",
                            "status": StepStatus.SUCCESS.value,
                            "severity": "INFO",
                            "component": "acl_binding_automation",
                            "transport": "NETCONF",
                            "message": (
                                f"ACL Binding Validation Successful "
                                f"| Interface: {interface}"
                                f" | Name: {acl_name} | Direction: {direction}"
                            )
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="acl_binding_automation",
                            event_type="acl_binding_validation",
                            outcome="SUCCESS",
                            interface=interface,
                            acl_name=acl_name,
                            direction=direction,
                            transport="NETCONF",
                            timestamp=timestamp,
                            reason=(
                                    f"ACL Binding Validation Successful "
                                    f"| Interface: {interface}"
                                    f" | Name: {acl_name} | Direction: {direction}"
                            )
                        )
                    )
                else:
                    results["status"] = OpStatus.VALIDATION_FAILED.value
                    results["drift"] = failures
                    results["summary_validation"] = (
                        f"ACL Binding Validation Failed "
                        f"| Interface: {interface}"
                        f" | Name: {acl_name} | Direction: {direction}"
                    )
                    log.info(
                        "acl_binding_check",
                        extra={
                            "device_ip": device_ip,
                            "event_type": "acl_binding_validation",
                            "status": StepStatus.FAILED.value,
                            "severity": "CRITICAL",
                            "component": "acl_binding_automation",
                            "transport": "NETCONF",
                            "results": failures,
                            "message": (
                                    f"ACL Binding Validation Failed "
                                    f"| Interface: {interface}"
                                    f" | Name: {acl_name} | Direction: {direction}"
                            )
                        }
                    )
                    results["events"].append(
                        emit_event(
                            device_ip=device_ip,
                            component="acl_binding_automation",
                            event_type="acl_binding_validation",
                            outcome="FAIL",
                            interface=interface,
                            acl_name=acl_name,
                            direction=direction,
                            transport="NETCONF",
                            failures="failures",
                            timestamp=timestamp,
                            reason=(
                                f"ACL Binding Validation Failed "
                                f"| Interface: {interface}"
                                f" | Name: {acl_name} | Direction: {direction}"
                        )
                            )
                    )

    except Exception as e:
        results["status"] = OpStatus.ERROR.value
        results["error"] = str(e)
        log.info(
            "acl_binding_check",
            extra={
                "device_ip": device_ip,
                "event_type": "acl_binding_config",
                "status": StepStatus.ERROR.value,
                "severity": "CRITICAL",
                "component": "acl_binding_automation",
                "transport": "NETCONF",
                "message": (
                    f"Try/Exception Error | ACL Binding "
                    f"| Interface: {interface}"
                    f" | Name: {acl_name} | Direction: {direction}"
                )
            }
        )
        results["events"].append(
            emit_event(
                device_ip=device_ip,
                component="acl_binding_automation",
                event_type="acl_binding_config",
                outcome="FAIL",
                interface=interface,
                acl_name=acl_name,
                direction=direction,
                transport="NETCONF",
                timestamp=timestamp,
                reason=(
                    f"Try/Exception Error | ACL Binding "
                    f"| Interface: {interface}"
                    f" | Name: {acl_name} | Direction: {direction}"
                )
            )
        )
        return results
    results["summary"] = (
        results["summary_validation"]
        or results["summary_config"]
    )
    results["events"].append(
        emit_event(
            device_ip=device_ip,
            component="acl_binding_automation",
            event_type="acl_binding_overall",
            outcome=(
                "DRY_RUN" if DRY_RUN else "SUCCESS"
                if results["status"] == OpStatus.SUCCESS.value
                else "FAIL"
            ),
            interface=interface,
            acl_name=acl_name,
            direction=direction,
            transport="NETCONF",
            timestamp=timestamp,
            reason=(
                f"Try/Exception Error | ACL Binding "
                f"| Interface: {interface}"
                f" | Name: {acl_name} | Direction: {direction}"
            )
        )

    )
    return results








def main_process(task):
    device = task["device"]
    context = task["context"]
    host_ip = device["device"]

    adapter = logging.LoggerAdapter(logger, {"dev": device["name"]})

    device_result = {
        "device_name": device["name"],
        "device_ip": host_ip,
        "status": "COMPLIANT",

        "actions_taken": [],
        "events": [],
        "checks_passed": 0,
        "checks_failed": 0,
        "critical_issues": [],
        "warnings": [],

        "start_time": datetime.utcnow().isoformat(),
        "end_time": None,
        "duration_seconds": None,

        "ospf_report": {},
        "errors": []

    }

    try:
        if device["device_type"] in ["cisco_ios_xe"]:
            auth = (device["username"], device["password"])

            with create_restconf_session(auth) as session:
                state = restconf_state(host_ip, session, adapter)

                updated = False

                for roas_data in context.get("roass", []):
                    config_roas = configure_roas(host_ip, roas_data, session, adapter)
                    if config_roas.get("status") == "SUCCESS":
                        updated = True
                        device_result["actions_taken"].append(config_roas["summary"])
                        device_result.append(
                            config_roas["event"]
                        )
                for ospf_data in context.get("ospf", []):
                    config_ospf = configure_ospf(host_ip, ospf_data, session, adapter)
                    if config_ospf.get("status") == "CONFIGURED":
                        updated = True
                        device_result["actions_taken"].append(config_ospf["summary"])
                        device_result.append(
                            config_ospf["event"]
                        )
                if updated and not DRY_RUN:
                    adapter.info("⏳ Changes detected. Waiting 30s for network convergence...")
                    time.sleep(30)

                checker = OSPF_Checker()
                for ospf_data in context("ospf", []):
                    report = checker.validate_device_ospf(host_ip, state , ospf_data)

                    device_result["ospf_report"].append(report)
                    if report["status"] != "HEALTHY":
                        device_result["status"] = "NON-COMPLIANT"
                        device_result["critical_issues"].append(
                            {
                                "process_id": ospf_data["process_id"],
                                "issues": report.get("critical_issues", [])
                            })
                    if report["warnings"]:
                        device_result["warnings"].append(
                            {
                                "process_id": ospf_data["process_id"],
                                "issues": report["warnings"]
                            }
                        )
        else:
            with ConnectHandler(**device) as conn:
                conn.enable()

                state = collect_device_state(conn)
                changed = False

                for vlan_data in context.get("vlan", []):
                    vlan_id = vlan_data.get("vlan_id")
                    name = vlan_data.get("name")
                    exists = check_vlan(state, vlan_id, name)
                    if exists:
                        log.info(
                            "vlan_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process"
                                "event_type": "vlan_precheck",
                                "status": StepStatus.SKIPPED.value,
                                "message": f"VLAN already exists | VLAN: {vlan_id} | "
                                           f"Name: {name}"
                            }
                        )
                        device_result["actions_taken"].append(
                            f"VLAN already exists | VLAN: {vlan_id} | "
                            f"Name: {name}"
                        )
                        continue
                    config_vlan = configure_vlan(conn, host_ip, vlan_data, log)
                    if config_vlan.get("status") == OpStatus.SUCCESS.value:
                        changed = True
                        device_result["actions_taken"].append(config_vlan["summary"])

                for access_data in context.get("access_ports", []):
                    access_interface = access_data.get("access_interface", "")
                    access_vlan = access_data.get("access_vlan", "")
                    exists = check_switch_mode(state, access_interface, "access", access_vlan)
                    if exists:
                        log.info(
                            "access_port_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "access_port_precheck",
                                "status": StepStatus.SKIPPED.value,
                                "message": f"Access Port Already Exists | Interface: "
                                           f"{access_interface} | VLAN: {access_vlan}"
                            }
                        )
                        device_result["actions_taken"].append(
                            f"Access Port Already Exists | Interface: "
                            f"{access_interface} | VLAN: {access_vlan}"
                        )
                        continue
                        config_access = configure_access_ports(conn, host_ip, access_data, log)
                        if config_access:
                            changed = True
                            device_result["actions_taken"].append(
                                config_access["summary"]
                            )
                
