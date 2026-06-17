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
def listify(data):
    if not data: return []
    return data if isinstance(data, list) else [data] 
def safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
def normalize_val(val):
    """Converts various 'any' formats and casing into a standard string."""
    if val is None:
        return "any"
    
    # Convert to string and lowercase
    v = str(val).strip().lower()
    
    # List of values that all mean "any" in Cisco-land
    any_equivalents = [
        "any", 
        "0.0.0.0 255.255.255.255", 
        "0.0.0.0/0", 
        "0.0.0.0 0.0.0.0", # Sometimes seen in wildcard masks
        "::/0"             # IPv6 any
    ]
    
    if v in any_equivalents:
        return "any"
    
    return v
def normalize_vlans(vlan_str):
    if vlan_str is None:
        return ""

    return " ".join(
        sorted(
            str(v).strip()
            for v in str(vlan_str).replace(",", " ").split()
            if v.strip()
        )
    )
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
        "interfaces":[],
        "roass":[],
        "ospf":[],
        "ACL": [],
        "acl_bindings": [],
        "ntp": {
            "keys": [],
            "servers": [],
            "trusted": []
        },
        "qos": []
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
        qos_context = context.get("qos", {})
        for device_interface in interface_on_device.get(device_name.id, []):
            tags = [t.slug for t in device_interface.tags]

            config_data["interfaces"].append({
            "device": host_ip,
            "interface": intf_name.lower(),
            "should_be_up": device_interface.custom_fields.get("should_be_up", True) if hasattr(device_interface, "custom_fields") else True
                })

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
                router_ips = ip_on_interface.get(device_interface.id, [])
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

        if qos_context:
            config_data["qos"].append({
                "device": host_ip,
                "policy_name": qos_context.get("policy_name", ""),
                "class_maps": qos_context.get("class_mapss", []),
                "direction": qos_context.get("direction", ""),
                "interface": qos_context.get("interface", "")
            })

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
def build_vlan_state(device_state)

    vlan_table = device_state.get("vlans", {})

    vlan_list = vlan_table.get("vlans", {})

    actual_inventory = {}

    for vlan_id, vlan_info in vlan_list.items():
        actual_inventory[str(vlan_id)] = {
            "name": vlan_info.get("name"),
            "status": vlan_info.get("status")
        }

    return actual_inventory
def build_interface_state(device_state):
 
    actual = {}

    interfaces = device_state.get("interfaces", {})

    if not isinstance(interfaces, dict):
        return {}

    # Genie output is usually keyed by interface name
    for intf_name, data in interfaces.items():

        if not isinstance(data, dict):
            continue

        name = intf_name.lower().strip()

        status = str(data.get("status", "")).lower().strip()
        protocol = str(data.get("protocol", "")).lower().strip()

        actual[name] = {
            "interface": name,
            "status": status,        
            "protocol": protocol,   
            "is_up": status == "up" and protocol == "up"
        }

    return actual
def build_access_state(device_state):
  
    sw_data = device_state.get("switchports", {})
    if not isinstance(sw_data, dict):
        return {}

    actual_access = {}

    for intf, data in sw_data.items():

        if not isinstance(data, dict):
            continue

        op_mode = str(data.get("operational_mode", "")).lower()


        if "access" not in op_mode or "trunk" in op_mode:
            continue

        interface = intf.lower().strip()
        access_vlan = str(data.get("access_vlan", "") or "").strip()
        access_vlan = access_vlan.split("(")[0].strip()

        actual_access[interface] = {
            "interface": interface,
            "mode": "access",
            "access_vlan": access_vlan
        }

    return actual_access
def build_trunk_state(device_state):
    
    sw_data = device_state.get("switchports", {})
    if not isinstance(sw_data, dict):
        return {}

    actual_trunks = {}

    for intf, data in sw_data.items():

        if not isinstance(data, dict):
            continue

        op_mode = str(data.get("operational_mode", "")).lower()

        if "trunk" not in op_mode:
            continue

        interface = intf.lower()

        allowed_vlans = str(data.get("trunk_vlans", ""))

        actual_trunks[interface] = {
            "interface": interface,
            "mode": "trunk",
            "allowed_vlans": allowed_vlans
        }

    return actual_trunks
def build_roas_state(restconf_data):

    actual_roas = {}

    iface_root = restconf_data.get("interface_restconf", {})

    interfaces = iface_root.get(
        "Cisco-IOS-XE-native:interface", {}
    )

    for intf_type, intf_list in interfaces.items():

        if not isinstance(intf_list, list):
            intf_list = [intf_list]

        for intf in intf_list:

            base_name = str(intf.get("name", "")).lower()

            subifs = intf.get("GigabitEthernet-subinterface", [])
            if not isinstance(subifs, list):
                subifs = [subifs]

            for sub in subifs:

                sub_name = sub.get("name")
                if not sub_name:
                    continue

                full_intf = f"{base_name}.{sub_name}".lower()

                ipv4 = sub.get("ip", {}).get("address", {})

                primary = ipv4.get("primary", {})

                ip_addr = primary.get("address")
                mask = primary.get("mask")

                vlan_id = sub.get("encapsulation", {}).get("dot1Q", {}).get("vlan-id")

                actual_roas[full_intf] = {
                    "interface": full_intf,
                    "vlan": vlan_id,
                    "ip": ip_addr,
                    "mask": mask
                }

    return actual_roas
def build_ospf_state(restconf_state):

    actual = {
        "processes": {}
    }

    ospf_data = restconf_state.get("ospf_restconf", {})

    router = ospf_data.get(
        "Cisco-IOS-XE-native:router", {}
    )

    ospf = router.get("ospf", {})

    processes = ospf.get("process-id", [])

    if not isinstance(processes, list):
        processes = [processes]

    for proc in processes:

        pid = str(proc.get("id"))

        router_id = proc.get("router-id", "")

        networks = []

        for net in proc.get("network", []):

            if not isinstance(net, dict):
                continue

            networks.append({
                "ip": net.get("ip"),
                "wildcard": net.get("wildcard"),
                "area": str(net.get("area"))
            })

        actual["processes"][pid] = {
            "process_id": pid,
            "router_id": router_id,
            "network_list": networks
        }

    return actual
def build_acl_state(native):

    actual_acls = {}

    extended = listify(
        native.get("ip", {})
              .get("access-list", {})
              .get("extended", [])
    )

    for acl_obj in extended:

        name = acl_obj.get("name")

        if not name:
            continue

        rules = []

        seq_rules = listify(
            acl_obj.get("access-list-seq-rule", [])
        )

        for r in seq_rules:

            ace = r.get("ace-rule", {})

            rules.append({
                "seq": int(r.get("sequence", 0)),
                "action": ace.get("action"),
                "protocol": ace.get("protocol"),

                "source_ip": ace.get("ipv4-address", "any"),
                "source_mask": ace.get("mask"),

                "dest_ip": ace.get("dest-ipv4-address", "any"),
                "dest_mask": ace.get("dest-mask"),

                "port": ace.get("dst-eq")
            })

        actual_acls[name] = sorted(rules, key=lambda x: x["seq"])
    return actual_acls
def build_acl_bindings_state(native):
    actual_bindings = {}

    intf_types = ["GigabitEthernet", "TenGigabitEthernet", "Vlan", "Loopback", "Port-channel"]
    interfaces_root = native.get("interface", {})

    for i_type in intf_types:
        intf_list = listify(interfaces_root.get(i_type, []))

        for intf in intf_list:
            name_val = intf.get("name")
            if not name_val:
                continue

            name = str(name_val).lower()

            ip_data = intf.get("ip", {})
            access_groups = listify(ip_data.get("access-group", []))

            for ag in access_groups:
                direction = ag.get("direction")
                acl_name = ag.get("acl-name")

                if not direction or not acl_name:
                    continue

                key = f"{name}|{direction.lower()}"

                actual_bindings[key] = {
                    "interface": name,
                    "acl_name": acl_name.lower(),
                    "direction": direction.lower()
                }

    return actual_bindings
def build_ntp_state(native):
    ntp = native.get("ntp", {}) or {}

    trusted = listify(ntp.get("trusted-key", []))

    trusted_ids = set()
    for t in trusted:
        try:
            trusted_ids.add(int(t.get("number", 0)))
        except (TypeError, ValueError):
            continue

    keys_raw = listify(ntp.get("authentication-key", []))

    actual_keys = []
    for k in keys_raw:
        try:
            key_id = int(k.get("number", 0))
        except (TypeError, ValueError):
            continue

        actual_keys.append({
            "id": key_id,
            "trusted": key_id in trusted_ids
        })

    servers_root = ntp.get("server", {}) or {}
    servers_raw = listify(servers_root.get("server-list", []))

    actual_servers = []
    
    for s in servers_raw:
        try:
            ip = s.get("ip-address")
            key = int(s.get("key", 0))
        except (TypeError, ValueError):
            continue

        if not ip:
            continue

        actual_servers.append({
            "ip": ip,
            "key": key
        })

    return {
        "keys": sorted(actual_keys, key=lambda x: x["id"]),
        "servers": sorted(actual_servers, key=lambda x: x["ip"])
    }
def build_qos_state(native):
    policy = native.get("policy", {})

    cm_raw = listify(policy.get("class-map", []))
    class_inventory = {}

    for cm in cm_raw:
        name = cm.get("name")
        if not name:
            continue

        match_data = cm.get("match", {}) or {}
        protocol = (
            match_data.get("protocol", {})
            .get("protocols-list", {})
            .get("protocols")
        )

        class_inventory[name] = {
            "name": name,
            "match_type": cm.get("prematch"),
            "protocol": protocol,
            "action_type": None,
            "bandwidth": None
        }

    pm_raw = listify(policy.get("policy-map", []))
    actual_policy_name = None

    for pm in pm_raw:
        actual_policy_name = pm.get("name")

        pm_classes = listify(pm.get("class", []))

        for cls in pm_classes:
            c_name = cls.get("name")

            if not c_name or c_name == "class-default":
                continue

            if c_name not in class_inventory:
                continue

            action = cls.get("action-list", {}) or {}
            a_type = action.get("action-type")

            bw_val = None
            if a_type == "priority":
                bw_val = action.get("priority", {}).get("kilo-bits")
            elif a_type == "bandwidth":
                bw_val = action.get("bandwidth", {}).get("kilo-bits")

            class_inventory[c_name]["action_type"] = a_type
            class_inventory[c_name]["bandwidth"] = int(bw_val) if bw_val else None

    return {
        "policy_name": actual_policy_name,
        "classes": class_inventory
    }
def check_qos(expected_qos, actual_qos):
    failures = []

    exp_policy = expected_qos.get("policy_name")
    act_policy = actual_qos.get("policy_name")

    if exp_policy != act_policy:
        failures.append(
            f"Policy name mismatch: expected={exp_policy}, actual={act_policy}"
        )

    exp_classes = expected_qos.get("class_map", {})
    act_classes = actual_qos.get("classes", {})

    exp_keys = set(exp_classes.keys())
    act_keys = set(act_classes.keys())

    for name in (exp_keys - act_keys):
        failures.append(f"Missing QoS class: {name}")

 
    for name in (act_keys - exp_keys):
        failures.append(f"Unexpected QoS class on device: {name}")


    for name in (exp_keys & act_keys):
        exp = exp_classes[name]
        act = act_classes[name]

        if str(exp.get("protocol")).lower() != str(act.get("protocol")).lower():
            failures.append(
                f"{name} protocol mismatch: expected={exp.get('protocol')} actual={act.get('protocol')}"
            )

        if exp.get("action_type") != act.get("action_type"):
            failures.append(
                f"{name} action mismatch: expected={exp.get('action_type')} actual={act.get('action_type')}"
            )

        if str(exp.get("bandwidth")) != str(act.get("bandwidth")):
            failures.append(
                f"{name} bandwidth mismatch: expected={exp.get('bandwidth')} actual={act.get('bandwidth')}"
            )

    return len(failures) == 0, failures
def check_ntp(expected_ntp, actual_ntp):
    failures = []

    expected_ntp = expected_ntp or {}
    actual_ntp = actual_ntp or {}


    exp_keys = {
        k.get("id"): bool(k.get("trusted", False))
        for k in expected_ntp.get("keys", [])
        if k.get("id") is not None
    }

    act_keys = {
        k.get("id"): bool(k.get("trusted", False))
        for k in actual_ntp.get("keys", [])
        if k.get("id") is not None
    }

    # Missing / mismatch keys
    for kid, exp_trusted in exp_keys.items():

        if kid not in act_keys:
            failures.append(f"Missing NTP Key: {kid}")
            continue

        if exp_trusted != act_keys[kid]:
            failures.append(
                f"NTP Key {kid} trust mismatch "
                f"(expected={exp_trusted}, actual={act_keys[kid]})"
            )

    exp_servers = {
        s.get("ip"): s.get("key", 0)
        for s in expected_ntp.get("servers", [])
        if s.get("ip")
    }

    act_servers = {
        s.get("ip"): s.get("key", 0)
        for s in actual_ntp.get("servers", [])
        if s.get("ip")
    }

    for ip, exp_key in exp_servers.items():

        if ip not in act_servers:
            failures.append(f"Missing NTP Server: {ip}")
            continue

        if int(exp_key) != int(act_servers[ip]):
            failures.append(
                f"NTP Server {ip} key mismatch "
                f"(expected={exp_key}, actual={act_servers[ip]})"
            )

    for ip in (act_servers.keys() - exp_servers.keys()):
        failures.append(f"Unexpected NTP Server (manual config): {ip}")

    return len(failures) == 0, failures
def check_acl(expected_rules, actual_rules):

    failures = []

    expected = {
        r.get("seq"): r
        for r in expected_rules
        if r.get("seq") is not None
    }

    actual = {
        r.get("seq"): r
        for r in actual_rules
        if r.get("seq") is not None
    }

    exp_seqs = set(expected.keys())
    act_seqs = set(actual.keys())

    for seq in (exp_seqs - act_seqs):
        failures.append(
            f"Missing rule {seq}"
        )

    for seq in (act_seqs - exp_seqs):
        failures.append(
            f"Unexpected rule {seq}"
        )

    for seq in (exp_seqs & act_seqs):

        for key, expected_value in expected[seq].items():

            actual_value = actual[seq].get(key)

            if normalize_val(expected_value) != normalize_val(actual_value):

                failures.append(
                    f"Rule {seq} mismatch on '{key}' "
                    f"(expected={expected_value}, actual={actual_value})"
                )

    return len(failures) == 0, failures
def normalize(v):
    if v is None:
        return ""
    return str(v).strip().lower()
def check_acl_bindings(expected_bindings, actual_bindings):
    failures = []

    expected = {}

    for b in expected_bindings:
        interface = normalize(b.get("interface"))
        direction = normalize(b.get("direction"))
        acl_name = normalize(b.get("acl_name"))

        if not interface or not direction:
            failures.append(f"Malformed expected binding: {b}")
            continue

        key = f"{interface}|{direction}"
        expected[key] = {
            "acl_name": acl_name,
            "raw": b
        }

    exp_keys = set(expected.keys())
    act_keys = set(actual_bindings.keys())

    for key in (exp_keys - act_keys):
        failures.append(f"Missing ACL Binding: {key.replace('|', ' ')}")

    for key in (act_keys - exp_keys):
        act = actual_bindings[key]
        failures.append(
            f"Unexpected ACL Binding: {key.replace('|', ' ')} "
            f"(ACL: {act.get('acl_name')})"
        )
    for key in (exp_keys & act_keys):
        exp = expected[key]["acl_name"]
        act = normalize(actual_bindings[key].get("acl_name"))

        if exp != act:
            failures.append(
                f"ACL mismatch on {key.replace('|', ' ')}: "
                f"expected={exp}, actual={act}"
            )

    return len(failures) == 0, failures
def check_vlan(expected_vlan, actual_inventory):
  
    failures = []

    vid = str(expected_vlan.get("vlan_id", "")).strip()
    exp_name = (expected_vlan.get("name") or "").strip()

    actual = actual_inventory.get(vid)

    if not actual:
        failures.append(f"VLAN {vid} is missing from device")
        return False, failures

    act_name = (actual.get("name") or "").strip()


    if exp_name.lower() != act_name.lower():
        failures.append(
            f"VLAN {vid} name mismatch: expected={exp_name}, actual={act_name}"
        )

    return len(failures) == 0, failures
def check_interface(expected_interface, actual_inventory):
    failures = []


    intf = str(expected_interface.get("interface", "")).lower().strip()

    should_be_up = expected_interface.get("should_be_up", True)

    actual = actual_inventory.get(intf)

    if not actual:
        failures.append(f"Interface {intf} not found on device")
        return False, failures


    is_up = actual.get("is_up", False)


    if should_be_up and not is_up:
        failures.append(
            f"{intf} should be UP but is DOWN "
            f"(status={actual.get('status')}, protocol={actual.get('protocol')})"
        )

    # Case 2: SHOULD BE DOWN but is UP (drift detection)
    if not should_be_up and is_up:
        failures.append(
            f"{intf} should be DOWN but is UP (unexpected active interface)"
        )

    return len(failures) == 0, failures
def check_access_port(expected_port, actual_inventory):
    failures = []

    intf = str(expected_port.get("access_interface", "")).lower().strip()


    exp_vlan = str(expected_port.get("access_vlan", "") or "").strip()


    actual = actual_inventory.get(intf)

    if not actual:
        failures.append(
            f"Interface {intf} missing or not configured as access port"
        )
        return False, failures

    act_vlan = str(actual.get("access_vlan", "") or "").strip()

    # Handle Cisco formatting like "10 (VLAN0010)"
    act_vlan = act_vlan.split("(")[0].strip()

    if exp_vlan != act_vlan:
        failures.append(
            f"Access VLAN mismatch on {intf}: "
            f"expected={exp_vlan}, actual={act_vlan}"
        )

    if actual.get("mode") != "access":
        failures.append(
            f"{intf} is not in access mode"
        )

    return len(failures) == 0, failures
def check_trunk(expected_trunk, actual_inventory):
    failures = []

    if not isinstance(expected_trunk, dict):
        return False, ["Expected trunk data is not a valid dictionary"]

    raw_intf = expected_trunk.get("trunk_interface")
    if not raw_intf:
        return False, ["Missing trunk_interface in expected config"]

    intf = str(raw_intf).lower().strip()

    # VLAN validation early (prevents silent bad comparisons)
    raw_vlans = expected_trunk.get("allowed_vlans", "")
    if raw_vlans is None:
        return False, [f"Trunk {intf}: allowed_vlans is None"]

    exp_vlans = normalize_vlans(raw_vlans)

    if exp_vlans is None:
        return False, [f"Trunk {intf}: VLAN normalization failed (invalid input: {raw_vlans})"]

    actual = actual_inventory.get(intf)

    if not actual:
        failures.append(
            f"Interface {intf} missing or not configured as trunk"
        )
        return False, failures

    if not isinstance(actual, dict):
        return False, [f"Invalid actual trunk structure for {intf}"]


    act_raw_vlans = actual.get("allowed_vlans", "")

    if act_raw_vlans is None:
        act_raw_vlans = ""

    act_vlans = normalize_vlans(act_raw_vlans)

    if act_vlans is None:
        return False, [f"Trunk {intf}: device returned invalid VLAN format"]

    if exp_vlans != act_vlans:
        failures.append(
            f"Trunk {intf} VLAN mismatch: expected={exp_vlans}, actual={act_vlans}"
        )


    if actual.get("mode") and actual.get("mode") != "trunk":
        failures.append(
            f"Trunk {intf} mode mismatch: expected=trunk, actual={actual.get('mode')}"
        )

    return len(failures) == 0, failures
def check_interface(device_state, r_interface):
    interfaces = device_state.get("interfaces", {})
    interface = interfaces.get(r_interface)
    if not interface:
        return False

    status = interface.get("status", "")
    protocol = interface.get("protocol", "")
    return status == "up" and protocol == "up"
def check_roas(expected_roas, actual_roas):

    failures = []

   
    base_intf = str(expected_roas.get("router_interface", "")).lower().strip()
    vlan = str(expected_roas.get("router_vlan", "")).strip()
    ip = expected_roas.get("ip")

    # Build expected subinterface key
    expected_key = f"{base_intf}.{vlan}"

    actual = actual_roas.get(expected_key)


    if not actual:
        failures.append(
            f"ROAS missing: {expected_key} (VLAN {vlan} on {base_intf})"
        )
        return False, failures


    actual_vlan = str(actual.get("vlan", "")).strip()

    if vlan != actual_vlan:
        failures.append(
            f"ROAS VLAN mismatch on {expected_key}: "
            f"expected={vlan}, actual={actual_vlan}"
        )

  
    actual_ip = actual.get("ip")

    if ip and actual_ip and ip != actual_ip:
        failures.append(
            f"ROAS IP mismatch on {expected_key}: "
            f"expected={ip}, actual={actual_ip}"
        )

    return len(failures) == 0, failures
def check_ospf(expected, actual_state):

    failures = []


    pid = str(expected.get("process_id"))

    actual_proc = actual_state.get("processes", {}).get(pid)

    if not actual_proc:
        failures.append(f"Missing OSPF process {pid}")
        return False, failures

    exp_router_id = str(expected.get("router_id", "")).strip()
    act_router_id = str(actual_proc.get("router_id", "")).strip()

    if exp_router_id and act_router_id and exp_router_id != act_router_id:
        failures.append(
            f"Router-ID mismatch: expected={exp_router_id}, actual={act_router_id}"
        )

    exp_networks = expected.get("network_list", [])
    act_networks = actual_proc.get("network_list", [])

    exp_set = {
        (
            str(n.get("ip", "")).strip(),
            str(n.get("wildcard", "")).strip(),
            str(n.get("area", "")).strip()
        )
        for n in exp_networks
    }

    # Normalize actual
    act_set = {
        (
            str(n.get("ip", "")).strip(),
            str(n.get("wildcard", "")).strip(),
            str(n.get("area", "")).strip()
        )
        for n in act_networks
    }

    for net in (exp_set - act_set):
        failures.append(
            f"Missing OSPF network: ip={net[0]} wildcard={net[1]} area={net[2]}"
        )


    for net in (act_set - exp_set):
        failures.append(
            f"Unexpected OSPF network on device: ip={net[0]} wildcard={net[1]} area={net[2]}"
        )

    return len(failures) == 0, failures
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
  

    vlan_id = vlan_data.get("vlan_id")
    name = vlan_data.get("name")

    try:

        template = template_env.get_template("vlan.j2")

        config_commands = template.render(
            vlan_id=vlan_id,
            name=name
        ).splitlines()


        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY_RUN] Would configure VLAN {vlan_id} ({name})"
            }


        output = conn.send_config_set(config_commands)

        log.info(
            "vlan_config_success",
            extra={
                "device_ip": device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "status": StepStatus.SUCCESS.value,
                "vlan_id": vlan_id,
                "name": name,
                "message": f"VLAN configured successfully | {vlan_id} {name}"
            }
        )

        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"Successfully configured VLAN {vlan_id} ({name})",
            "output": output
        }

    except Exception as e:
        log.exception(
            "vlan_config_exception",
            extra={
                "device_ip": device_ip,
                "component": "vlan_automation",
                "event_type": "vlan_config",
                "vlan_id": vlan_id,
                "name": name
            }
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": f"VLAN config failed: {str(e)}",
            "error": str(e)
        }
def configure_access_ports(conn, device_ip, access_data, log):
  
    intf = access_data.get("access_interface")
    vlan = access_data.get("access_vlan")

    try:
   
        template = template_env.get_template("access_port.j2")

        commands = template.render(
            interface=intf,
            vlan=vlan
        ).splitlines()

    
        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY_RUN] Would configure access port {intf} VLAN {vlan}"
            }


        output = conn.send_config_set(commands)


        if "%" in output or "Error" in output or "Invalid" in output:
            return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": f"CLI rejected access config on {intf}",
                "error": output
            }

 
        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"Access port configured: {intf} VLAN {vlan}"
        }

    except Exception as e:
        log.exception(
            "access_config_exception",
            extra={"device_ip": device_ip}
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": str(e)
        }
def configure_trunk_ports(conn, device_ip, trunk_data, log):

    intf = trunk_data.get("trunk_interface", "")
    vlans = trunk_data.get("allowed_vlans", "")

    try:
   
        template = template_env.get_template("trunk.j2")

        commands = template.render(
            trunk_interface=intf,
            allowed_vlans=vlans
        ).splitlines()

  
        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY_RUN] Would configure trunk {intf} (VLANs: {vlans})"
            }


        conn.send_config_set(commands)

        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"Trunk configured successfully on {intf} (Allowed VLANs: {vlans})"
        }

    except Exception as e:
        log.exception(
            "trunk_config_exception",
            extra={
                "device_ip": device_ip,
                "interface": intf,
                "vlans": vlans,
                "component": "trunk_config"
            }
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": f"Trunk configuration failed on {intf}: {str(e)}"
        }
def configure_interface(conn, device_ip, interface_data, log):

    try:
        intf = interface_data.get("interface")
        should_be_up = interface_data.get("should_be_up", True)


        state = "no shutdown" if should_be_up else "shutdown"


        template = template_env.get_template("interface.j2")

        commands = template.render(
            interface=intf,
            state=state
        ).splitlines()

        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY] Would set {intf} -> {state}"
            }

        output = conn.send_config_set(commands)

        if "%" in output or "Error" in output or "Invalid" in output:
            return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": f"CLI rejected interface config on {intf}",
                "error": output
            }

        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"Interface {intf} configured to {state}"
        }

    except Exception as e:
        log.exception(
            "interface_config_exception",
            extra={"device_ip": device_ip, "interface": interface_data.get("interface")}
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": str(e)
        }
def configure_roas(device_ip, roas_data, session, log):

    try:
        payload = build_roas_payload(roas_data)  

        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY] Would configure ROAS on {device_ip}"
            }

        response = session.patch(
            url=f"https://{device_ip}/restconf/.../roas",
            json=payload
        )

        if response.status_code not in [200, 201, 204]:
            return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": f"ROAS config failed {response.text}",
                "error": response.text
            }

        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"ROAS configured successfully on {device_ip}"
        }

    except Exception as e:
        log.exception("roas_exception", extra={"device_ip": device_ip})

        return {
            "status": OpStatus.ERROR.value,
            "summary": str(e)
        }
def configure_ospf(device_ip, ospf_data, session, log):

    try:
        template = template_env.get_template("ospf.j2")

        xml_payload = template.render(
            process_id=ospf_data.get("process_id"),
            router_id=ospf_data.get("router_id"),
            network_list=ospf_data.get("network_list", [])
        )

        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY] Would configure OSPF process {ospf_data.get('process_id')}"
            }

        success, error = safe_netconf_edit(session, xml_payload)

        if not success:
            return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": f"OSPF config failed for process {ospf_data.get('process_id')}",
                "error": error
            }

        return {
            "status": OpStatus.CONFIGURED.value,
            "summary": f"OSPF configured successfully | process {ospf_data.get('process_id')}",
            "event": "ospf_config_applied"
        }

    except Exception as e:
        log.exception(
            "ospf_config_exception",
            extra={"device_ip": device_ip}
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": f"OSPF exception: {str(e)}"
        }
def configure_acl(session, device_ip, acl_data, log):

    acl_name = acl_data.get("acl_name", "")
    rules = acl_data.get("rules", [])

    try:
        # Render NETCONF payload
        template = template_env.get_template("ACL.j2")

        xml_payload = template.render(
            acl_name=acl_name,
            rules=rules
        )

        # DRY RUN support
        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY_RUN] ACL would be configured | {acl_name}",
                "error": None
            }

        # Push to device (NETCONF)
        success, error = safe_netconf_edit(session, xml_payload)

        if not success:
            log.error(
                "acl_config_failed",
                extra={
                    "device_ip": device_ip,
                    "component": "acl_automation",
                    "acl_name": acl_name,
                    "error": error
                }
            )

            return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": f"ACL configuration failed | {acl_name}",
                "error": error
            }

        # Success
        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"ACL configured successfully | {acl_name}",
            "error": None
        }

    except Exception as e:
        log.exception(
            "acl_config_exception",
            extra={
                "device_ip": device_ip,
                "component": "acl_automation",
                "acl_name": acl_name,
                "error": str(e)
            }
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": f"ACL exception occurred | {acl_name}",
            "error": str(e)
        }
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
def configure_ntp(session, device_ip, ntp_data, log):
  
    try:
        ntp_data = ntp_data or {}

        keys = ntp_data.get("keys", [])
        servers = ntp_data.get("servers", [])

        template = template_env.get_template("NTP.j2")

        xml_payload = template.render(
            keys=keys,
            servers=servers
        )

        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": f"[DRY_RUN] Would configure NTP on {device_ip}",
                "error": None
            }

        success, error = safe_netconf_edit(session, xml_payload)

        if not success:
            log.error(
                "ntp_config_failed",
                extra={
                    "device_ip": device_ip,
                    "error": error,
                    "component": "ntp"
                }
            )

            return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": f"NTP Config Failed: {error}",
                "error": error
            }

        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"NTP configuration applied successfully on {device_ip}",
            "error": None
        }

    except Exception as e:
        log.exception(
            "ntp_config_exception",
            extra={
                "device_ip": device_ip,
                "component": "ntp"
            }
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": f"NTP Exception: {str(e)}",
            "error": str(e)
        }
def configure_qos(session, device_ip, qos_data, log):
 

    policy_name = qos_data.get("policy_name", "")
    class_map = qos_data.get("class_map", [])

    try:
       
        template = template_env.get_template("QOS.j2")

        xml_payload = template.render(
            policy_name=policy_name,
            class_map=class_map
        )


        if DRY_RUN:
            return {
                "status": OpStatus.DRY_RUN.value,
                "summary": (
                    f"[DRY_RUN] Would configure QoS policy: {policy_name}"
                )
            }


        success, error = safe_netconf_edit(session, xml_payload)

        if not success:
            log.error(
                "qos_config_failed",
                extra={
                    "device_ip": device_ip,
                    "component": "qos_automation",
                    "event_type": "qos_config",
                    "status": StepStatus.FAILED.value,
                    "policy_name": policy_name,
                    "error": error,
                    "message": f"QoS configuration failed: {error}"
                }
            )

            return {
                "status": OpStatus.CONFIG_FAILED.value,
                "summary": f"QoS Config Failed: {error}",
                "error": error
            }

        log.info(
            "qos_config_success",
            extra={
                "device_ip": device_ip,
                "component": "qos_automation",
                "event_type": "qos_config",
                "status": StepStatus.SUCCESS.value,
                "policy_name": policy_name,
                "message": f"QoS configured successfully: {policy_name}"
            }
        )

        return {
            "status": OpStatus.SUCCESS.value,
            "summary": f"QoS policy configured successfully: {policy_name}"
        }

    except Exception as e:
        log.exception(
            "qos_config_exception",
            extra={
                "device_ip": device_ip,
                "component": "qos_automation",
                "event_type": "qos_config",
                "policy_name": policy_name
            }
        )

        return {
            "status": OpStatus.ERROR.value,
            "summary": f"QoS Exception: {str(e)}"
        }
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

                actual_roas = build_roas_state(session)
                expected_roas = context.get("roass", [])

                for roas_data in expected_roas:

                    ok, failures = check_roas(roas_data, actual_roas)

                    base_intf = roas_data.get("router_interface", "unknown")

                    if ok:
                        adapter.info(
                            "roas_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "roas_precheck",
                                "status": StepStatus.SKIPPED.value,
                                "interface": base_intf,
                                "message": f"ROAS already compliant | {base_intf}"
                            }
                        )

                        device_result["actions_taken"].append(
                            f"ROAS compliant | {base_intf}"
                        )
                        continue

      
                    device_result["critical_issues"].extend(failures)

                    adapter.warning(
                        "roas_drift_detected",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "roas_audit",
                            "status": StepStatus.FAILED.value,
                            "interface": base_intf,
                            "failures": failures,
                            "message": f"ROAS drift detected | {base_intf}"
                        }
                    )

                    res = configure_roas(host_ip, roas_data, session, adapter)

                    device_result["actions_taken"].append(
                        res.get("summary", "No Summary Returned")
                    )

                    if res.get("status") == OpStatus.SUCCESS.value:
                        updated = True


                if updated and not DRY_RUN:

                    new_state = build_roas_state(session)

                    for roas_data in expected_roas:

                        ok, failures = check_roas(roas_data, new_state)

                        base_intf = roas_data.get("router_interface", "unknown")

                        if not ok:

                            device_result["critical_issues"].extend(failures)

                            adapter.error(
                                "roas_post_validation_failed",
                                extra={
                                    "device_ip": host_ip,
                                    "component": "main_process",
                                    "event_type": "roas_postcheck",
                                    "status": StepStatus.FAILED.value,
                                    "interface": base_intf,
                                    "failures": failures,
                                    "message": "ROAS post-validation failed"
                                }
                            )

                        else:
                            device_result["actions_taken"].append(
                                f"ROAS validated successfully | {base_intf}"
                            )
                actual_state = build_ospf_state(state)
                expected_ospf = context.get("ospf", [])


                for ospf_data in expected_ospf:

                    pid = ospf_data.get("process_id")

                    ok, failures = check_ospf(ospf_data, actual_state)

                    if ok:
                        adapter.info(
                            "ospf_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "ospf_precheck",
                                "status": StepStatus.SKIPPED.value,
                                "process_id": pid,
                                "message": f"OSPF compliant | process {pid}"
                            }
                        )

                        device_result["actions_taken"].append(
                            f"OSPF compliant | process {pid}"
                        )
                        continue

                    device_result["critical_issues"].extend(failures)

                    adapter.warning(
                        "ospf_drift_detected",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "ospf_audit",
                            "status": StepStatus.FAILED.value,
                            "process_id": pid,
                            "failures": failures,
                            "message": f"OSPF drift detected | process {pid}"
                        }
                    )

                    res = configure_ospf(host_ip, ospf_data, session, adapter)

                    device_result["actions_taken"].append(
                        res.get("summary", "No Summary Returned")
                    )

                    if res.get("status") == OpStatus.CONFIGURED.value:
                        updated = True

                if updated and not DRY_RUN:
                    adapter.info(
                        "ospf_convergence",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "ospf_post_config",
                            "status": StepStatus.IN_PROGRESS.value,
                            "message": "Waiting for OSPF convergence (30s)"
                        }
                    )

                    time.sleep(30)

                if updated and not DRY_RUN:

                    new_state = build_ospf_state(state)

                    for ospf_data in expected_ospf:

                        pid = ospf_data.get("process_id")

                        ok, failures = check_ospf(ospf_data, new_state)

                        if not ok:

                            device_result["critical_issues"].extend(failures)

                            adapter.error(
                                "ospf_post_validation_failed",
                                extra={
                                    "device_ip": host_ip,
                                    "component": "main_process",
                                    "event_type": "ospf_postcheck",
                                    "status": StepStatus.FAILED.value,
                                    "process_id": pid,
                                    "failures": failures,
                                    "message": f"OSPF post-validation failed | process {pid}"
                                }
                            )

                        else:
                            device_result["actions_taken"].append(
                                f"OSPF validated successfully | process {pid}"
                            )
                if updated and not DRY_RUN:
                    adapter.info("⏳ Changes detected. Waiting 30s for network convergence...")
                    time.sleep(30)

                checker = OSPF_Checker()


                expected_ospf = context.get("ospf", [])

                
                for ospf_data in expected_ospf:

                    report = checker.validate_device_ospf(
                        host_ip,
                        state,
                        ospf_data
                    )

                    device_result["ospf_report"].append(report)

                    pid = ospf_data.get("process_id")

                    
                    if report["status"] == "HEALTHY":

                        adapter.info(
                            "ospf_health_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "ospf_check",
                                "status": StepStatus.PASSED.value,
                                "process_id": pid,
                                "message": f"OSPF HEALTHY | process {pid}"
                            }
                        )

                        device_result["actions_taken"].append(
                            f"OSPF HEALTHY | process {pid}"
                        )

                        continue

                  
                    device_result["status"] = "NON-COMPLIANT"

                    device_result["critical_issues"].append({
                        "process_id": pid,
                        "issues": report.get("critical_issues", [])
                    })

                    if report.get("warnings"):
                        device_result["warnings"].append({
                            "process_id": pid,
                            "issues": report["warnings"]
                        })

                    adapter.warning(
                        "ospf_health_failed",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "ospf_check",
                            "status": StepStatus.FAILED.value,
                            "process_id": pid,
                            "message": "OSPF NOT HEALTHY"
                        }
                    )

                    updated = True

            with manager.connect(
            host=host_ip,
            port=830,
            username=device.get("username"),
            password=device.get("password"),
            hostkey_verify=False,
            timeout=30
                ) as session:

            native = collect_netconf_state(session)
            actual_acls = build_acl_state(native)

            expected_acls = context.get("ACL", [])

            acls_to_config = []

            for acl_data in expected_acls:

                acl_name = acl_data.get("acl_name", "")
                expected_rules = sorted(
                    acl_data.get("rules", []),
                    key=lambda x: x.get("seq", 0)
                )

                actual_rules = actual_acls.get(acl_name, [])

                is_ok, failures = check_acl(expected_rules, actual_rules)

                if is_ok:
                    adapter.info(
                        "acl_check",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "acl_precheck",
                            "status": StepStatus.SKIPPED.value,
                            "message": f"ACL already correct | {acl_name}"
                        }
                    )

                    device_result["actions_taken"].append(
                        f"ACL already correct | {acl_name}"
                    )
                    continue

                acls_to_config.append(acl_data)

                device_result["critical_issues"].append({
                    "acl": acl_name,
                    "issues": failures
                })

            for acl_data in acls_to_config:

                result = configure_acl(session, host_ip, acl_data, adapter)

                device_result["actions_taken"].append(
                    result.get("summary", "No Summary Returned")
                )

                if result.get("status") == OpStatus.SUCCESS.value:
                    changed = True

            if changed and not DRY_RUN:

                new_native = collect_netconf_state(session)
                new_actual_acls = build_acl_state(new_native)

                for acl_data in acls_to_config:
                    acl_name = acl_data.get("acl_name")

                    ok, failures = check_acl(
                        sorted(acl_data.get("rules", []), key=lambda x: x.get("seq", 0)),
                        new_actual_acls.get(acl_name, [])
                    )

                    if not ok:
                        device_result["critical_issues"].append({
                            "acl": acl_name,
                            "issues": failures
                        })


                    else: 
                        device_result["critical_issues"].append(
                        f"ACL {acl_name} missing on device {host_ip}"
                                )
                        config_acl = configure_acl(session, host_ip, acl_data, adapter)
                        device_result["actions_taken"].append(
                                config_acl.get("summary", "No Summary Returned")
                           )
                        if config_acl.get("status") == OpStatus.SUCCESS.value: 
                             changed = True
                
            actual_bindings = build_acl_bindings_state(native)
            expected_bindings = context.get("ACL_BINDINGS", [])

            bindings_ok, binding_failures = check_acl_bindings(
                expected_bindings,
                actual_bindings
            )
            if bindings_ok:
                device_result["actions_taken"].append(
                    "ACL bindings already in desired state"
                )

                adapter.info(
                    "acl_binding_check",
                    extra={
                        "device_ip": host_ip,
                        "component": "main_process",
                        "event_type": "acl_binding_precheck",
                        "status": StepStatus.SKIPPED.value,
                        "message": "ACL bindings already correct"
                    }
                )

            else:
                device_result["critical_issues"].extend(binding_failures)

                adapter.warning(
                    "acl_binding_drift",
                    extra={
                        "device_ip": host_ip,
                        "component": "main_process",
                        "event_type": "acl_binding_drift",
                        "status": StepStatus.FAILED.value,
                        "failures": binding_failures
                    }
                )
                config = configure_acl_bindings(
                    session,
                    host_ip,
                    expected_bindings,
                    log
                )

                device_result["actions_taken"].append(
                    config.get("summary", "No Summary Returned")
                )

                if config.get("status") == OpStatus.SUCCESS.value:
                    changed = True

                    new_native = collect_netconf_state(session)
                    new_bindings = build_acl_bindings_state(new_native)

                    post_ok, post_failures = check_acl_bindings(
                        expected_bindings,
                        new_bindings
                    )

                    if not post_ok:
                        device_result["critical_issues"].extend(post_failures)

                        adapter.error(
                            "acl_binding_validation_failed",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "acl_binding_postcheck",
                                "status": StepStatus.FAILED.value,
                                "failures": post_failures
                            }
                        )

                    else:
                        device_result["actions_taken"].append(
                            "ACL bindings validated successfully after config"
                        )
            
            actual_ntp = build_ntp_state(native)

            expected_ntp = context.get("NTP", {})

            ntp_ok, ntp_failures = check_ntp(expected_ntp, actual_ntp)

            if ntp_ok:
                device_result["actions_taken"].append(
                    "NTP already in desired state"
                )

                adapter.info(
                    "ntp_check",
                    extra={
                        "device_ip": host_ip,
                        "component": "main_process",
                        "event_type": "ntp_precheck",
                        "status": StepStatus.SKIPPED.value,
                        "message": "NTP already correctly configured"
                    }
                )

            else:
                device_result["critical_issues"].extend(ntp_failures)

                adapter.warning(
                    "ntp_check",
                    extra={
                        "device_ip": host_ip,
                        "component": "main_process",
                        "event_type": "ntp_drift_detected",
                        "status": StepStatus.FAILED.value,
                        "failures": ntp_failures
                    }
                )

                config_ntp = configure_ntp(
                    session,
                    host_ip,
                    expected_ntp,
                    adapter
                )

                device_result["actions_taken"].append(
                    config_ntp.get("summary", "No Summary Returned")
                )

                if config_ntp.get("status") == OpStatus.SUCCESS.value:
                    changed = True


                    new_native = collect_netconf_state(session)
                    new_ntp = build_ntp_state(new_native)

                    recheck_ok, recheck_failures = check_ntp(
                        expected_ntp,
                        new_ntp
                    )

                    if not recheck_ok:
                        device_result["critical_issues"].extend(recheck_failures)
                        device_result["status"] = "NON-COMPLIANT"

            actual_qos = build_qos_state(native)
            expected_qos = {
                "policy_name": policy_name,
                "class_map": {
                    c["name"]: c for c in qos_data.get("class_map", [])
                    }
                }

            qos_ok, qos_failures = check_qos(expected_qos, actual_qos)

            if qos_ok:
                device_result["actions_taken"].append(
                    "QoS already in desired state"
                )

                adapter.info(
                    "qos_check",
                    extra={
                        "device_ip": host_ip,
                        "component": "main_process",
                        "event_type": "qos_precheck",
                        "status": StepStatus.SKIPPED.value,
                        "message": "QoS already correct"
                    }
                )

            else:
                device_result["critical_issues"].extend(qos_failures)

                adapter.warning(
                    "qos_drift",
                    extra={
                        "device_ip": host_ip,
                        "component": "main_process",
                        "event_type": "qos_drift",
                        "status": StepStatus.FAILED.value,
                        "failures": qos_failures
                    }
                )

                config_qos = configure_qos(
                    session,
                    host_ip,
                    qos_data,
                    adapter
                )

                device_result["actions_taken"].append(
                    config_qos.get("summary", "No Summary Returned")
                )

                if config_qos.get("status") == OpStatus.SUCCESS.value:
                    changed = True

                    new_state = collect_netconf_state(session)
                    new_qos = build_qos_state(new_state)

                    recheck_ok, recheck_failures = check_qos(
                        expected_qos,
                        new_qos
                    )

                    if not recheck_ok:
                        device_result["critical_issues"].extend(recheck_failures)

                        adapter.error(
                            "qos_post_validation_failed",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "qos_postcheck",
                                "status": StepStatus.FAILED.value,
                                "failures": recheck_failures
                            }
                        )
                    else:
                        device_result["actions_taken"].append(
                            "QoS validated successfully after configuration"
                        )

        else:
            with ConnectHandler(**device) as conn:
                conn.enable()

                state = collect_device_state(conn)
                changed = False
                
                actual_inventory = build_vlan_state(state)
                expected_vlans = context.get("vlan", [])


                expected_ids = {str(v["vlan_id"]) for v in expected_vlans}
                actual_ids = set(actual_inventory.keys())
                reserved_vlans = {"1", "1002", "1003", "1004", "1005"}

                extra_vlans = (actual_ids - expected_ids) - reserved_vlans

                for vlan_id in extra_vlans:
                    vlan = actual_inventory.get(vlan_id)

                    adapter.warning(
                        "vlan_drift_detected",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "vlan_drift",
                            "status": StepStatus.FAILED.value,
                            "vlan_id": vlan_id,
                            "name": vlan.get("name") if vlan else None,
                            "message": f"Manual VLAN detected on device: {vlan_id}"
                        }
                    )

                    device_result["critical_issues"].append(
                        f"Unexpected VLAN {vlan_id} found on device"
                    )

                for vlan_data in expected_vlans:

                    vlan_id = str(vlan_data.get("vlan_id"))

                    is_ok, failures = check_vlan(vlan_data, actual_inventory)

                    if is_ok:
                        adapter.info(
                            "vlan_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "vlan_precheck",
                                "status": StepStatus.SKIPPED.value,
                                "message": f"VLAN {vlan_id} is compliant. Skipping."
                            }
                        )

                        device_result["actions_taken"].append(
                            f"VLAN {vlan_id} is compliant. Skipping."
                        )
                        continue


                    device_result["critical_issues"].extend(failures)

                    adapter.info(
                        "vlan_drift_fix",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "vlan_audit",
                            "status": StepStatus.FAILED.value,
                            "vlan_id": vlan_id,
                            "failures": failures,
                            "message": f"VLAN drift detected: {vlan_id}"
                        }
                    )

                    res = configure_vlan(conn, host_ip, vlan_data, adapter)

                    device_result["actions_taken"].append(
                        res.get("summary", "No Summary Returned")
                    )

                    if res.get("status") == OpStatus.SUCCESS.value:
                        changed = True


                if changed and not DRY_RUN:

                    new_inventory = build_vlan_state(conn)

                    for vlan_data in expected_vlans:

                        ok, failures = check_vlan(vlan_data, new_inventory)

                        if not ok:
                            device_result["critical_issues"].extend(failures)

                            adapter.error(
                                "vlan_post_validation_failed",
                                extra={
                                    "device_ip": host_ip,
                                    "component": "main_process",
                                    "event_type": "vlan_postcheck",
                                    "status": StepStatus.FAILED.value,
                                    "vlan_id": vlan_data.get("vlan_id"),
                                    "failures": failures,
                                    "message": "Post-validation failed"
                                }
                            )

                        else:
                            device_result["actions_taken"].append(
                                f"VLAN {vlan_data.get('vlan_id')} validated successfully"
                            )

                actual_access = build_access_state(state)
                expected_access = context.get("access_ports", [])

                expected_interfaces = {
                    str(a.get("access_interface", "")).lower().strip()
                    for a in expected_access
                }

                actual_interfaces = set(actual_access.keys())

                extra_access_ports = actual_interfaces - expected_interfaces

                for intf in extra_access_ports:

                    port = actual_access.get(intf)

                    adapter.warning(
                        "access_drift_detected",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "access_drift",
                            "status": StepStatus.FAILED.value,
                            "interface": intf,
                            "access_vlan": port.get("access_vlan"),
                            "message": f"Unexpected access port detected: {intf}"
                        }
                    )

                    device_result["critical_issues"].append(
                        f"Unexpected access port found on {intf}"
                    )

                for access_data in expected_access:

                    intf = str(
                        access_data.get("access_interface", "")
                    ).lower().strip()

                    ok, failures = check_access_port(
                        access_data,
                        actual_access
                    )

                    if ok:

                        adapter.info(
                            "access_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "access_precheck",
                                "status": StepStatus.SKIPPED.value,
                                "interface": intf,
                                "message": f"Access port {intf} is compliant"
                            }
                        )

                        device_result["actions_taken"].append(
                            f"Access port {intf} is compliant. Skipping."
                        )

                        continue


                    device_result["critical_issues"].extend(failures)

                    adapter.info(
                        "access_drift_fix",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "access_audit",
                            "status": StepStatus.FAILED.value,
                            "interface": intf,
                            "failures": failures,
                            "message": f"Access port drift detected on {intf}"
                        }
                    )


                    result = configure_access_ports(
                        conn,
                        host_ip,
                        access_data,
                        adapter
                    )

                    device_result["actions_taken"].append(
                        result.get("summary", "No Summary Returned")
                    )

                    if result.get("status") == OpStatus.SUCCESS.value:
                        changed = True


                if changed and not DRY_RUN:

                    new_state = collect_device_state(conn)
                    new_access = build_access_state(new_state)

                    for access_data in expected_access:

                        intf = str(
                            access_data.get("access_interface", "")
                        ).lower().strip()

                        ok, failures = check_access_port(
                            access_data,
                            new_access
                        )

                        if not ok:

                            device_result["critical_issues"].extend(failures)

                            adapter.error(
                                "access_post_validation_failed",
                                extra={
                                    "device_ip": host_ip,
                                    "component": "main_process",
                                    "event_type": "access_postcheck",
                                    "status": StepStatus.FAILED.value,
                                    "interface": intf,
                                    "failures": failures,
                                    "message": "Post-validation failed"
                                }
                            )

                        else:

                            device_result["actions_taken"].append(
                                f"Access port {intf} validated successfully"
                            )
                                actual_trunks = build_trunk_state(state)
                                expected_trunks = context.get("trunk_ports", [])

                                changed = False

                                expected_interfaces = {
                                    str(t.get("trunk_interface", "")).lower().strip()
                                    for t in expected_trunks
                                }

                actual_interfaces = set(actual_trunks.keys())

                extra_trunks = actual_interfaces - expected_interfaces

                for intf in extra_trunks:

                    trunk = actual_trunks.get(intf)

                    adapter.warning(
                        "trunk_drift_detected",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "trunk_drift",
                            "status": StepStatus.FAILED.value,
                            "interface": intf,
                            "allowed_vlans": trunk.get("allowed_vlans"),
                            "message": f"Unexpected trunk detected on {intf}"
                        }
                    )

                    device_result["critical_issues"].append(
                        f"Unexpected trunk found on {intf}"
                    )

                for trunk_data in expected_trunks:

                    intf = str(
                        trunk_data.get("trunk_interface", "")
                    ).lower().strip()

                    ok, failures = check_trunk(
                        trunk_data,
                        actual_trunks
                    )

                    if ok:

                        adapter.info(
                            "trunk_check",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "trunk_precheck",
                                "status": StepStatus.SKIPPED.value,
                                "interface": intf,
                                "message": f"Trunk {intf} is compliant"
                            }
                        )

                        device_result["actions_taken"].append(
                            f"Trunk {intf} is compliant. Skipping."
                        )

                        continue

                    device_result["critical_issues"].extend(
                        failures
                    )

                    adapter.info(
                        "trunk_drift_fix",
                        extra={
                            "device_ip": host_ip,
                            "component": "main_process",
                            "event_type": "trunk_audit",
                            "status": StepStatus.FAILED.value,
                            "interface": intf,
                            "failures": failures,
                            "message": f"Trunk drift detected on {intf}"
                        }
                    )

                    result = configure_trunk_ports(
                        conn,
                        host_ip,
                        trunk_data,
                        adapter
                    )

                    device_result["actions_taken"].append(
                        result.get(
                            "summary",
                            "No Summary Returned"
                        )
                    )

                    if result.get("status") == OpStatus.SUCCESS.value:
                        changed = True

                if changed and not DRY_RUN:

                    new_state = collect_device_state(conn)
                    new_trunks = build_trunk_state(new_state)

                    for trunk_data in expected_trunks:

                        intf = str(
                            trunk_data.get("trunk_interface", "")
                        ).lower().strip()

                        ok, failures = check_trunk(
                            trunk_data,
                            new_trunks
                        )

                        if not ok:

                            device_result["critical_issues"].extend(
                                failures
                            )

                            adapter.error(
                                "trunk_post_validation_failed",
                                extra={
                                    "device_ip": host_ip,
                                    "component": "main_process",
                                    "event_type": "trunk_postcheck",
                                    "status": StepStatus.FAILED.value,
                                    "interface": intf,
                                    "failures": failures,
                                    "message": "Post-validation failed"
                                }
                            )

                    actual_interfaces = build_interface_state(new_state)

                    expected_interfaces = config_data.get("interfaces", [])

                    changed = False

    
                    for intf_data in expected_interfaces:

                        ok, failures = check_interface(intf_data, actual_interfaces)

                        intf_name = intf_data.get("interface")

                        if ok:
                            adapter.info(
                                "interface_check",
                                extra={
                                    "device_ip": host_ip,
                                    "component": "main_process",
                                    "event_type": "interface_precheck",
                                    "status": StepStatus.SKIPPED.value,
                                    "message": f"Interface {intf_name} compliant"
                                }
                            )

                            device_result["actions_taken"].append(
                                f"Interface {intf_name} already compliant"
                            )
                            continue

                        device_result["critical_issues"].extend(failures)

                        adapter.warning(
                            "interface_drift_detected",
                            extra={
                                "device_ip": host_ip,
                                "component": "main_process",
                                "event_type": "interface_audit",
                                "status": StepStatus.FAILED.value,
                                "interface": intf_name,
                                "failures": failures,
                                "message": f"Interface drift detected: {intf_name}"
                            }
                        )

                        res = configure_interface(
                            session,
                            host_ip,
                            intf_data,
                            log
                        )

                        device_result["actions_taken"].append(
                            res.get("summary", "No Summary Returned")
                        )

                        if res.get("status") == OpStatus.SUCCESS.value:
                            changed = True

                    if changed and not DRY_RUN:

                    new_state = build_interface_state(
                        collect_device_state(conn)
                    )

                    for intf_data in expected_interfaces:

                        ok, failures = check_interface(intf_data, new_state)

                        intf_name = intf_data.get("interface")

                        if not ok:

                            device_result["critical_issues"].extend(failures)

                            adapter.error(
                                "interface_post_validation_failed",
                                extra={
                                    "device_ip": host_ip,
                                    "component": "main_process",
                                    "event_type": "interface_postcheck",
                                    "status": StepStatus.FAILED.value,
                                    "interface": intf_name,
                                    "failures": failures,
                                    "message": "Post-validation failed"
                                }
                            )

                        else:
                            device_result["actions_taken"].append(
                                f"Interface {intf_name} validated successfully"

        
    finally:
    end = datetime.utcnow()
    device_result["end_time"] = end.isoformat()

    device_result["duration_seconds"] = (
        end - datetime.fromisoformat(device_result["start_time"])
    ).total_seconds()

    if device_result["critical_issues"]:
        device_result["status"] = "NON-COMPLIANT"
    elif device_result["status"] != "FAILED":
        device_result["status"] = "COMPLIANT"

    return device_result

def main():
    main_log = logging.LoggerAdapter(logger, {"dev": "MAIN"})
    main_log.info("🚀 INITIALIZING HYBRID NETDEV-OPS ENGINE...")

    COMPLIANCE_RESULTS = []

    try:
        inventory, config_data = get_netbox()
        main_log.info(f"✅ NetBox Sync Successful. ({len(inventory)} devices found)")

        tasks = []
        for dev in inventory:
            ip = dev["host"]

            ctx = config_data.get(ip)
            tasks.append({
                "device": dev,
                "context": copy.deepcopy(ctx) if ctx else {}
            })

        num_workers = min(len(inventory), 15)

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(main_process, t) for t in tasks]

            for f in as_completed(futures):
                try:
                    result = f.result()
                    COMPLIANCE_RESULTS.append(result)

                except Exception as e:
                    main_log.error(f"❌ Device thread failed: {e}")
                    COMPLIANCE_RESULTS.append({
                        "device_name": "UNKNOWN",
                        "status": "FAILED",
                        "error": str(e)
                    })

        report = {
            "run_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "total_devices": len(inventory),
                "successful_runs": len([r for r in COMPLIANCE_RESULTS if r.get("status") != "FAILED"])
            },
            "devices": COMPLIANCE_RESULTS,
            "summary": {
                "compliant": len([r for r in COMPLIANCE_RESULTS if r.get("status") == "COMPLIANT"]),
                "non_compliant": len([r for r in COMPLIANCE_RESULTS if r.get("status") == "NON-COMPLIANT"]),
                "failed": len([r for r in COMPLIANCE_RESULTS if r.get("status") == "FAILED"])
            }
        }

        with open("final_compliance_report.json", "w") as f:
            json.dump(report, f, indent=4, default=str)

        main_log.info("📊 Final Compliance Report saved successfully")

    except Exception as e:
        main_log.error(f"❌ ENGINE ABORTED: {e}")

    finally:
        logging.LoggerAdapter(logger, {"dev": "FINAL"}).info(
            "🏁 AUTOMATION CYCLE COMPLETE"
        )
if __name__ == "__main__":
    main()