from src.utils import safe_int
from ciscoconfparse import CiscoConfParse


# VLAN
def build_vlan(device_state):
    if not device_state:
        return {}

    device_state_vlan = device_state.get("vlans") or {}

    vlan_data = device_state_vlan.get("vlans", {})
    actual_vlans = {}
    for vlan_id, vlan_values in vlan_data.items():
        actual_vlans[safe_int(vlan_id)] = {
            "name": vlan_values.get("name"),
        }
    return actual_vlans


# ACCESS PORT
def build_access(device_state):
    if not device_state:
        return {}

    device_state_access = device_state.get("switchports") or {}
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
            "access_vlan": access_vlan,
        }
    return actual_access


# TRUNK PORT
def build_trunk(device_state):
    if not device_state:
        return {}

    device_state_trunk = device_state.get("switchports") or {}
    actual_trunk = {}
    for trunk_int, trunk_values in device_state_trunk.items():
        if not isinstance(trunk_values, dict):
            continue

        operational_mode = trunk_values.get("operational_mode", "").lower()

        if "trunk" not in operational_mode:
            continue
        allowed_vlans = trunk_values.get("trunk_vlans", "")

        actual_trunk[trunk_int] = {
            "trunk_interface": trunk_int,
            "allowed_vlans": allowed_vlans,
            "mode": operational_mode,
        }
    return actual_trunk


# INTERFACE
def build_interface(device_state):
    if not device_state:
        return {}

    device_state_interface = device_state.get("interfaces") or {}
    actual_interfaces = {}
    interfaces = device_state_interface.get("interface", {})
    for interface_name, interface_values in interfaces.items():
        if not isinstance(interface_values, dict):
            continue
        status = interface_values.get("status", "")
        protocol = interface_values.get("protocol", "")
        interface_name = interface_name.lower().strip()
        actual_interfaces[interface_name] = {
            "interface": interface_name,
            "status": status,
            "protocol": protocol,
            "is_up": status == "up" and protocol == "up",
        }
    return actual_interfaces


# STP GLOBAL
def build_stp_global(device_state):
    if not device_state:
        return {}
    stp = device_state.get("stp") or {}
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
        if vlan is None:
            continue

        priority = safe_int(
            data.get("bridge", {}).get("configured_bridge_priority", 32768)
        )

        actual_stp["vlan_priorities"][vlan] = priority
    return actual_stp


# STP INTERFACE
def build_stp_interfaces(device_state):
    if not device_state:
        return {}
    running_config = device_state.get("running_config") or ""
    parse = CiscoConfParse(running_config.splitlines())
    act_stp_int = {}
    for interface in parse.find_objects(r"^interface"):
        parts = interface.text.split()
        if len(parts) < 2:
            continue

        name = parts[1].strip().lower()
        act_stp_int[name] = {
            "portfast": False,
            "bpdu_guard": False,
            "root_guard": False,
            "loop_guard": False,
            "bpdu_filter": False,
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


# SNMP
def build_snmp_netmiko(device_state):
    if not device_state:
        return {}
    running_config = device_state.get("running_config") or ""
    parse = CiscoConfParse(running_config.splitlines())
    actual_snmp = {
        "communities": [],
        "hosts": [],
        "traps": {},
        "location": "",
        "contact": "",
    }

    for s in parse.find_objects(r"^snmp-server community"):
        parts = s.text.split()

        actual_snmp["communities"].append(
            {"snmp_name": parts[2].lower(), "permission": parts[3].lower()}
        )
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
            actual_snmp["hosts"].append(
                {"snmp_ip": parts[2], "snmp_version": parts[4], "snmp_name": parts[5]}
            )
    return actual_snmp


# SYSLOG
def build_syslog_netmiko(device_state):
    if not device_state:
        return {}
    actual_syslog = {
        "hosts": [],
        "trap_level": "",
        "source_interface": "",
        "timestamps": False,
    }
    state_logging = device_state.get("syslog") or {}
    logging = state_logging.get("logging") or {}
    running_config = device_state.get("running_config") or ""
    parse = CiscoConfParse(running_config.splitlines())
    for p in parse.find_objects(r"^service timestamps"):
        if "log datetime msec" in p.text:
            actual_syslog["timestamps"] = True
    trap_level = logging.get("trap", {}).get("level", "")
    if trap_level:
        actual_syslog["trap_level"] = trap_level.lower()
    logging_to = logging.get("trap", {}).get("logging_to", {})
    if logging_to:
        actual_syslog["hosts"] = list(logging_to.keys())
    source_interface = logging.get("trap", {}).get("logging_source_interface", {})
    if source_interface:
        for interface in source_interface.keys():
            actual_syslog["source_interface"] = interface.lower()
    return actual_syslog


# CDP
def build_cdp_netimko(device_state):
    if not device_state:
        return {"enabled": False, "timer": None, "holdtime": None, "interfaces": {}}
    actual_cdp = {"enabled": False, "timer": None, "holdtime": None, "interfaces": {}}
    run_global = device_state.get("cdp") or ""
    run_interface = device_state.get("cdp_interface") or ""
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
        interface_name = config[0].lower()

        actual_cdp["interfaces"][interface_name] = {"enabled": True}
    return actual_cdp


# PORT SECURITY
def build_port_security(device_state):
    if not device_state:
        return {"interfaces": {}}
    running_config = device_state.get("running_config") or ""
    parse = CiscoConfParse(running_config.splitlines())

    actual_psecurity = {"interfaces": {}}
    for p in parse.find_objects(r"^interface"):
        interface_name = p.text.split()[1]
        ps_config = actual_psecurity["interfaces"].setdefault(
            interface_name.lower(),
            {
                "enabled": False,
                "maximum": None,
                "violation": None,
                "sticky": False,
                "mac_addresses": [],
            },
        )
        for child in p.children:
            full_config = child.text.strip()
            config = child.text.strip().split()
            if "switchport port-security" == full_config:
                ps_config["enabled"] = True
            if "port-security maximum" in full_config:
                ps_config["maximum"] = safe_int(config[-1])
            if "port-security violation" in full_config:
                ps_config["violation"] = config[-1]
            if "port-security mac-address sticky" in full_config:
                ps_config["sticky"] = True
            if (
                "switchport port-security mac-address" in full_config
                and "sticky" not in full_config
            ):
                ps_config["mac_addresses"].append(config[-1])
            if ps_config["enabled"] and ps_config["violation"] is None:
                ps_config["violation"] = "shutdown"
    return actual_psecurity


# DHCP SNOOPING
def build_snooping(device_state):
    if not device_state:
        return {"enabled_vlans": [], "interfaces": {}, "option82": False}
    running_config = device_state.get("running_config") or ""
    actual_snooping = {"enabled_vlans": [], "interfaces": {}, "option82": False}
    parse = CiscoConfParse(running_config.splitlines())
    for p in parse.find_objects(r"^ip dhcp snooping"):
        full_config = p.text.strip()
        config = p.text.split()
        if "snooping vlan" in full_config:
            vlan = config[-1].split(",")
            vlan_list = [safe_int(v) for v in vlan if v.isdigit()]
            actual_snooping["enabled_vlans"] = vlan_list
    for p in parse.find_objects(r"^no ip dhcp snooping"):
        if "no ip dhcp snooping information" in full_config:
            actual_snooping["option82"] = False
        else:
            actual_snooping["option82"] = True
    for p in parse.find_objects(r"^interface"):
        part = p.text.split().lower()
        interface_name = part[-1]

        for child in p.children:
            full_config = child.text.strip()
            config = child.text.split()

            if "snooping limit rate" in full_config:
                actual_snooping["interfaces"][interface_name]["rate_limit"] = safe_int(
                    config[-1]
                )
            if "snooping trust" in full_config:
                actual_snooping["interfaces"][interface_name]["trusted"] = True
    return actual_snooping


# DAI
def build_dai(device_state):
    if not device_state:
        return {
            "arp_inspection": "",
            "enabled_vlans": [],
            "interfaces": {},
            "log_buffer": {},
        }
    running_config = device_state.get("running_config") or ""
    dai_interfaces = device_state.get("dai_interfaces") or ""
    parse = CiscoConfParse(running_config.splitlines())
    actual_dai = {
        "arp_inspection": False,
        "enabled_vlans": [],
        "interfaces": {},
        "log_buffer": {},
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
                "entries": safe_int(config[-1]),
            }
    for config in dai_interfaces.splitlines():
        parts = config.split()

        if len(parts) >= 4 and parts[0].startswith("Gi"):
            interface = parts[0].lower()
            rate = safe_int(parts[2])

            actual_dai["interfaces"][interface] = {
                "rate_limit": rate,
                "trusted": parts[1].lower() == "trusted",
            }
    return actual_dai


# ETHERCHANNEL
def build_etherchannel(device_state):
    if not device_state:
        return {"enabled": False, "groups": {}}
    running_config = device_state.get("running_config") or ""
    parse = CiscoConfParse(running_config.splitlines())
    actual_ether = {"enabled": False, "groups": {}}

    for p in parse.find_objects(r"^interface"):
        config = p.text.strip().split()
        interface_name = config[-1].strip().lower()
        full_config = p.text.strip()
        for c in p.children:
            full_config = c.text.strip()
            config = c.text.strip().split()

            if "channel-group" in full_config:
                group = safe_int(config[-3])
                mode = config[-1]
                group_entry = actual_ether["groups"].setdefault(
                    group,
                    {
                        "mode": mode,
                        "interfaces": [],
                        "description": None,
                        "switchport_mode": None,
                        "type": None,
                        "enabled": True,
                    },
                )
                group_entry["enabled"] = True
                group_entry["interfaces"].append(interface_name)

                if mode in ["active", "passive"]:
                    group_entry["type"] = "lacp"
                elif mode in ["desirable", "auto"]:
                    group_entry["type"] = "pagp"
                else:
                    group_entry["type"] = "static"
    for p in parse.find_objects(r"^interface Port-channel"):
        config = p.text.strip().split().lower()
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
