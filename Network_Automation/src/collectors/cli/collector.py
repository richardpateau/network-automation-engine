def collect_device_state(conn):
    device_state = {}
    try:
        device_state["vlans"] = conn.send_command("show vlan", use_genie=True)
    except Exception:
        device_state["vlans"] = {}

    try:
        device_state["switchports"] = conn.send_command(
            "show interfaces switchport", use_genie=True
        )
    except Exception:
        device_state["switchports"] = {}

    try:
        device_state["interfaces"] = conn.send_command(
            "show ip interface brief", use_genie=True
        )
    except Exception:
        device_state["interfaces"] = {}
    try:
        device_state["stp"] = conn.send_command("show spanning-tree", use_genie=True)
    except Exception:
        device_state["stp"] = {}
    try:
        device_state["running_config"] = conn.send_command("show run")
    except Exception:
        device_state["running_config"] = ""
    try:
        device_state["syslog"] = conn.send_command("show logging", use_genie=True)
    except Exception:
        device_state["syslog"] = {}
    try:
        device_state["cdp"] = conn.send_command("show cdp")
    except Exception:
        device_state["cdp"] = ""
    try:
        device_state["cdp_interface"] = conn.send_command("show cdp interface")
    except Exception:
        device_state["cdp_interface"] = ""
    return device_state
    try:
        device_state["dai_interfaces"] = conn.send_command(
            "show ip arp inspection interfaces"
        )

    except Exception:
        device_state["dai_interfaces"] = ""
