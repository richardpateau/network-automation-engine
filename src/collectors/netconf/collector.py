import xmltodict
def collect_netconf_state(netconf, log):

    netconf_state = {}

    filter_xml = """
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"/>
    """

    try:

        response = netconf.session.get_config(
            source="running",
            filter=("subtree", filter_xml)
        )
        if response.ok:
            parsed = xmltodict.parse(response.data_xml)
            data = parsed.get("data") or parsed.get("rpc-reply", {}).get("data") or {}
            netconf_state["native_netconf"] = data.get("native") or {}

    except Exception as e:

        log.error(
            f"NETCONF collection failed | {e}"
        )

        netconf_state["native_netconf"] = {}

    return netconf_state