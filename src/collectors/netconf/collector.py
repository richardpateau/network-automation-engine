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
            data = xmltodict.parse(
                response.data_xml
            )

            netconf_state["native_netconf"] = (
                data.get("rpc-reply", {})
                    .get("data", {})
                    .get("native", {})
            )

    except Exception as e:

        log.error(
            f"NETCONF collection failed | {e}"
        )

        netconf_state["native_netconf"] = {}

    return netconf_state