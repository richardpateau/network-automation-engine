def collect_restconf_state(restconf, log):
    restconf_state = {}

    try:
        session = restconf.session
        base_url = restconf.base_url

        # Interface
        interface_url = (
            f"{base_url}/Cisco-IOS-XE-native:native/interface"
        )

        restconf_state["interface_restconf"] = (
            restconf_get(session, interface_url)
        )


        # OSPF configuration
        ospf_url = (
            f"{base_url}/Cisco-IOS-XE-native:native/router"
        )

        restconf_state["ospf_restconf"] = (
            restconf_get(session, ospf_url)
        )


        # OSPF operational state
        ospf_oper_url = (
            f"{base_url}/Cisco-IOS-XE-ospf_oper:ospf-oper-data"
        )

        restconf_state["ospf_oper_restconf"] = (
            restconf_get(session, ospf_oper_url)
        )


    except Exception as e:
        log.exception(
            f"RESTCONF collection failed | {restconf.device_ip} | {e}"
        )

    return restconf_state

def restconf_get(session, url):
    try:
        response = session.get(url, verify=False)

        response.raise_for_status()

        return response.json()
    except requests.exceptions.HTTPError as e:
        raise Exception(f"RESTCONF HTTP error: {e} | URL: {url}")

    except requests.exceptions.RequestException as e:
        raise Exception(f"RESTCONF request failed: {e} | URL: {url}")
