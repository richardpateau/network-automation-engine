from src.pipeline.resolver import resolve_pipeline

def has_expected_config(feature, context):


    value = context.get(feature)

    if feature in {
        "vlans",
        "access_ports",
        "trunk_ports",
        "roas",
        "hsrp",
        "ospf",
        "static_routes",
    }:
        return bool(value)

    # Interfaces: an interface name alone is not sufficient.
    if feature == "interfaces":
        return any(
            bool(item.get("description"))
            or item.get("should_be_up") not in ("", None)
            or any(item.get("stp", {}).values())
            for item in (value or [])
        )

    if feature == "etherchannel":
        return bool(value.get("enabled")) or bool(value.get("groups"))

    if feature == "stp":
        return bool(value.get("mode")) or bool(value.get("vlan_priorities"))

    if feature == "nat":
        return any([
            bool(value.get("dynamic")),
            bool(value.get("static")),
            bool(value.get("pat")),
            bool(value.get("interfaces", {}).get("inside")),
            bool(value.get("interfaces", {}).get("outside")),
        ])

    if feature == "dhcp_snooping":
        return any([
            bool(value.get("enabled_vlans")),
            bool(value.get("interfaces")),
            bool(value.get("option82")),
        ])

    if feature == "dai":
        return any([
            bool(value.get("enabled_vlans")),
            bool(value.get("interfaces")),
            bool(value.get("log_buffer")),
        ])

    if feature == "port_security":
        return bool(value.get("interfaces"))

    if feature == "dhcp":
        return any([
            bool(value.get("excluded_addresses")),
            bool(value.get("pools")),
            bool(value.get("helper", {}).get("interfaces")),
        ])

    if feature == "ntp":
        return bool(value.get("keys")) or bool(value.get("servers"))

    if feature == "snmp":
        return any([
            bool(value.get("communities")),
            bool(value.get("hosts")),
            bool(value.get("traps")),
            bool(value.get("location")),
            bool(value.get("contact")),
        ])

    if feature == "syslog":
        return any([
            bool(value.get("hosts")),
            bool(value.get("facility")),
            bool(value.get("trap_level")),
            bool(value.get("source_interface")),
            bool(value.get("timestamps")),
        ])

    if feature == "cdp":
        return any([
            bool(value.get("enabled")),
            bool(value.get("timer")),
            bool(value.get("holdtime")),
            bool(value.get("interfaces")),
        ])

    return bool(value)


def run_pipeline(
    pipeline,
    context,
    session,
    device_state,
    device_result,
    log,
    device_ip,
    transport
):
    order = resolve_pipeline(pipeline)

    if context is None:
        context = {}

    for feature in order:

        feature_config = pipeline[feature]
        context_key = feature_config.get("context_key", feature)

        if not has_expected_config(context_key, context):
            log.debug(
                "Skipping feature | %s | No expected configuration",
                feature
            )
            continue

        compliance_function = feature_config["function"]

        try:
            compliance_function(
                session,
                device_ip,
                context,
                device_state,
                device_result,
                log,
                transport
            )

        except Exception as e:
            log.exception(
                "Pipeline failed | %s | %s",
                feature,
                e
            )

            device_result["critical_issues"].append(
                f"{feature} pipeline failure"
            )

    return device_result
