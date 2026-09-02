from src.compliance.switching.vlan.compliance import compliance_vlan
from src.compliance.switching.interface.compliance import compliance_interface
from src.compliance.switching.access.compliance import compliance_access
from src.compliance.switching.trunk.compliance import compliance_trunk
from src.compliance.switching.etherchannel.compliance import compliance_etherchannel
from src.compliance.switching.stp.compliance import compliance_stp_global, compliance_stp_interfaces
from src.compliance.routing.ospf.compliance import compliance_ospf
from src.compliance.routing.roas.compliance import compliance_roas
from src.compliance.routing.hsrp.compliance import compliance_hsrp
from src.compliance.routing.static.compliance import compliance_static
from src.compliance.routing.nat.compliance import compliance_nat
from src.compliance.security.dai.compliance import compliance_dai
from src.compliance.security.dhcp_snooping.compliance import compliance_snooping
from src.compliance.security.port_security.compliance import compliance_port_security
from src.compliance.services.cdp.compliance import compliance_cdp
from src.compliance.services.dhcp.compliance import compliance_dhcp
from src.compliance.services.ntp.compliance import compliance_ntp
from src.compliance.services.qos.compliance import compliance_qos
from src.compliance.services.snmp.compliance import compliance_snmp
from src.compliance.services.syslog.compliance import compliance_syslog

PIPELINE = {

    "vlans": {
        "function": compliance_vlan,
        "depends_on": [],
        "context_key": "vlans",
    	"transport": "NETMIKO",
    },

    "interfaces": {
        "function": compliance_interface,
        "depends_on": ["vlans"],
        "context_key": "interfaces",
    	"transport": "NETMIKO",
    },

    "access_ports": {
        "function": compliance_access,
        "depends_on": ["vlans", "interfaces"],
        "context_key": "access_ports",
    	"transport": "NETMIKO",
    },

    "trunk_ports": {
        "function": compliance_trunk,
        "depends_on": ["vlans", "interfaces"],
        "context_key": "trunk_ports",
    	"transport": "NETMIKO",
    },

    "etherchannel": {
        "function": compliance_etherchannel,
        "depends_on": [
            "vlans",
            "interfaces",
            "trunk_ports"
        ],
        "context_key": "etherchannel",
    	"transport": "NETMIKO",
    },

    "stp": {
        "function": compliance_stp_global,
        "depends_on": [
            "vlans",
            "etherchannel"
        ],
        "context_key": "stp",
    	"transport": "NETMIKO",
    },

    "stp_interfaces": {
        "function": compliance_stp_interfaces,
        "depends_on": [
            "vlans",
            "etherchannel"
        ],
        "context_key": "interfaces",
    	"transport": "NETMIKO",
    },


    "roas": {
        "function": compliance_roas,
        "depends_on": [
            "vlans",
            "interfaces"
        ],
        "context_key": "roas",
    	"transport": "RESTCONF",
    },

    "hsrp": {
        "function": compliance_hsrp,
        "depends_on": [
            "roas"
        ],
        "context_key": "hsrp",
    	"transport": "NETCONF",
    },

    "ospf": {
        "function": compliance_ospf,
        "depends_on": [
            "roas"
        ],
        "context_key": "ospf",
    	"transport": "RESTCONF",
    },

    "static_routes": {
        "function": compliance_static,
        "depends_on": [
            "interfaces"
        ],
        "context_key": "static_routes",
    	"transport": "NETCONF",
    },

    "nat": {
        "function": compliance_nat,
        "depends_on": [
            "interfaces",
            "roas"
        ],
        "context_key": "nat",
    	"transport": "NETMIKO",
    },


    "dhcp_snooping": {
        "function": compliance_snooping,
        "depends_on": [
            "vlans",
            "access_ports",
            "trunk_ports"
        ],
        "context_key": "dhcp_snooping",
    	"transport": "NETMIKO",
    },

    "dai": {
        "function": compliance_dai,
        "depends_on": [
            "dhcp_snooping"
        ],
        "context_key": "dai",
    	"transport": "NETMIKO",
    },

    "port_security": {
        "function": compliance_port_security,
        "depends_on": [
            "access_ports"
        ], 
        "context_key": "port_security",
    	"transport": "NETMIKO",
    },


    "dhcp": {
        "function": compliance_dhcp,
        "depends_on": [
            "interfaces",
            "roas"
        ],
        "context_key": "dhcp",
    	"transport": "NETCONF",
    },

    "ntp": {
        "function": compliance_ntp,
        "depends_on": [
            "interfaces"
        ],
        "context_key": "ntp",
    	"transport": "NETCONF",
    },

    "snmp": {
        "function": compliance_snmp,
        "depends_on": [
            "interfaces"
        ],
        "context_key": "snmp",
    },

    "syslog": {
        "function": compliance_syslog,
        "depends_on": [
            "interfaces"
        ],
        "context_key": "syslog",
    },
	"cdp": {
		    "function": compliance_cdp,
		    "depends_on": [
		        "interfaces"
		    ],
		   	"context_key": "cdp",
		},
			

}