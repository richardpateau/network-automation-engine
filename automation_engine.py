import ipaddress
import os
from concurrent.futures.thread import ThreadPoolExecutor
import requests
import urllib3
from jinja2 import Environment, FileSystemLoader
from netmiko import ConnectHandler
import pynetbox
import logging
template_env=Environment(
    loader=FileSystemLoader('/run/media/rich/HDD/Templates/'),trim_blocks=True,lstrip_blocks=True
)
DRY_RUN=False
os.environ["NET_TEXTFSM"] = "/home/rich/netlab/lib/python3.14/site-packages/ntc_templates/templates"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger=logging.getLogger('NetworkAutomation')
logger.setLevel(logging.INFO)
file=logging.FileHandler('network_automation.log')
file.setFormatter(logging.Formatter('%(asctime)s - [%(dev)s] - %(levelname)s - %(message)s'))
logger.addHandler(file)
console=logging.StreamHandler()
console.setFormatter(logging.Formatter('[%(dev)s] - %(message)s'))
logger.addHandler(console)
def clean_interface_name(name):
    return "".join([c for c in name if c.isdigit() or c == "/" or c=="."])
###############################INVENTORY##################################################################
def get_netbox():
    nb=pynetbox.api(url=netbox_url,token=netbox_token)
    inventory=[]
    config_data={"vlans":[],"access_ports":[],"trunks":[],"interfaces":[],"roass":[]}
    dev=nb.dcim.devices.all()
    for device_name in dev:
        if not device_name.platform.slug or not device_name.primary_ip:
            continue
        host_ip=str(device_name.primary_ip.address.split('/')[0])
        inventory.append({
            "host":host_ip,
            "device_type":device_name.platform.slug,
            "name":device_name.name,
            "username":"sysadmin",
            "password":"*******",
            "secret":"********"
        })
        device_vlan = {}
        interfaces=nb.dcim.interfaces.filter(device_id=device_name.id)
        for device_interface in interfaces:
            is_switch=device_name.role.slug=="switch"
            if device_interface.mode and device_interface.mode.value=="access" and device_interface.untagged_vlan:
                if is_switch:
                    config_data['access_ports'].append({
                            "device":host_ip,
                            "access_interface":device_interface.name,
                            "access_vlan":device_interface.untagged_vlan.vid
                        })
                    if device_interface.untagged_vlan:
                            v = device_interface.untagged_vlan
                            device_vlan[v.id]= v
            if device_interface.mode and device_interface.mode.value=="tagged" and device_interface.tagged_vlans:
                if is_switch:
                    vlan_list= ",".join([str(v.vid) for v in device_interface.tagged_vlans])
                    config_data['trunks'].append({
                            "device":host_ip,
                            "trunk_interface":device_interface.name,
                            "allowed_vlans":vlan_list
                        })
                    if device_interface.tagged_vlans:
                        for v in device_interface.tagged_vlans:
                            device_vlan[v.id]=v
            if device_name.role.slug=="router" and device_interface.type.value !="virtual":
                config_data['interfaces'].append({
                        "device":host_ip,
                        "r_interface":device_interface.name
                    })
            if device_name.role.slug=="router" and device_interface.type and device_interface.type.value=="virtual":
                router_ip=list(nb.ipam.ip_addresses.filter(interface_id=device_interface.id))
                if router_ip:  # Always check if the list is not empty!
                    new_ip = ipaddress.ip_interface(router_ip[0].address)
                    if device_interface.parent:
                        config_data['roass'].append({
                            "device":host_ip,
                            "router_interface":device_interface.parent.name,
                            "router_vlan": str(device_interface.tagged_vlans[0].vid) if device_interface.tagged_vlans else 10,
                            "ip":str(new_ip.ip),
                            "mask":str(new_ip.netmask)
                        })
        for v_id in device_vlan.values():
            is_switch = device_name.role.slug == "switch"
            if is_switch:
                    config_data['vlans'].append({
                    "device":host_ip,
                    "vlan_id":str(v_id.vid),
                    "name":str(v_id.name)
                })

    return inventory,config_data
############################## CHECK FUNCTIONS ###########################################################
def check_vlans(conn,vlan_id,name):
    vlan_string = str(vlan_id)
    try:
        data=conn.send_command("show vlan", use_genie=True)
        if vlan_string in data['vlans']:
            return data['vlans'][vlan_string]['name']==name
        return False
    except Exception:
        output=conn.send_command("show vlan brief")
        return f"{vlan_string}" in output and f"{name}" in output
def check_switchport(conn,switch_interface,mode,vlan_or_allowed):
    try:
        data=conn.send_command(f"show interface {switch_interface} switchport", use_genie=True)
        operational_mode=data[switch_interface]['operational_mode']
        if mode=="access":
            return "access" in operational_mode and str(vlan_or_allowed)==str(data[switch_interface]['access_vlan'])
        if mode=="trunk":
            return "trunk" in operational_mode and str(vlan_or_allowed) in str(data[switch_interface]['trunk_vlans'])
        return False
    except Exception:
        output=conn.send_command(f"show run interface {switch_interface}")
        if mode=="access":
            return f"switchport access vlan {vlan_or_allowed}" in output and "switchport mode access" in output
        if mode=="trunk":
            return f"switchport trunk allowed vlan {vlan_or_allowed}" in output and "switchport mode trunk" in output
def check_interface(conn,r_interface):
    try:
        data=conn.send_command("show ip interface brief", use_genie=True)
        if r_interface in data['interface']:
            return data['interface'][r_interface]['status']=="up"
        return False
    except Exception:
        output=conn.send_command(f"show interface {r_interface}")
        return "is up, line protocol is up" in output.lower()
def check_roas(device_ip,auth,ip,new_int):
    url = f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/interface/GigabitEthernet={new_int}"
    headers={"Accept":"application/yang-data+json"}
    response=requests.get(url,auth=auth,headers=headers,verify=False,timeout=5)
    try:
        if response.status_code==404:
            return False
        if response.status_code==200:
            data=response.json()
            actual_ip=data['Cisco-IOS-XE-native:GigabitEthernet']['ip']['address']['primary']['address']
            return str(actual_ip)==str(ip)
        return False
    except Exception:
        return False
def check_ospf(device_ip,auth,):
    url=f"https://{device_ip}/restconf/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data"
    headers={"Accept:application/yang-data+json"}
    try:
        response=requests.get(url,auth=auth,headers=headers,verify=False,timeout=30)
        if response in [200,201,204]:
            data=response.json()


###################################CONFIGURE FUNCTIONS################################################
def configure_vlans(conn,vlan_data,log):
    vlan_id,name=vlan_data['vlan_id'],vlan_data['name']
    if check_vlans(conn,vlan_id,name):
        log.info(f"VLAN {vlan_id} for {name} already configured.")
        return False
    template=template_env.get_template('vlans.j2')
    commands=template.render(vlan_id=vlan_id,name=name)
    if DRY_RUN:
        log.info(f"[DRY-RUN] Would configure VLAN {vlan_id} for {name}....")
        return True
    log.info(f"**** Configuring VLAN {vlan_id} for {name} ****")
    conn.send_config_set(commands.splitlines())
    log.info(f"VLAN {vlan_id} for {name} successfully configured.")
    return True
def configure_access(conn,access_data,log):
    access__interface,access_vlan=access_data['access_interface'],access_data['access_vlan']
    if check_switchport(conn,access__interface,"access",access_vlan):
        log.info(f"Access Port {access__interface} for VLAN {access_vlan} already configured.")
        return False
    template=template_env.get_template('access_port.j2')
    commands=template.render(access__interface=access__interface,access_vlan=access_vlan)
    if DRY_RUN:
        log.info(f"[DRY-RUN] Would configure Access Port {access__interface} for VLAN {access_vlan}...")
        return True
    log.info(f"**** Configuring Access Port {access__interface} for VLAN {access_vlan}")
    conn.send_config_set(commands.splitlines())
    log.info(f"Access Port {access__interface} for VLAN {access_vlan} successfully configured.")
    return True
def configure_trunks(conn,trunk_data,log):
    trunk_interface,allowed_vlans=trunk_data['trunk_interface'],trunk_data['allowed_vlans']
    if check_switchport(conn,trunk_interface,"trunk",allowed_vlans):
        log.info(f"Trunk Port for Interface {trunk_interface} already configured. Allowed VLANs: {allowed_vlans}")
        return False
    template=template_env.get_template('trunk.j2')
    commands=template.render(trunk_interface=trunk_interface,allowed_vlans=allowed_vlans)
    if DRY_RUN:
        log.info(f"[DRY-RUN] Would Configure Trunk Port for Interface {trunk_interface}....")
        return True
    log.info(f"**** Configuring Trunk Port for Interface {trunk_interface}.")
    conn.send_config_set(commands.splitlines())
    log.info(f"Trunk Port for Interface {trunk_interface} successfully configured. Allowed VLANs: {allowed_vlans}")
    return True
def configure_interface(conn,interface_data,log):
    r_interface=interface_data['r_interface']
    if check_interface(conn,r_interface):
        log.info(f"Interface {r_interface} status already UP!")
        return False
    template=template_env.get_template('interface.j2')
    commands=template.render(r_interface=r_interface)
    if DRY_RUN:
        log.info(f"[DRY-RUN] Would Configure Interface {r_interface} status to UP!")
        return True
    log.info(f"**** Configuring Interface {r_interface} status to UP! ****")
    conn.send_config_set(commands.splitlines())
    return True
def configure_roas_restconf(device_ip,roas_data,auth,log):
    router_interface,router_vlan,ip,mask=roas_data['router_interface'],roas_data['router_vlan'],roas_data['ip'],roas_data['mask']
    new_number=clean_interface_name(router_interface)
    new_int=f"{new_number}.{router_vlan}"
    url=f"https://{device_ip}/restconf/data/Cisco-IOS-XE-native:native/interface/GigabitEthernet={new_int}"
    headers={
        "Accept":"application/yang-data+json",
        "Content-Type":"application/yang-data+json"
    }
    if check_roas(device_ip,auth,ip,new_int):
        log.info(f"ROAS for VLAN {router_vlan} already configured. IP: {ip}")
        return False
    if DRY_RUN:
        log.info(f"[DRY-RUN] Would configure ROAS for VLAN {router_vlan}...")
        return True
    template=template_env.get_template('restconf.j2')
    commands=template.render(new_interface=new_int,router_vlan=int(router_vlan),ip=ip,mask=mask)
    response=requests.put(url,auth=auth,headers=headers,data=commands,verify=False)
    if response.status_code in [201,204]:
        log.info(f"**** ROAS for VLAN {router_vlan} successfully configured via RESTCONF ****")
        return True
    else:
        log.error(f"x FAILED to configrue ROAS for VLAN {router_vlan}")
        log.error(f"Router says: {response.text}") # <--- WHAT DOES THIS PRINT?
        return False
################################### LIVE SESSION ################################################
def main_process(device,config_data):
    host_ip=device['host']
    device_copy=device.copy()
    device_name=device_copy.pop('name', host_ip)
    adapter=logging.LoggerAdapter(logger,{'dev':device_name})
    platform=device['device_type']
    try:
        if platform=='cisco-ios-xe':
            adapter.info(f"---- REST CONF CONFIG for Device at {host_ip} ----")
            changed=False
            auth=(device['username'],device['password'])
            for roas in [roas for roas in config_data['roass'] if roas['device']==host_ip]:
                if configure_roas_restconf(host_ip,roas,auth,adapter):
                    changed = True
            if not changed:
                adapter.info(f"Device at {host_ip} already in compliance.")
        else:
            adapter.info("---- Starting Netmiko Configurations ----")
            with ConnectHandler(**device_copy) as conn:
                conn.enable()
                changed = False
                for vlan in [vlan for vlan in config_data['vlans'] if vlan['device'] == host_ip]:
                    if configure_vlans(conn, vlan, adapter):
                        changed = True
                for access in [access for access in config_data['access_ports'] if access['device'] == host_ip]:
                    if configure_access(conn, access, adapter):
                        changed = True
                for trunk in [trunk for trunk in config_data['trunks'] if trunk['device'] == host_ip]:
                    if configure_trunks(conn, trunk, adapter):
                        changed= True
                for interface in [interface for interface in config_data['interfaces'] if
                                  interface['device'] == host_ip]:
                    if configure_interface(conn, interface, adapter):
                        changed = True
                if changed:
                    if DRY_RUN:
                        adapter.info("[DRY-RUN] Changes have been detected. See configurations above.")
                    else:
                        adapter.info(f"Changes have been made to Device at {host_ip}. See configurations above.")
                else:
                    adapter.info(f"Device at {host_ip} is already in compliance.")
    except Exception as e:
        adapter.error(f"x ERROR found at {host_ip}:{e}")
def main():
    main_log=logging.LoggerAdapter(logger,{'dev':'MAIN'})
    main_log.info("==== STARTING HYBRID(RESTCONF+NETMIKO) CONFIGS ====")

    try:
        inventory,config_data=get_netbox()
        main_log.info(f"NET BOX SYNC SUCCESSFUL. ({len(inventory)} Devices Found)")
    except Exception as e:
        main_log.info(f"x NETBOX SYNC FAILED: {e}")
        return

    with ThreadPoolExecutor(max_workers=15) as execution:
        for device in inventory:
            execution.submit(main_process,device,config_data)
if __name__=="__main__":
    main()
    end_log = logging.LoggerAdapter(logger, {'dev': 'FINAL'})
    end_log.info("----- SCRIPT SUCCESSFULLY FINISHED -----")



