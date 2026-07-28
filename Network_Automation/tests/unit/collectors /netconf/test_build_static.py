from src.collectors.netconf.builders import build_static
import pytest

def test_build_static_valid(static_netconf): 
    result = build_static(static_netconf)

    assert {
             "AD": 1, 
             "network_address": "10.10.10.0" ,
             "mask": "255.255.255.0",
             "next_hop": "192.168.1.2",
             "exit_interface": ,
             "name": None, 
           } in result
    assert {
             "AD": 5, 
             "network_address": "20.20.20.0" ,
             "mask": "255.255.255.0",
             "next_hop": "192.168.1.2",
             "exit_interface": ,
             "name": None, 
           } in result
    assert {
             "AD": 1, 
             "network_address": "40.40.40.0" ,
             "mask": "255.255.255.0",
             "next_hop": None,
             "exit_interface": "GigabitEthernet1",
             "name": None, 
           } in result
    assert {
             "AD": 1, 
             "network_address": "40.40.40.0" ,
             "mask": "255.255.255.0",
             "next_hop": None,
             "exit_interface": "GigabitEthernet1",
             "name": None, 
           } in result