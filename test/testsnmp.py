#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pysnmp.hlapi import *
import json
import sys 


def dlink_mac_table(host, snmp_community, oid, exclude_interfaces = []):
    """
    Get MAC table D-Link
    """

    total_out = []
    
    for errorIndication, errorStatus, \
        errorIndex, varBinds in bulkCmd(
            SnmpEngine(),
            CommunityData(snmp_community),
            UdpTransportTarget((host, 161)),
            ContextData(),
            0, 50,  # GETBULK specific: request up to 50 OIDs in a single response
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False, lexicographicMode=False):

        if errorIndication:
            return {"error": errorIndication}
        elif errorStatus:
            return {"error": ('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex)-1][0] or '?'))}
        else:
            list_mac_out = []
            for varBind in varBinds:
                list_mac_temp = [x.prettyPrint().replace('oid', '').split('.') for x in varBind]
                if list_mac_temp[1][0] not in exclude_interfaces:
                    mac = hex(int(list_mac_temp[0][1])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][2])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][3])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][4])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][5])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][6])).split('x')[1].zfill(2)
                    list_mac_out.append(list_mac_temp[0][0])
                    list_mac_out.append(mac)
                    list_mac_out.append(list_mac_temp[1][0])
                    total_out.append(list_mac_out)                
                    # print(json.dumps(list_mac_out))
    return(total_out)     


def cisco_vlan_id(host, snmp_community, oid):
    """
    Get VLAN's id
    """
    
    total_out = []
    
    for errorIndication, errorStatus, \
        errorIndex, varBinds in bulkCmd(
            SnmpEngine(),
            CommunityData(snmp_community),
            UdpTransportTarget((host, 161)),
            ContextData(),
            0, 50,  # GETBULK specific: request up to 50 OIDs in a single response
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False, lexicographicMode=False):

        if errorIndication:
            return {"error": errorIndication}
        elif errorStatus:
            return {"error": ('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex)-1][0] or '?'))}
        else:
            for varBind in varBinds:
                list_vlan_id = ([x.prettyPrint().replace(oid + '.1.', '') for x in varBind])
                total_out.append(list_vlan_id[0])
                # print(list_vlan_id[0])
    return(total_out)
                
def cisco_mac_per_vlan(host, snmp_community, oid, vlan_id = '1'):
    """
    Get MAC's per VLAN's
    """
    
    total_out = []
    
    for errorIndication, errorStatus, \
        errorIndex, varBinds in bulkCmd(
            SnmpEngine(),
            CommunityData(snmp_community + '@' + vlan_id),
            UdpTransportTarget((host, 161)),
            ContextData(),
            0, 50,  # GETBULK specific: request up to 50 OIDs in a single response
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False, lexicographicMode=False):

        if errorIndication:
            return {"error": errorIndication}
        elif errorStatus:
            return {"error": ('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex)-1][0] or '?'))}
        else:
            mac_address_table = []
            for varBind in varBinds:
                mac_address_table = ([x.prettyPrint().replace('0x','') for x in varBind])
                i = 0
                mac = ''
                for ch in mac_address_table[1]:
                    if i == 2:
                        mac = mac + ':'
                        i = 0
                    mac = mac + ch
                    i+=1
                total_out.append([vlan_id,mac])    
                # print([vlan_id,mac])
    return(total_out)            


def cisco_mac_per_interface(host, snmp_community, oid, vlan_id = '1', exclude_interfaces = []):
    """
    Get bridge port number & MAC address
    """
    
    total_out = []
    
    for errorIndication, errorStatus, \
        errorIndex, varBinds in bulkCmd(
            SnmpEngine(),
            CommunityData(snmp_community + '@' + vlan_id),
            UdpTransportTarget((host, 161)),
            ContextData(),
            0, 50,  # GETBULK specific: request up to 50 OIDs in a single response
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False, lexicographicMode=False):

        if errorIndication:
            return {"error": errorIndication}
        elif errorStatus:
            return {"error": ('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex)-1][0] or '?'))}
        else:
            list_mac_out = []
            for varBind in varBinds:
                list_mac_temp = ([x.prettyPrint().replace(oid + '.', '').split('.') for x in varBind])
                
                if list_mac_temp[1][0] not in exclude_interfaces:
                    mac = hex(int(list_mac_temp[0][0])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][1])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][2])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][3])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][4])).split('x')[1].zfill(2)+':'+\
                        hex(int(list_mac_temp[0][5])).split('x')[1].zfill(2)
                    # list_mac_out.append(vlan_id)    
                    list_mac_out.append(mac)
                    list_mac_out.append(list_mac_temp[1][0])
                    total_out.append(list_mac_out)                
                    # print(list_mac_out)
    return(total_out)

    
def cisco_ifname_ifindex(host, snmp_community, oid, vlan_id = '1'):
    """
    Get mapping the bridge port to the ifIndex per VLAN's
    or
    Get interface name by ifIndex
    """
    
    total_out = []
    
    for errorIndication, errorStatus, \
        errorIndex, varBinds in bulkCmd(
            SnmpEngine(),
            CommunityData(snmp_community + '@' + vlan_id),
            UdpTransportTarget((host, 161)),
            ContextData(),
            0, 50,  # GETBULK specific: request up to 50 OIDs in a single response
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False, lexicographicMode=False):

        if errorIndication:
            return {"error": errorIndication}
        elif errorStatus:
            return {"error": ('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex)-1][0] or '?'))}
        else:
            for varBind in varBinds:
                list_out = ([x.prettyPrint().replace(oid + '.', '') for x in varBind])
                total_out.append(list_out)
                # print(list_out)
    return(total_out)

                
def cisco_interface_name():
    """
    Get interface name
    """
    
    for errorIndication, errorStatus, \
        errorIndex, varBinds in bulkCmd(
            SnmpEngine(),
            CommunityData(snmp_community),
            UdpTransportTarget((host, 161)),
            ContextData(),
            0, 50,  # GETBULK specific: request up to 50 OIDs in a single response
            ObjectType(ObjectIdentity(if_name)),
            lookupMib=False, lexicographicMode=False):

        if errorIndication:
            return {"error": errorIndication}
        elif errorStatus:
            return {"error": ('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex)-1][0] or '?'))}
        else:
            list_ifname_out = []
            for varBind in varBinds:
                list_ifname_out = ([x.prettyPrint().replace(if_name+'.', '') for x in varBind])
                print(list_ifname_out)


def main():
    #host = '192.168.205.184'                            # CISCO
    host = '192.168.205.221'                           # D-Link
    snmp_community = 'dude'
    oid_dlink = '1.3.6.1.2.1.17.7.1.2.2.1.2'            # D-Link oid
    oid_vlan_id = '1.3.6.1.4.1.9.9.46.1.3.1.1.2'
    oid_mac_address_table = '1.3.6.1.2.1.17.4.3.1.1'    # CISCO MAC address table per VLAN. community@vlan_id
    oid_bridge_port_number = '1.3.6.1.2.1.17.4.3.1.2'   # CISCO Bridge port number per VLAN. community@vlan_id
    oid_if_name = '1.3.6.1.2.1.31.1.1.1.1'              # CISCO
    oid_if_index = '1.3.6.1.2.1.17.1.4.1.2'             # CISCO Map the bridge port to the ifIndex per VLAN. community@vlan_id
    exclude_interfaces = ['25','26','0']
    total_out = []
    
    # D-Link
    return(dlink_mac_table(host, snmp_community, oid_dlink, exclude_interfaces))
    
    # CISCO
    # return{'error':'test-error'}    
    """
    dic_ifname = dict(cisco_ifname_ifindex(host, snmp_community, oid_if_name))  # Get interface name by ifIndex
    if dic_ifname.get('error'):
        return(dic_ifname)

    list_vlan_id = cisco_vlan_id(host, snmp_community, oid_vlan_id)
    if 'error' in list_vlan_id:
        return(list_vlan_id)
    
    for vlan_id in list_vlan_id:
        list_mac_per_interface = cisco_mac_per_interface(host, snmp_community, oid_bridge_port_number, vlan_id)
        if 'error' in list_mac_per_interface:
            return(list_mac_per_interface)
 
        if list_mac_per_interface:
            list_ifindex = dict(cisco_ifname_ifindex(host, snmp_community, oid_if_index, vlan_id))  # Get mapping the bridge port to the ifIndex per VLAN's
            if list_ifindex.get('error'):
                return(list_ifindex)
            for mac,interface in list_mac_per_interface:
                total_out.append([vlan_id,mac,dic_ifname[list_ifindex[interface]]])        
    return(total_out)
    """
                        
if __name__ == "__main__":

    # print(cisco_mac_per_vlan(host, snmp_community, oid_mac_address_table, vlan_id))
    print(main())
    