import json
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen


class Request(object):

    def get_if_data(self, json_dict, config_params):
        """
        Gets description, name, operation status and administrative status of interfaces
        """
        
        try:
            for oids in config_params['oid_list_interface']:
                if oids[0] == json_dict['oid']: 
                    break

            host = json_dict['host']
            snmp_ro_comm = json_dict['community']

            auth = cmdgen.CommunityData(snmp_ro_comm)
            cmdGen = cmdgen.CommandGenerator()

            errorIndication, errorStatus, errorIndex, varTable = cmdGen.nextCmd(
                auth,
                cmdgen.UdpTransportTarget((host, 161)),
                *[cmdgen.MibVariable(oid) for oid in json.loads(oids[1])],
                lookupMib=False,
            )

            if errorIndication:
                return {"error": errorIndication}
            elif errorStatus:
                return {"error": ('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'))}

            oid_list = []
            total_oid_list = []

            for varBinds in varTable:
                for oid, val in varBinds:
                    oid_list.append(val.prettyPrint()) 
                total_oid_list.append(oid_list)
                oid_list = []
                    
            return total_oid_list
        except Exception as e:
            return {"error": str(e)}


    def get_mac_table_dlink(self, json_dict, config_params):
        """
        Gets the MAC address table of the D-LINK switch
        """
        
        try:    
            host = json_dict['host']
            snmp_ro_comm = json_dict['community']
            # exclude_interfaces = ['25','26','0']
            if 'exclude_interfaces' in json_dict:
                exclude_interfaces = json_dict['exclude_interfaces']
            else:    
                exclude_interfaces = []
            oid = config_params['oids_mac_table']['dlink_dot1qtpfdbport']
            total_mac_out = []
            
            for errorIndication, errorStatus, \
                errorIndex, varBinds in bulkCmd(
                    SnmpEngine(),
                    CommunityData(snmp_ro_comm),
                    UdpTransportTarget((host, 161)),
                    ContextData(),
                    0, 50,  # GETBULK specific: request up to 50 OIDs in a single response
                    ObjectType(ObjectIdentity(oid)),
                    lookupMib=False, lexicographicMode=False):

                if errorIndication:
                    return(errorIndication)
                elif errorStatus:
                    return('%s at %s' % (errorStatus.prettyPrint(),
                                        errorIndex and varBinds[int(errorIndex)-1][0] or '?'))

                else:
                    list_mac_out = []
                    for varBind in varBinds:
                        list_mac_temp = [x.prettyPrint().replace(oid + '.', '').split('.') for x in varBind]
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
                            total_mac_out.append(list_mac_out)                

            return(total_mac_out)      
        except Exception as e:
            return {"error": str(e)}


    def get_mac_table_cisco(self, json_dict, config_params):
        """
        Gets the MAC address table of the CISCO switch
        """
        
        try:
            host = json_dict['host']
            snmp_ro_comm = json_dict['community']
            oid_if_name = config_params['oids_mac_table']['ifname']
            oid_vlan_id = config_params['oids_mac_table']['vtpvlanstate']
            oid_bridge_port_number = config_params['oids_mac_table']['cisco_dot1dtpfdbport']
            oid_if_index = config_params['oids_mac_table']['dot1dbaseportifindex']
            total_out = []
            
            dic_ifname = dict(self.cisco_ifname_ifindex(host, snmp_ro_comm, oid_if_name))  # Get interface name by ifIndex,ifname
            if dic_ifname.get('error'):
                return(dic_ifname)

            list_vlan_id = self.cisco_vlan_id(host, snmp_ro_comm, oid_vlan_id)
            if 'error' in list_vlan_id:
                return(list_vlan_id)
            
            for vlan_id in list_vlan_id:
                list_mac_per_interface = self.cisco_mac_per_interface(host, snmp_ro_comm, oid_bridge_port_number, vlan_id)
                if 'error' in list_mac_per_interface:
                    return(list_mac_per_interface)
         
                if list_mac_per_interface:
                    list_ifindex = dict(self.cisco_ifname_ifindex(host, snmp_ro_comm, oid_if_index, vlan_id))  # Get mapping the bridge port to the ifIndex per VLAN's
                    if list_ifindex.get('error'):
                        return(list_ifindex)
                    for mac, interface in list_mac_per_interface:
                        total_out.append([vlan_id,mac,dic_ifname[list_ifindex[interface]]])        
            return(total_out)
        except Exception as e:
            return {"error": str(e)}


    def get_mac_table(self, json_dict, config_params):
        """
        Gets the MAC address table
        """    
    
        try:
            oid_system_description = config_params['oids_mac_table']['sysdescr']
            host = json_dict['host']
            snmp_ro_comm = json_dict['community']

            cmdGen = cmdgen.CommandGenerator()

            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                 cmdgen.CommunityData(snmp_ro_comm),
                 cmdgen.UdpTransportTarget((host, 161)),
                 oid_system_description,
                 lookupNames=True, lookupValues=True
            )
            
            if errorIndication:
                return(errorIndication)
            elif errorStatus:
                return('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'))
            else:
                for varBind in varBinds:
                    if 'cisco' in [x.prettyPrint() for x in varBind][1].lower():
                        return (self.get_mac_table_cisco(json_dict, config_params))
                    else:
                        return (self.get_mac_table_dlink(json_dict, config_params))
                        
        except Exception as e:
            return {"error": str(e)}        


    def get_ifnterface_map_table(self, json_dict, config_params):
        """
        Gets interfaces and bridge indexes mapping. Only for COSCO
        """
    
        try:
            host = json_dict['host']
            snmp_ro_comm = json_dict['community']
            oid_if_name = config_params['oids_mac_table']['ifname']
            oid_if_index = config_params['oids_mac_table']['dot1dbaseportifindex']
            oid_vlan_id = config_params['oids_mac_table']['vtpvlanstate']
            total_out = []
            check_dict = {}
           
            dic_ifname = dict(self.cisco_ifname_ifindex(host, snmp_ro_comm, oid_if_name))  # Get interface name by ifIndex,ifname
            if dic_ifname.get('error'):
                return(dic_ifname)

            list_vlan_id = self.cisco_vlan_id(host, snmp_ro_comm, oid_vlan_id)
            if 'error' in list_vlan_id:
                return(list_vlan_id)
            
            for vlan_id in list_vlan_id:
                list_ifindex = dict(self.cisco_ifname_ifindex(host, snmp_ro_comm, oid_if_index, vlan_id))  # Get mapping the bridge port to the ifIndex per VLAN's
                if list_ifindex.get('error'):
                    return(list_ifindex)
                    
                if bool(list_ifindex):
                    for brindex, ifindex in list_ifindex.items():
                        if not check_dict.get(brindex):
                            check_dict[brindex] = ifindex
                            total_out.append([int(brindex), dic_ifname[ifindex]])    
            check_dict.clear()    

            return(sorted(total_out, key=lambda x:x[0]))
        except Exception as e:
            return {"error": str(e)}


    @staticmethod
    def cisco_vlan_id(host, snmp_ro_comm, oid):
        """
        Get VLAN's id
        """
        
        total_out = []
        
        try:
            for errorIndication, errorStatus, \
                errorIndex, varBinds in bulkCmd(
                    SnmpEngine(),
                    CommunityData(snmp_ro_comm),
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

            return(total_out)
        except Exception as e:
            return {"error": str(e)}
            
            
    @staticmethod                   
    def cisco_mac_per_vlan(host, snmp_ro_comm, oid, vlan_id = '1'):
        """
        Get MAC addresses per VLAN
        """
        
        total_out = []
        
        try:
            for errorIndication, errorStatus, \
                errorIndex, varBinds in bulkCmd(
                    SnmpEngine(),
                    CommunityData(snmp_ro_comm + '@' + vlan_id),
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

            return(total_out)            
        except Exception as e:
            return {"error": str(e)}
            
            
    @staticmethod
    def cisco_mac_per_interface(host, snmp_ro_comm, oid, vlan_id = '1', exclude_interfaces = []):
        """
        Get bridge port number & MAC address
        """
        
        total_out = []
        
        try:
            for errorIndication, errorStatus, \
                errorIndex, varBinds in bulkCmd(
                    SnmpEngine(),
                    CommunityData(snmp_ro_comm + '@' + vlan_id),
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
                            list_mac_out.append(mac)
                            list_mac_out.append(list_mac_temp[1][0])
                            total_out.append(list_mac_out)                

            return(total_out)
        except Exception as e:
            return {"error": str(e)}


    @staticmethod        
    def cisco_ifname_ifindex(host, snmp_ro_comm, oid, vlan_id = '1'):
        """
        Get mapping the bridge port to the ifIndex per VLAN's
        or
        Get interface name by ifIndex
        """
        
        total_out = []
        
        try:
            for errorIndication, errorStatus, \
                errorIndex, varBinds in bulkCmd(
                    SnmpEngine(),
                    CommunityData(snmp_ro_comm + '@' + vlan_id),
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
  
            return(total_out)
        except Exception as e:
            return {"error": str(e)}
            