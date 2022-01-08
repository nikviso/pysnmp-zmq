#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    getCmd(SnmpEngine(),
           CommunityData('dude', mpModel=0),
           UdpTransportTarget(('192.168.205.220', 161)),
           ContextData(),
           ObjectType(ObjectIdentity('1.3.6.1.2.1.17.1.4.1.2.28')))
)
if errorIndication:
    print(errorIndication)
elif errorStatus:
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(' = '.join([x.prettyPrint() for x in varBind]))


for errorIndication, errorStatus, \
           errorIndex, varBinds in bulkCmd(SnmpEngine(),
           CommunityData('dude', mpModel=1),
           UdpTransportTarget(('192.168.205.220', 161)),
           ContextData(),
           0, 50,
           ObjectType(ObjectIdentity('1.3.6.1.2.1.17.1.4.1.2')), lookupMib=False, lexicographicMode=False):

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
            

for oid in ('27','52'):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData('dude', mpModel=1),
               UdpTransportTarget(('192.168.205.220', 161)),
               ContextData(),
               ObjectType(ObjectIdentity('1.3.6.1.2.1.17.1.4.1.2.'+oid)))
    )
    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))    

""" 
""" 
from pysnmp.entity.rfc3413.oneliner import cmdgen  

errorIndication, errorStatus, errorIndex, \
varBindTable = cmdgen.CommandGenerator().bulkCmd(  
            cmdgen.CommunityData('dude'),  
            cmdgen.UdpTransportTarget(('192.168.205.220', 161)),  
            0, 
            25, 
            ('1.3.6.1.2.1.17.1.4.1.2'),
        )

if errorIndication:
   print(errorIndication)
else:
    if errorStatus:
        print('%s at %s\n' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
            ))
    else:
        for varBindTableRow in varBindTable:
            for name, val in varBindTableRow:
                print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
"""               

from puresnmp import bulkwalk
ip = '192.168.205.220'
community = 'dude@777'
oids = [
    '1.3.6.1.2.1.17.1.4.1.2',
]

result = bulkwalk(ip, community, oids)
for row in result:
    print(row)