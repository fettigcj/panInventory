#!/usr/bin/env python

################################################################################
# script:	PanInventory.py
# by:		Christopher Fettig, Palo Alto Networks
# rqmts:	Panorama IP Address, [username, password]
#
# © 2020 Palo Alto Networks, Inc.  All rights reserved.
# Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
#
################################################################################
"""
Changelog 2023-10-31:
    Create file.

Goals:
    Incorporate multi-vsys handling for UID group-mapping state <ALL> logic
    Investigate uidGroupMappingService > show user group-mapping-service status
    uidServerMonitor 'stats' xmlData = panCore.xmlToLXML(fw_obj.op('show user server-monitor statistics'))
    uidServerMonitor 'states' xmlData = panCore.xmlToLXML(fw_obj.op('<show><user><server-monitor><state>all</state></server-monitor></user></show>', cmd_xml=False))
"""
#Import custom library modules
from pancore import panCore, panExcelStyles
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse, re

def kvStringUserIdAgentState(lines):
    extrafield = 1
    messagesStateFlag = False
    dictionary = {}
    for line in lines.splitlines():
        #print(f"Processing line: {line}")
        if len(line) <= 0:
            #print('    1> Short line. Skipping')
            continue
        elif line.lower().startswith('agent: '):
            #print('    2> New agent detected in line. Recording:')
            #print(line[3])
            messagesStateFlag = False
            line = line.replace('vsys: vsys', 'vsys:vsys').split()
            agentName = line[1]
            dictionary[agentName] = {'host':line[3]}
        elif line.split()[0].lower() == 'status' and line.split()[1] == ":":
            #print(f"    3> Processing status line for agent: {agentName}")
            i = line.index(":")+1
            dictionary[agentName]['status'] = "".join(line[i:].split())
        elif 'messages state:' in line.lower():
                #print('    4> message state flag tripped.')
                messagesStateFlag = True
                continue
        else:
            if ":" not in line:
                #print(f"     5stupid corner case.")
                dictionary[agentName][f"ExtraField_{extrafield}"] = line
                extrafield += 1
                continue
            line = " ".join(line.replace(" : ", ":").split()).split(":")
            if messagesStateFlag:
                #print(f"     5a> Recording agent data to dictionary: MessagesState_{line[0]} > {line[1]}")
                if "\t  " not in line:
                    dictionary[agentName][line[0]] = line[1]
                else:
                    dictionary[agentName][f'MessagesState_{line[0]}'] = line[1]
            else:
                #print(f"     5b> Recording agent data to dictionary: {line[0]} > {line[1]}")
                dictionary[agentName][line[0]] = line[1]
    return dictionary

parser = argparse.ArgumentParser(
    prog="adHoc",
    description="Development sandbox for Ad Hoc scripts.")
    #epilog="Text")

parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='adHoc.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='adHoc.xlsx')
args = parser.parse_known_args()
panCore.startLogging(args[0].logfile)
panCore.configStart(headless=args[0].headless, configStorage=args[0].conffile)
if hasattr(panCore, 'panUser'):
    pano_obj, deviceGroups, firewalls = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, 'panKey'):
    pano_obj, deviceGroups, firewalls = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    panCore.logging.critical("Found neither username/password nor API key. Exiting.")
    sys.exit()

preambleHeaders = ['FW_Serial', 'FW_Hostname', 'FW_MgmtIP', 'AgentName']
uidAgents = {
    'stats': {'headers': preambleHeaders, 'firewalls': {}},
    'states': {'headers': preambleHeaders, 'firewalls': {}}
    }
uidService = {'headers': preambleHeaders, 'firewalls': {}}
dataRedistAgents = {
    'stats': {'headers': preambleHeaders, 'firewalls': {}},
    'states': {'headers': preambleHeaders, 'firewalls': {}}
    }
dataRedistServers = {'headers': preambleHeaders + ['svrNumber'], 'firewalls': {}}
uidServerMonitor = {
    'stats': {'headers': preambleHeaders, 'firewalls': {}},
    'states': {'headers': preambleHeaders, 'firewalls': {}}
    }
uidGroupMapping = {
    'stats': {'headers': preambleHeaders, 'firewalls': {}},
    'states': {'headers': preambleHeaders, 'firewalls': {}},
    'configs': {'headers': preambleHeaders, 'firewalls': {}}
    }
uidGroupMappingService = {'headers': preambleHeaders, 'firewalls': {}}
fwCount = len(firewalls)
fwNum = 1
#######################################################################################
################## Fetch Firewall Inventory from Panorama #############################
panCore.logging.info("Gathering Panorama inventory data")
xmlData = panCore.xmlToLXML(pano_obj.op(cmd="show devices all"))
panCore.devData = {}
panCore.headers = []
for device in xmlData.xpath('//devices/entry'):
    panCore.devData[device.get('name')] = {}
    for child in device.getchildren():
        if len(child):
            panCore.iterator(child, device.get('name'))
        else:
            panCore.devData[device.get('name')][child.tag] = child.text
            if child.tag not in panCore.headers:
                panCore.headers.extend([child.tag])
panoInventory = panCore.devData
panCore.logging.info("Finished\n")

auditStartTime = datetime.datetime.now(datetime.timezone.utc)
panCore.logging.info(f"Starting audit at {auditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
for fw_obj in firewalls:
    startTime = datetime.datetime.now(datetime.timezone.utc)
    try:
        fw_serial = fw_obj.serial
        if not fw_obj.state.connected:
            panCore.logging.info(f"--> Device Offline: {fw_serial} ({fwNum}/{fwCount}) at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
            fwNum += 1
            continue
        panCore.logging.info(f"--> Gathering user ID details for device: {fw_serial} ({fwNum}/{fwCount}) at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
        fwNum += 1
        deviceData = fw_obj.show_system_info()
        fwName = deviceData['system']['hostname']
        fw_sysInfo = fw_obj.show_system_info()['system']
        swVersion = fw_sysInfo['sw-version'].split('.')
        if int(swVersion[0]) >= 10:
            panCore.logging.info(f"     {swVersion} >= PAN-OS version 10.0.0 including 'Data Redistribution' logic.")
            xmlData = panCore.xmlToLXML(fw_obj.op('show redistribution service status'))
            if len(xmlData.xpath('/response/result/entry')):
                i = 1
                dataRedistServers['firewalls'][fw_serial] = {}
                for service in xmlData.xpath('/response/result/entry'):
                    panCore.devData = {'temp': {}}
                    panCore.headers = dataRedistServers['headers']
                    dataRedistServers['firewalls'][fw_serial][i] = {}
                    for child in service.getchildren():
                        panCore.iterator(child,'temp')
                        dataRedistServers['firewalls'][fw_serial][i] = panCore.devData['temp']
                    dataRedistServers['headers'] = panCore.headers
                    i += 1
            else:
                dataRedistServers['firewalls'][fw_serial] = {1: {'status': 'NOT CONFIGURED'}}
            xmlData = panCore.xmlToLXML(fw_obj.op('<show><redistribution><agent><state>all</state></agent></redistribution></show>',cmd_xml=False))
            if len(xmlData.xpath('/response/result/entry')):
                dataRedistAgents['states']['firewalls'][fw_serial] = {}
                for agent in xmlData.xpath('/response/result/entry'):
                    panCore.devData = {'temp': {}}
                    panCore.headers = dataRedistAgents['states']['headers']
                    for child in agent.getchildren():
                        panCore.iterator(child, 'temp')
                        dataRedistAgents['states']['firewalls'][fw_serial][agent.attrib['name']] = panCore.devData['temp']
                    dataRedistAgents['states']['headers'] = panCore.headers
            else:
                dataRedistAgents['states']['firewalls'][fw_serial] = {'NOT CONFIGURED': {}}
            xmlData = panCore.xmlToLXML(fw_obj.op('show redistribution agent statistics'))
            if len(xmlData.xpath('/response/result/entry')):
                dataRedistAgents['stats']['firewalls'][fw_serial] = {}
                for agent in xmlData.xpath('/response/result/entry'):
                    panCore.devData = {'temp': {}}
                    panCore.headers = dataRedistAgents['stats']['headers']
                    for child in agent.getchildren():
                        panCore.iterator(child, 'temp')
                        dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']] = panCore.devData['temp']
                    #print(f"Trying to check if 'usage' in data redist agents statistics table for firewall {fw_serial}")
                    if 'usage' in dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']].keys():
                        usageCode = dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage']
                        del dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage']
                        dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usageCode'] = usageCode
                        #Break out usage types from the "usage code" field
                        dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_UserMapping'] = (False, True)['I' in usageCode]
                        dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_IP-Tag'] = (False, True)['T' in usageCode]
                        dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_UserTag'] = (False, True)['U' in usageCode]
                        dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_HIP-Reports'] = (False, True)['H' in usageCode]
                        dataRedistAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_Quarantine'] = (False, True)['Q' in usageCode]
                    dataRedistAgents['stats']['headers'] = panCore.headers
            else:
                dataRedistAgents['stats']['firewalls'][fw_serial] = {'NOT CONFIGURED': {}}
        else:
            panCore.logging.info(f"{swVersion} <= PAN-OS version 10.0. Restricting to 'User-ID agents' logic.")
        # Finished processing "Data Redistribution" elements for PAN-OS >= 10.0
        # Put any "9.x ONLY" logic here.
        # Leaving remaining tests outside 'else' block in case someone configures legacy methodology on >= 10.0 PAN-OS
        xmlData = panCore.xmlToLXML(fw_obj.op('<show><user><user-id-agent><state>all</state></user-id-agent></user></show>', cmd_xml=False))
        if len(xmlData.xpath('/response/result')[0].text):
            respText = xmlData.xpath('/response/result')[0].text
            if 'no user-id agent agents' in respText.lower():
                uidAgents['states']['firewalls'][fw_serial] = {'NOT CONFIGURED': {}}
            else:
                uidAgents['states']['firewalls'][fw_serial] = kvStringUserIdAgentState(respText)
                for agent in uidAgents['states']['firewalls'][fw_serial].keys():
                    for key in uidAgents['states']['firewalls'][fw_serial][agent].keys():
                        if key not in uidAgents['states']['headers']:
                            uidAgents['states']['headers'].append(key)
        xmlData = panCore.xmlToLXML(fw_obj.op('show user user-id-agent statistics'))
        if len(xmlData.xpath('/response/result/entry')):
            uidAgents['stats']['firewalls'][fw_serial] = {}
            for agent in xmlData.xpath('/response/result/entry'):
                panCore.devData = {'temp': {}}
                panCore.headers = uidAgents['stats']['headers']
                for child in agent.getchildren():
                    panCore.iterator(child, 'temp')
                    uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']] = panCore.devData['temp']
                #print(f"Trying to check if 'usage' in UID agent statistics table for firewall {fw_serial} under agent {agent.attrib['name']}")
                #for key in uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']].keys():
                    #print(f"Key: {key}")
                if 'usage' in uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']].keys():
                    #print(f"Found 'usage' code for firewall {fw_serial}! Continuing.")
                    usageCode = uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage']
                    del uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage']
                    uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usageCode'] = usageCode
                    #Break out usage types from the 'usage code' field
                    uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_LDAP-Proxy'] = (False, True)['P' in usageCode]
                    uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_NTLM-Auth'] = (False, True)['N' in usageCode]
                    uidAgents['stats']['firewalls'][fw_serial][agent.attrib['name']]['usage_CredentialEnforcement'] = (False, True)['C' in usageCode]
                uidAgents['stats']['headers'] = panCore.headers
        else:
            uidAgents['stats']['firewalls'][fw_serial] = {'NOT CONFIGURED': {}}
        xmlData = panCore.xmlToLXML(fw_obj.op('show user user-id-service status'))
        if len(xmlData.xpath('/response/result')[0].text.splitlines()) >= 1:
            uidService['firewalls'][fw_serial] = {}
            for line in xmlData.xpath('/response/result')[0].text.splitlines():
                if len(line) <= 0:
                    continue
                elif 'user id service info' in line.lower():
                    continue
                else:
                    line = " ".join(line.replace(" : ", ":").split()).split(":")
                    uidService['firewalls'][fw_serial][line[0]] = line[1]
            for header in uidService['firewalls'][fw_serial].keys():
                if header not in uidService['headers']:
                    uidService['headers'].append(header)
        else:
            uidService['firewalls'][fw_serial] = {'NOT CONFIGURED': {}}
        xmlData = panCore.xmlToLXML(fw_obj.op('show user group-mapping statistics'))
        if len(xmlData.xpath('/response/result/entry')):
            uidGroupMapping['stats']['firewalls'][fw_serial] = {}
            for groupMapping in xmlData.xpath('/response/result/entry'):
                panCore.devData = {'temp': {}}
                panCore.headers = uidGroupMapping['stats']['headers']
                for child in groupMapping.getchildren():
                    panCore.iterator(child,'temp')
                    uidGroupMapping['stats']['firewalls'][fw_serial][groupMapping.find('./name').text] = panCore.devData['temp']
            uidGroupMapping['stats']['headers'] = panCore.headers
        else:
            uidGroupMapping['stats']['firewalls'][fw_serial] = {'NOT CONFIGURED': {}}
        """
        Show user group-mapping state all command results in string which doesn't show LDAP profile, etc
        Retrieving config defining group-mapping allows better reporting and break out.
        """
        #xmlData = panCore.xmlToLXML(fw_obj.op('<show><user><group-mapping><state>all</state></group-mapping></user></show>', cmd_xml=False))
        if fw_obj.multi_vsys == True:
            print('Multi-vsys enabled')
        else:
            xmlData = panCore.xmlToLXML(fw_obj.xapi.get("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/group-mapping"))
            if len(xmlData.xpath('/response/result/group-mapping/entry')):
                uidGroupMapping['configs']['firewalls'][fw_serial] = {}
                for groupMapping in xmlData.xpath('/response/result/group-mapping/entry'):
                    groupMappingName = groupMapping.attrib['name']
                    panCore.devData = {groupMappingName: {}}
                    panCore.headers = uidGroupMapping['configs']['headers']
                    for child in groupMapping:
                        panCore.iterator(child, groupMappingName, ignoreTemplateKeys=True)
                    uidGroupMapping['configs']['firewalls'][fw_serial][groupMappingName] = panCore.devData[groupMappingName]
                uidGroupMapping['configs']['headers'] = panCore.headers
            uidGroupMapping['states']['firewalls'][fw_serial] = {}
            for groupMappingName in uidGroupMapping['configs']['firewalls'][fw_serial].keys():
                uidGroupMapping['states']['firewalls'][fw_serial][groupMappingName] = {}
                xmlData = panCore.xmlToLXML(fw_obj.op(f'<show><user><group-mapping><state>{groupMappingName}</state></group-mapping></user></show>', cmd_xml=False))
                if len(xmlData.xpath('/response/result')[0].text) >= 1:
                    uidGroupMapping['states']['firewalls'][fw_serial][groupMappingName]['groupMappingName'] = groupMappingName
                    if 'groupMappingName' not in uidGroupMapping['states']['headers']:
                        uidGroupMapping['states']['headers'].append('groupMappingName')
                    respText = xmlData.xpath('/response/result')[0].text
                    grpNumber = 0
                    svrNumber = 0
                    for line in respText.splitlines():
                        if not len(line):
                            continue # skip empty line breaks
                        elif line.lower().startswith('group mapping('):
                            continue # Skip intro line. Parsing would be redundant - config already reported.
                        line = " ".join(line.split()).replace(" : ", ":").split(":")
                        if len(line) == 1:
                            if 'cn=' in line[0]:
                                grpNumber += 1
                                uidGroupMapping['states']['firewalls'][fw_serial][groupMappingName][f"Group-{grpNumber}"] = line[0]
                                if f"Group-{grpNumber}" not in uidGroupMapping['states']['headers']:
                                    uidGroupMapping['states']['headers'].append(f"Group-{grpNumber}")
                                continue
                            else:
                                svrNumber += 1
                                uidGroupMapping['states']['firewalls'][fw_serial][groupMappingName][f"Server-{svrNumber}_serverName"] = line[0]
                                if f"Server-{svrNumber}_serverName" not in uidGroupMapping['states']['headers']:
                                    uidGroupMapping['states']['headers'].append(f"Server-{svrNumber}_serverName")
                                continue
                        else:
                            if 'action time' in line[0].lower():
                                uidGroupMapping['states']['firewalls'][fw_serial][groupMappingName][f"Server-{svrNumber}_{line[0]}"] = line[1]
                                if f"Server-{svrNumber}_{line[0]}" not in uidGroupMapping['states']['headers']:
                                    uidGroupMapping['states']['headers'].append(f"Server-{svrNumber}_{line[0]}")
                            else:
                                uidGroupMapping['states']['firewalls'][fw_serial][groupMappingName][line[0]] = line[1]
                                if line[0] not in  uidGroupMapping['states']['headers']:
                                    uidGroupMapping['states']['headers'].append(line[0])
                else:
                    uidGroupMapping['states']['firewalls'][fw_serial][groupMappingName] = {'NOT CONFIGURED': {}}
        #xmlData = panCore.xmlToLXML(fw_obj.op('show user group-mapping-service status'))
        #xmlData = panCore.xmlToLXML(fw_obj.op('<show><user><server-monitor><state>all</state></server-monitor></user></show>', cmd_xml=False))
    except Exception as exception_details:
        panCore.logging.exception(f"ERROR ENCOUNTERED WHILE AUDITING {fw_obj.serial}")
        panCore.logging.exception(exception_details)

dataRedistAgents['stats']['headers'].extend(['usageCode', 'usage_UserMapping', 'usage_IP', 'usage_UserTag', 'usage_HIP-Reports', 'usage_Quarantine'])
uidAgents['stats']['headers'].extend(['usageCode', 'usage_LDAP-Proxy', 'usage_NTLM-Auth', 'usage_CredentialEnforcement'])
if 'usage' in uidAgents['stats']['headers']: uidAgents['stats']['headers'].remove('usage')

"""
uidAgents['stats']['headers'] = ['FW_Serial', 'AgentName'] + uidAgents['stats']['headers']
uidAgents['states']['headers'] = ['FW_Serial', 'AgentName'] + uidAgents['states']['headers']
dataRedistAgents['stats']['headers'] = ['FW_Serial', 'AgentName'] + dataRedistAgents['stats']['headers']
dataRedistAgents['states']['headers'] = ['FW_Serial', 'AgentName'] + dataRedistAgents['states']['headers']
dataRedistServers['headers'] = ['FW_Serial', 'svrNumber'] + dataRedistServers['headers']
"""
workbook_obj = xlsxwriter.Workbook(args[0].workbookname)
worksheet = workbook_obj.add_worksheet('UIDAgents_Statistics')
worksheet.write_row('A1', uidAgents['stats']['headers'], workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
for preambleHeader in preambleHeaders:
    if preambleHeader in uidAgents['stats']['headers']: uidAgents['stats']['headers'].remove(preambleHeader)
row = 1
for fw_serial in uidAgents['stats']['firewalls'].keys():
    for agentName in uidAgents['stats']['firewalls'][fw_serial].keys():
        worksheet.write(row, 0, fw_serial)
        worksheet.write(row, 1, panoInventory[fw_serial]['hostname'])
        worksheet.write(row, 2, panoInventory[fw_serial]['ip-address'])
        worksheet.write(row, 3, agentName)
        col = 4
        for item in uidAgents['stats']['headers']:
            if item in uidAgents['stats']['firewalls'][fw_serial][agentName].keys():
                worksheet.write(row, col, uidAgents['stats']['firewalls'][fw_serial][agentName][item])
            else:
                worksheet.write(row, col, "", workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
        row += 1

worksheet = workbook_obj.add_worksheet('UIDAgents_States')
worksheet.write_row('A1', uidAgents['states']['headers'], workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
for preambleHeader in preambleHeaders:
    if preambleHeader in uidAgents['states']['headers']: uidAgents['states']['headers'].remove(preambleHeader)
row = 1
for fw_serial in uidAgents['states']['firewalls'].keys():
    for agentName in uidAgents['states']['firewalls'][fw_serial].keys():
        worksheet.write(row, 0, fw_serial)
        worksheet.write(row, 1, panoInventory[fw_serial]['hostname'])
        worksheet.write(row, 2, panoInventory[fw_serial]['ip-address'])
        worksheet.write(row, 3, agentName)
        col = 4
        for item in uidAgents['states']['headers']:
            if item in uidAgents['states']['firewalls'][fw_serial][agentName].keys():
                worksheet.write(row, col, uidAgents['states']['firewalls'][fw_serial][agentName][item])
            else:
                worksheet.write(row, col, "", workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
        row += 1

worksheet = workbook_obj.add_worksheet('UID-Service')
worksheet.write_row('A1', uidService['headers'], workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
for preambleHeader in preambleHeaders:
    if preambleHeader in uidService['headers']: uidService['headers'].remove(preambleHeader)
row = 1
for fw_serial in uidService['firewalls'].keys():
    worksheet.write(row, 0, fw_serial)
    worksheet.write(row, 1, panoInventory[fw_serial]['hostname'])
    worksheet.write(row, 2, panoInventory[fw_serial]['ip-address'])
    col = 3
    for item in uidService['headers']:
        if item in uidService['firewalls'][fw_serial].keys():
            worksheet.write(row, col, uidService['firewalls'][fw_serial][item])
        else:
            worksheet.write(row, col, "", workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row += 1

worksheet = workbook_obj.add_worksheet('Redistribution Statistics')
worksheet.write_row('A1', dataRedistAgents['stats']['headers'], workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
for preambleHeader in preambleHeaders:
    if preambleHeader in dataRedistAgents['stats']['headers']: dataRedistAgents['stats']['headers'].remove(preambleHeader)
row = 1
for fw_serial in dataRedistAgents['stats']['firewalls'].keys():
    for agentName in dataRedistAgents['stats']['firewalls'][fw_serial].keys():
        worksheet.write(row, 0, fw_serial)
        worksheet.write(row, 1, panoInventory[fw_serial]['hostname'])
        worksheet.write(row, 2, panoInventory[fw_serial]['ip-address'])
        worksheet.write(row, 3, agentName)
        col = 4
        for item in dataRedistAgents['stats']['headers']:
            if item in dataRedistAgents['stats']['firewalls'][fw_serial][agentName].keys():
                worksheet.write(row, col, dataRedistAgents['stats']['firewalls'][fw_serial][agentName][item])
            else:
                worksheet.write(row, col, "", workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
        row += 1

worksheet = workbook_obj.add_worksheet('Redistribution States')
worksheet.write_row('A1', dataRedistAgents['states']['headers'], workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
for preambleHeader in preambleHeaders:
    if preambleHeader in dataRedistAgents['states']['headers']: dataRedistAgents['states']['headers'].remove(preambleHeader)
row = 1
for fw_serial in dataRedistAgents['states']['firewalls'].keys():
    for agentName in dataRedistAgents['states']['firewalls'][fw_serial].keys():
        worksheet.write(row, 0, fw_serial)
        worksheet.write(row, 1, panoInventory[fw_serial]['hostname'])
        worksheet.write(row, 2, panoInventory[fw_serial]['ip-address'])
        worksheet.write(row, 3, agentName)
        col = 4
        for item in dataRedistAgents['states']['headers']:
            if item in dataRedistAgents['states']['firewalls'][fw_serial][agentName].keys():
                worksheet.write(row, col, dataRedistAgents['states']['firewalls'][fw_serial][agentName][item])
            else:
                worksheet.write(row, col, "", workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
        row += 1

worksheet = workbook_obj.add_worksheet('Redistribution Servers')
worksheet.write_row('A1', dataRedistServers['headers'], workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
for preambleHeader in preambleHeaders + ['svrNumber']:
    if preambleHeader in dataRedistServers['headers']: dataRedistServers['headers'].remove(preambleHeader)
row = 1
for fw_serial in dataRedistServers['firewalls'].keys():
    for svrNumber in dataRedistServers['firewalls'][fw_serial].keys():
        worksheet.write(row, 0, fw_serial)
        worksheet.write(row, 1, panoInventory[fw_serial]['hostname'])
        worksheet.write(row, 2, panoInventory[fw_serial]['ip-address'])
        worksheet.write(row, 3, svrNumber)
        col = 4
        for item in dataRedistServers['headers']:
            if item in dataRedistServers['firewalls'][fw_serial][svrNumber].keys():
                worksheet.write(row, col, dataRedistServers['firewalls'][fw_serial][svrNumber][item])
            else:
                worksheet.write(row, col, "", workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
        row += 1
workbook_obj.close()
