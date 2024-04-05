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
Changelog 2023-10-25:
    Create file.

Goals:


"""
#Import custom library modules
from pancore import panCore, panExcelStyles
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse, panos.errors

parser = argparse.ArgumentParser(
    prog="PanSecurityGroupsAndProfiles",
    description="Audit Panorama report back on security profiles and security profile groups.")
    #epilog="Text")

parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='GP-PreviousUsers.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='GP-PreviousUsers.xlsx')
args = parser.parse_known_args()

panCore.startLogging(args[0].logfile)
panCore.configStart(headless=args[0].headless, configStorage=args[0].conffile)
if hasattr(panCore, 'panUser'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, 'panKey'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    panCore.logging.critical("Found neither username/password nor API key. Exiting.")
    sys.exit()


auditStartTime = datetime.datetime.now(datetime.timezone.utc)
panCore.headers = ['FirewallName', 'GatewayName']
panCore.devData = {}
fwCount = len(firewalls)
panCore.logging.info("*********")
panCore.logging.info(f"Starting to gather GP user data from {fwCount} total firewalls at {auditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
fwNum = 1
gpUserList = {}
for fw_obj in firewalls:
    startTime = datetime.datetime.now(datetime.timezone.utc)
    try:
        device = fw_obj.serial
        if not fw_obj.state.connected:
            panCore.logging.info(f"--> Device Offline: {device} ({fwNum}/{fwCount}) at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
            fwNum += 1
            continue
        panCore.logging.info(f"--> Gathering GP Previous Users for device: {device} ({fwNum}/{fwCount}) at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
        deviceData = fw_obj.show_system_info()
        fwName = deviceData['system']['hostname']
        try:
            gpTunnelingGateways = panCore.xmlToLXML(fw_obj.xapi.show("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/global-protect-gateway"))
        except panos.errors.PanNoSuchNode as e:
            panCore.logging.info(f"--> {device} has no GP Gatewas. Skipping. ({fwNum}/{fwCount})")
            fwNum += 1
            continue
        if len(gpTunnelingGateways.xpath('/response/result/global-protect-gateway/entry')):
            # If firewall has GP tunneling gateways proceed to audit it for "previous users"
            gpUserList[fwName] = {}
            for gateway in gpTunnelingGateways.xpath('/response/result/global-protect-gateway/entry'):
                gwName = gateway.attrib['name'][:-2]  # String slice off "-n" suffix from TUNNEL name to acquire GATEWAY name
                gpUserList[fwName][gwName] = {}
                gpUsers = panCore.xmlToLXML(fw_obj.op(f"<show><global-protect-gateway><previous-user><gateway>{gwName}</gateway></previous-user></global-protect-gateway></show>",cmd_xml=False))
                if len(gpUsers.xpath('/response/result/entry')):
                    #If users exist in "previous user" command output add them to the dictionary
                    i = 1
                    for gpUser in gpUsers.xpath('/response/result/entry'):
                        # Re-declare devData to empty set for each iteration.
                        # DO NOT Re-declare headers. Continue appending new headers as encountered.
                        panCore.devData = {'temp': {}}
                        for data in gpUser.getchildren():
                            panCore.iterator(data, 'temp')
                        gpUserList[fwName][gwName][i] = panCore.devData['temp']
                        i += 1
        fwNum += 1
    except Exception:
        panCore.logging.exception(f"ERROR ENCOUNTERED WHILE AUDITING {fw_obj.serial}")

auditEndTime = datetime.datetime.now(datetime.timezone.utc)
panCore.logging.info(f"Finished gathering GP user data from {fwCount} total firewalls at {auditEndTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")

workbook = xlsxwriter.Workbook(args[0].workbookname)
worksheet = workbook.add_worksheet('GP Previous Users')
worksheet.write_row('A1', panCore.headers,workbook.add_format(panExcelStyles.styles['rowHeader']))
if "FirewallName" in panCore.headers:
    panCore.headers.remove("FirewallName")
if "GatewayName" in panCore.headers:
    panCore.headers.remove("GatewayName")
row = 1
for firewall in gpUserList.keys():
    for gateway in gpUserList[firewall].keys():
        for user in gpUserList[firewall][gateway]:
            worksheet.write(row, 0, firewall)
            worksheet.write(row, 1, gateway)
            col = 2
            for data in panCore.headers:
                if data in gpUserList[firewall][gateway][user].keys():
                    worksheet.write(row, col, gpUserList[firewall][gateway][user][data])
                    col += 1
                else:
                    worksheet.write(row, col, "",workbook.add_format(panExcelStyles.styles['blackBox']))
                    col += 1
            row += 1
workbook.close()