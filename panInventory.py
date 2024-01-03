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
Changelog
2023-01-25 - Added ability parse either 'fail-cond' or 'failure-condition' in HA Link group monitoring. (PAN-OS <= 9.1 vs >= 10.x)
2023-02-10 - Added check for active-active clustervls in "Check passive link state" test.
2023-03-30 - Fixed 'NetworkInterfaces-Logical' spreadsheet
2023-04-01 - Added syslogProfiles & LogOutput summary & details report
2023-12-01 - Added 'template' and 'template stack' worksheets

Goals
1.  On "zoneInfo" worksheet the "Zones withouth interfaces" report should use colspan() to spread the list of firewalls
    with these zones out to avoid auto-width from messing with the other tables' views.
2.  'HALinkGroups' worksheet is showing stand-alone firewalls as though they were a single-node cluster. This is not desired.
3. Test 'gatherSyslogProfiles' function on multi-vsys firewall, validate /config/shared is sole path. Incorporate "for vsys" loop if necessary.
4. Implement additional arg to skip syslog / log output details not required.
5. Cope with timeouts, add error handling to "for fw_obj in firewalls" loop to allow for passing over errors rather than crashing
"""


from pancore import panCore, panExcelStyles
import json
import sys
from collections import OrderedDict
import re  # Because regex is awesome
import datetime, argparse
import panos  # Because we hate reinventing the wheel
from panos import ha, panorama, base, firewall


parser = argparse.ArgumentParser(
    prog="PanInventory",
    description="Audit Panorama & connected firewalls to generate reports on system state & health")
    #epilog="Text")

"""
In order to have a default behavior of reports being "ENABLED" we default=True below, but then use "store_false" when 
 a flag is activated. This is strange "enabling a negative" is counter-intuitive, but the reversed behavior upon 
 ENABLING the flag to DISABLE the report simplifies the user interactions and allows the default to be overruled 
 when the flag is used.
"""
parser.add_argument('-I', '--headless', help="Disable Interactions; operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='panInventory.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='PanInventory.xlsx')
parser.add_argument('-l', '--license', help="Disable licensing report", default=True, action='store_false')
parser.add_argument('-i', '--interfaces', help="Disable Interface details reporting", default=True, action='store_false')
parser.add_argument('-r', '--systemresources', help="Disable system Resource reporting", default=True, action='store_false')
parser.add_argument('-s', '--systemstate', help="Disable system State reporting (SysState is VERY noisy)", default=True, action='store_false')
parser.add_argument('-e', '--environmentals', help="Disable system Environmental monitoring details", default=True, action='store_false')
parser.add_argument('-z', '--zones', help="Disable zone details reporting.", default=True, action='store_false')
args = parser.parse_known_args()

todayDate = datetime.date.today()

def gatherHighAvailabilityAll(device):
    #global panCore.devData, panCore.headers
    xmlData = panCore.xmlToLXML(fw_obj.op('show high-availability all'))
    panCore.devData = {
        'enabled': xmlData.xpath("./result/enabled")[0].text,
        'mode': xmlData.xpath("./result/group/mode")[0].text,
        'running-sync': xmlData.xpath("./result/group/running-sync")[0].text,
        'running-sync-enabled': xmlData.xpath("./result/group/running-sync-enabled")[0].text,
        'local-info': {},
        'peer-info': {},
        'link-monitoring': {},
        'path-monitoring': {}
        }
    panCore.headers = []
    for setting in xmlData.xpath("./result/group/local-info")[0].getchildren():
        panCore.iterator(setting,'local-info')
    for setting in xmlData.xpath("./result/group/peer-info")[0].getchildren():
        panCore.iterator(setting,'peer-info')
    for setting in xmlData.xpath("./result/group/link-monitoring")[0].getchildren():
        panCore.iterator(setting,'link-monitoring')
    for setting in xmlData.xpath("./result/group/path-monitoring")[0].getchildren():
        panCore.iterator(setting,'path-monitoring')
    return(panCore.devData)


def gatherHighAvailabilityLinkMonitoringDetails():
    xmlData = panCore.xmlToLXML(fw_obj.op('show high-availability link-monitoring'))
    # Accomodate XML path changes in 10.x:
    if xmlData.xpath("./result/group/link-monitoring/fail-cond"):
        linkMonitorFailCond = xmlData.xpath("./result/group/link-monitoring/fail-cond")[0].text
    elif xmlData.xpath("./result/group/link-monitoring/failure-condition"):
        linkMonitorFailCond = xmlData.xpath("./result/group/link-monitoring/failure-condition")[0].text
    linkMonitorEnabled = xmlData.xpath('./result/group/link-monitoring/enabled')[0].text
    panCore.devData = {"linkMonitorEnabled": linkMonitorEnabled, "linkMonitorFailCond": linkMonitorFailCond}
    panCore.devData['groups'] = {}
    for intGroup in xmlData.xpath('//groups/entry'):
        grpName = intGroup.xpath("./name")[0].text
        grpEnabled = intGroup.xpath("./enabled")[0].text
        grpFailCond = intGroup.xpath("./fail-cond")[0].text
        panCore.devData['groups'][grpName] = {
            "groupEnabled": grpEnabled,
            "groupFailCond": grpFailCond,
            "groupMemberDown": "NotCheckedYet",
            "Interfaces": {}}
        for interface in intGroup.xpath('./interface/entry'):
            intName = interface.xpath("./name")[0].text
            intStatus = interface.xpath("./status")[0].text
            panCore.devData['groups'][grpName]['Interfaces'][intName] = intStatus
            if intStatus == 'up':
                panCore.devData['groups'][grpName]['groupMemberDown'] = "No"
            else:
                panCore.devData['groups'][grpName]['groupMemberDown'] = "Yes"
    return(panCore.devData)


def checkLinkMonitoring():
    if clusterDetails[clusterGUID][device]['haConfig']['link-monitoring'] == clusterDetails[clusterGUID][peerDevice]['haConfig']['link-monitoring']:
        return True
    else:
        return False


def checkPassiveLinkState():
    if clusterDetails[clusterGUID][device]['haConfig']['mode'].lower() == 'active-active':
        return "Active-Active"
    elif clusterDetails[clusterGUID][device]['haConfig']['local-info']['active-passive.passive-link-state'].lower() == "auto" and clusterDetails[clusterGUID][peerDevice]['haConfig']['local-info']['active-passive.passive-link-state'].lower() == "auto":
        return "Both Auto"
    elif clusterDetails[clusterGUID][device]['haConfig']['local-info']['active-passive.passive-link-state'].lower() == "shutdown" and clusterDetails[clusterGUID][peerDevice]['haConfig']['local-info']['active-passive.passive-link-state'].lower() == "shutdown":
        return "Both Shutdown"
    else:
        return "Mismatch between peers"


def gatherFirewallDetails(device):
    #global panCore.devData,panCore.headers
    ### Modify the global-scope 'firewallDetails' dictionary with the detailed config from each firewall
    # try:
    #    fw_obj.vsys = None
    # if VM / GCP VM  has no VSYS functionality skip this.
    # except:
    #    pass
    # firewallDetails[device] = {'deviceState': fw_obj.show_system_info()['system']}
    # ^ Would Prefer to use pan-os-python, however VM series plugin data arrives in a nested dictionary, which causes some trauma in exporting to CSV/Excel.
    # Forced to use panCore.iterator to flatten the XML response JSON-style so it's easier to export into reports. Keeping .show_system_info() method for historical purposes
    xmlData = panCore.xmlToLXML(fw_obj.op("show system info"))
    panCore.devData = {device: {}} #Nested dictionary to conform to panCore.iterator expected input. Don't try to simplify this; it's really not worth it.
    panCore.headers = []
    for setting in xmlData.xpath("./result/system")[0].getchildren():
        panCore.iterator(setting, device)
    sysInfo = panCore.devData[device]
    if not args[0].systemstate:
        return sysInfo
    else:
        xmlData = panCore.xmlToLXML(fw_obj.op('show system state'))
        sysStateLines = (xmlData[0].text).split("\n")
        sysState = {}
        for line in sysStateLines:
            line = line.replace(", }", " }") # Get rid of the trailing coma after the last item as it will break later conversion to dictionary object
            if len(line) < 2 or line[-1] == ':':
                # Skip line if it has nothing to import.
                pass
            elif ":" not in line:
                sysState[oldKey] = sysState[oldKey] + line
                #print(f"Appended {line} to {sysState[oldKey]}")
                pass
            else:
                key, val = line.split(":", 1)
                oldKey = key
                sysState[key] = str(val)
        return sysInfo, sysState



def gatherFirewallSchedules(device):
    #### Gather dynamic update schedules
    xmlData = panCore.xmlToLXML(
        fw_obj.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule"))
    panCore.devData = {'schedules': {}}
    expectedSchedules = ['anti-virus', 'app-profile', 'global-protect-clientless-vpn', 'global-protect-datafile',
                         'statistics-service', 'threats', 'url-database', 'wf-private', 'wildfire']
    foundSchedules = []
    for schedule in xmlData.xpath('//result/update-schedule')[0].getchildren():
        # panCore.devData['schedules'] = {}
        if len(schedule):
            panCore.iterator(schedule, "schedules")
    for schedule in panCore.devData['schedules']:
        foundSchedules.extend([schedule.split('.')[0]])
    for schedule in expectedSchedules:
        if schedule not in foundSchedules:
            panCore.devData['schedules'][schedule] = "Not Configured"
    return(panCore.devData['schedules'])


def gatherFirewallInterfaces():
    #Create dictionary slots for interface info before launches loops over interfaces of the firewall
    ifData = {'logical': {}, 'hardware': {}}
    ifData['fullDetails'] = ('skip',{})[args[0].interfaces]
    # If full interface details are requested create dictionary slot for them, else record 'skip'
    xmlData = panCore.xmlToLXML(fw_obj.op(cmd="<show><interface>all</interface></show>", cmd_xml=False))
    for hwIf in xmlData.xpath('//result/hw/entry'):
        ifName = hwIf.xpath("./name")[0].text
        panCore.headers = []
        panCore.devData = {ifName: {}}
        for ifAttribute in hwIf.getchildren():
            panCore.iterator(ifAttribute, ifName)
        ifData['hardware'].update(panCore.devData)
    for logicalIf in xmlData.xpath('//result/ifnet/entry'):
        ifName = logicalIf.xpath("./name")[0].text
        panCore.headers = []
        panCore.devData = {ifName: {}}
        for ifAttribute in logicalIf.getchildren():
            panCore.iterator(ifAttribute, ifName)
        ifData['logical'].update(panCore.devData)
        if args[0].interfaces:
            panCore.logging.info("      > Gathering detailed interface info for {0}".format(ifName))
            try:
                ifDetails = panCore.xmlToLXML(fw_obj.op(cmd="<show><interface>{0}</interface></show>".format(ifName), cmd_xml=False))
            except:
                panCore.logging.info("********> FAILED GATHERING DETAILED INTERFACE INFO FOR {0}".format(ifName))
                pass
            panCore.headers = []
            panCore.devData = {ifName: {}}
            for ifDetail in ifDetails.xpath('/response/result')[0].getchildren():
                panCore.iterator(element=ifDetail,item=ifName,deleteEntryTag=False)
            ifData['fullDetails'].update(panCore.devData)
    return ifData


def gatherSystemEnvironmentals():
    xmlData = panCore.xmlToLXML(fw_obj.op('show system environmentals'))
    panCore.headers = []
    panCore.devData = {'environmentals': {}}
    panCore.iterator(xmlData[0],'environmentals')
    envData = {'alarmPresent': False}
    for key in panCore.devData['environmentals'].keys():
        envData[key.replace("result.","")] = panCore.devData['environmentals'][key]
        if '.alarm' in key and not panCore.devData['environmentals'][key] == "False":
            envData['alarmPresent'] = True
    return envData


def gatherLicenseInfo():
    xmlData = panCore.xmlToLXML(fw_obj.op('request license info'))
    panCore.devData = {'licenseInfo': {}}
    panCore.headers = []
    for license in xmlData.xpath('//response/result/licenses')[0].getchildren():
        panCore.iterator(license, 'licenseInfo')
    return panCore.devData['licenseInfo']


def gatherSyslogProfiles():
    xmlData = panCore.xmlToLXML(fw_obj.xapi.get('/config/shared/log-settings/syslog'))
    if not len(xmlData[0]):
        return
    # Multi-vsys xpath?
    # /devices/entry[@name='<device_name>']/vsys/entry[@name='<vsys_name>']/log-settings/syslog/
    syslogProfiles = {}
    for profile in xmlData[0][0].getchildren():
        profileName = profile.get('name')
        syslogProfiles[profileName] = {'servers': {},'customFormats': {}}
        for server in profile.xpath('./server/entry'):
            serverName = server.get('name')
            panCore.headers = []
            panCore.devData = {serverName: {}}
            for child in server.getchildren():
                panCore.iterator(child, serverName)
            syslogProfiles[profileName]['servers'][serverName] = panCore.devData[serverName]
            serverProperties = serverName + " " + \
                               str([syslogProfiles[profileName]['servers'][serverName]['server'],
                                    syslogProfiles[profileName]['servers'][serverName]['transport'],
                                    syslogProfiles[profileName]['servers'][serverName]['port'],
                                    syslogProfiles[profileName]['servers'][serverName]['facility']])
            if serverProperties not in profileData['syslog'].keys():
                profileData['syslog'][serverProperties] = {'config': panCore.devData[serverName],
                                                           'firewalls': [fwName]}
                #profileData['syslog'][serverProperties]['config']['name'] = serverName
                profileData['syslog'][serverProperties]['name'] = serverName
            else:
                profileData['syslog'][serverProperties]['firewalls'].append(fwName)
        if profile.xpath('./format'):
            for customFormat in profile.xpath('./format')[0].getchildren():
                syslogProfiles[profileName]['customFormats'][customFormat.tag] = customFormat.text
    return syslogProfiles

def gatherDeviceLogSettings():
    xmlData = panCore.xmlToLXML(fw_obj.xapi.get('/config/shared/log-settings'))
    deviceLogConfig = {
        'config': {},
        'system': {},
        'userid': {},
        'hipmatch': {},
        'globalprotect': {},
        'iptag': {},
        'correlation': {}}
    for logType in deviceLogConfig.keys():
        if xmlData.xpath(f'/response/result/log-settings/{logType}'):
            config = xmlData.xpath(f'/response/result/log-settings/{logType}')[0]
            for rule in config.xpath('./match-list/entry'):
                ruleName = rule.get('name')
                if rule.xpath('./description'):
                    ruleDescription = rule.xpath('./description')[0].text
                else:
                    ruleDescription = ""
                deviceLogConfig[logType][ruleName] = {
                'ruleFilter': rule.xpath('./filter')[0].text,
                'ruleDescription': ruleDescription,
                'logType': logType,
                'destinations': {}}
                for child in rule.getchildren():
                    if child.tag not in ['filter', 'description']:
                        destList = []
                        for destination in child.xpath('./member'):
                            destList.append(destination.text)
                        deviceLogConfig[logType][ruleName]['destinations'][child.tag] = destList
                list = [deviceLogConfig[logType][ruleName]['ruleFilter'], deviceLogConfig[logType][ruleName]['destinations']]
                ruleConfig = ruleName + " " + str(list)
                if ruleConfig not in profileData['logOutputs']:
                    profileData['logOutputs'][ruleConfig] = {'config': deviceLogConfig[logType][ruleName],
                                                             'name': ruleName,
                                                             'firewalls': [fwName]}
                else:
                    profileData['logOutputs'][ruleConfig]['firewalls'].append(fwName)
    return deviceLogConfig

def gatherZoneList():
    panCore.devData = {}
    fwZoneList = panos.network.Zone.refreshall(fw_obj)
    for zone_obj in fwZoneList:
        zoneAbout = zone_obj.about()
        if len(zoneAbout['interface']):
            zoneAbout['hasInterfaces'] = True
        else:
            zoneAbout['hasInterfaces'] = False
        zoneAbout.pop('interface')
        panCore.devData[zoneAbout['name']] = zoneAbout
        if zoneAbout['name'] not in zoneList.keys():
            # If zone isn't in dictionary add it.
            zoneList[zone_obj.name] = {0: {"config": zoneAbout, "firewalls": [fwName + " (" + device + ")"]}}
        else:
            # If zone is in dictionary check if it's configured the same as the instance in the dictionary.
            matchFound = False
            for zoneRecord in zoneList[zone_obj.name]:
                if zoneAbout == zoneList[zone_obj.name][zoneRecord]["config"]:
                    matchFound = True
                    # Zone config matches an existing config. Append firewall to list of firewalls which utilize it.
                    zoneList[zone_obj.name][zoneRecord]['firewalls'].append(fwName + " (" + device + ")")
            if not matchFound:
                # Zone config doesn't match an existing configuration on record. Create a new record.
                zoneRecord += 1
                zoneList[zone_obj.name][zoneRecord] = {"config": zoneAbout,
                                                       "firewalls": [fwName + " (" + device + ")"]}
    return(panCore.devData)


def gatherTemplateData(templates, tStacks):
    devData = {'templates': {},
               'stacks': {}}
    maxVar = 0
    for tpl_obj in templates:
        tplName = tpl_obj.about()['name']
        tplVars = tpl_obj.findall(panos.panorama.TemplateVariable)
        maxVar = max(maxVar, len(tplVars))
        devData['templates'][tplName] = {'config': tpl_obj.about(),
                                         'variables':{},
                                         'usedIn': []}
        varNum = 1
        for tplVar in tplVars:
            #varName = tplVar.about()['name']
            devData['templates'][tplName]['variables'][varNum] = tplVar.about()
            varNum += 1
    devData['tplVarCount'] = maxVar
    maxVar = 0
    for stk_obj in tStacks:
        stkName = stk_obj.about()['name']
        stkVars = stk_obj.findall(panos.panorama.TemplateVariable)
        maxVar = max(maxVar, len(stkVars))
        devData['stacks'][stkName] = {'config': stk_obj.about(),
                                      'variables': {}}
        varNum = 1
        for stkVar in stkVars:
            #varName = stkVar.about()['name']
            devData['stacks'][stkName]['variables'][varNum] = stkVar.about()
            varNum += 1
        for tplName in stk_obj.about()['templates']:
            devData['templates'][tplName]['usedIn'].append(stkName)
    devData['stkVarCount'] = maxVar
    return devData

panCore.startLogging(args[0].logfile)

panCore.configStart(headless=args[0].headless, configStorage=args[0].conffile)
if hasattr(panCore, 'panUser'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, 'panKey'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    panCore.logging.critical("Found neither username/password nor API key. Exiting.")
    sys.exit()

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

tplData = gatherTemplateData(templates, tStacks)

#######################################################################################
#######################################################################################
##################### Fetch firewall Details ##########################################

panCore.logging.info("Gathering Detailed Inventory from Firewalls:")
firewallDetails = {}
fwDetailsByModel = {}
clusterDetails = {}
profileData = {'syslog': {}, 'logOutputs': {}}
zoneList = {}
fwCount = len(firewalls)
fwNum = 1
for fw_obj in firewalls[0:10]:
    try:
        device = fw_obj.serial
        if not fw_obj.state.connected:
            panCore.logging.info("--> Device Offline: {0} ({1}/{2}".format(device, fwNum, fwCount))
            fwNum += 1
            continue
        panCore.logging.info("--> Gathering Inventory of Device: {0} ({1}/{2})".format(device, fwNum, fwCount))
        fwNum += 1
        fw_obj.refresh_system_info()  # Update PAN-OS version, platform & serial #
        firewallDetails[device] = {}
        panCore.logging.info("    > Gathering 'show system info' information...")
        if args[0].systemstate == True:
            firewallDetails[device]['system'],firewallDetails[device]['systemState'] = gatherFirewallDetails(device)
        else:
            firewallDetails[device]['system'] = gatherFirewallDetails(device)
        fwName = firewallDetails[device]['system']['hostname']
        # The "System Environmentals" report has different headers per firewall model to avoid lots of "Null" columns
        # To support this we need to preserve a list of system environmental columns in its own dictionary.
        if fw_obj.platform not in fwDetailsByModel.keys():
            fwDetailsByModel[fw_obj.platform] = {}
        fwDetailsByModel[fw_obj.platform][device] = {}
        panCore.logging.info("    > Gathering 'show system environmentals' information...")
        fwDetailsByModel[fw_obj.platform][device]['environmentals'] = firewallDetails[device]['environmentals'] = gatherSystemEnvironmentals()
        panCore.logging.info("    > Gathering syslog profiles...")
        firewallDetails[device]['syslogProfiles'] = gatherSyslogProfiles()
        #if not firewallDetails[device]['syslogProfiles']:
        #    del firewallDetails[device]['syslogProfiles']
        panCore.logging.info("    > Gathering device log configuration...")
        # gatherDeviceLogSettings() depends on gatherSyslogProfiles() and MUST come after it.
        firewallDetails[device]['deviceLogOutputs'] = gatherDeviceLogSettings()
        panCore.logging.info("    > Gathering interface info...")
        firewallDetails[device]['interfaces'] = gatherFirewallInterfaces()
        panCore.logging.info("    > Gathering dynamic content update schedule information...")
        firewallDetails[device]['schedules'] = gatherFirewallSchedules(device)
        panCore.logging.info("    > Gathering zones attached to this firewall...")
        firewallDetails[device]['zones'] = gatherZoneList() #Function also updates zoneList dictionary.
        panCore.logging.info("    > Gathering licensing info...")
        firewallDetails[device]['licensing'] = gatherLicenseInfo()
        #### Check if the firewall is in an HA cluster, and if so gather the info about the cluster
        #if fw_obj.op(cmd="show high-availability state").findall(".//enabled")[0].text != 'yes':
        if 'ha.peer.serial' not in panoInventory[device]:
            panCore.logging.info("    > Skipping HA configuration audit, no HA peer serial number found in Panorama Inventory")
            firewallDetails[device]['haClusterMember'] = False
        else:
            panCore.logging.info("    > Gathering general HA configuration information...")
            peerDevice = panoInventory[device]['ha.peer.serial']
            ha_obj = panos.ha.HighAvailability()
            fw_obj.add(ha_obj)
            ha_obj.refresh()
            clusterGUID = min(panoInventory[device]['serial'], panoInventory[device]['ha.peer.serial']) + "-" + max(panoInventory[device]['serial'], panoInventory[device]['ha.peer.serial'])
            firewallDetails[device]['haClusterMember'] = {clusterGUID}
            #### Check if Cluster already exists, if not create it and the current device. If so add the current device to the previously gathered peer info.
            if clusterGUID not in clusterDetails:
                clusterDetails[clusterGUID] = {device: {"haConfig": gatherHighAvailabilityAll(device)}}
            else:
                clusterDetails[clusterGUID][device] = {"haConfig": gatherHighAvailabilityAll(device)}
            panCore.logging.info("    > Gathering HA link-monitoring info...")
            # VM's don't have physical links, thus have no 'link monitoring' to configure. Skip them.
            if not firewallDetails[device]['system']['family'] == 'vm':
                clusterDetails[clusterGUID][device]['link-monitoring'] = gatherHighAvailabilityLinkMonitoringDetails()
            if peerDevice not in clusterDetails[clusterGUID]:
                # If peer is offline (and thus not auditable) or just hasn't been audited yet drop a memo to that effect
                # Memo will be replaced once both cluster members have been audited.
                clusterDetails[clusterGUID][device]['linkMonitoringMatchesPeer'] = "Peer Device Not Audited/Available"
                clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'] = "Peer Device Not Audited/Available"
            else:
                panCore.logging.info("    > Calculating if Link Monitoring Config Matches Peer's")
                clusterDetails[clusterGUID][device]['linkMonitoringMatchesPeer'], clusterDetails[clusterGUID][peerDevice]['linkMonitoringMatchesPeer'] = [checkLinkMonitoring()] * 2
                clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'], clusterDetails[clusterGUID][peerDevice]['passiveLinkStateMatchesPeer'] = [checkPassiveLinkState()] * 2
    except Exception as exception_details:
        panCore.logging.exception(f"ERROR ENCOUNTERED WHILE AUDITING {fw_obj.serial}")
        panCore.logging.exception(exception_details)
panCore.logging.info("Finished Gathering Audit Data\n")


zoneReport = {'zonesWithoutInterfaces': {},
              'zonesWithMultipleConfigs': []}
for zoneName in zoneList.keys():
    if len(zoneList[zoneName]) >1:
        zoneReport['zonesWithMultipleConfigs'].append(zoneName)
    for zoneInstance in zoneList[zoneName]:
        if not zoneList[zoneName][zoneInstance]['config']['hasInterfaces']:
            zoneReport['zonesWithoutInterfaces'][f"{zoneName}^^{zoneInstance}"] = {"zoneName": zoneName, 'zoneInstance': zoneInstance, 'zoneFirewalls':zoneList[zoneName][zoneInstance]['firewalls']}
panCore.logging.info("Finished building ZoneReport\n")
panCore.logging.info("Begining building dictionaries for summary data reports")
syslogProfileCount = {}
for key, value in profileData['syslog'].items():
    name = value['name']
    if name not in syslogProfileCount:
        syslogProfileCount[name] = {'total': 1, 'counted': 1}
    else:
        syslogProfileCount[name]['total'] += 1
for syslogProfile in profileData['syslog']:
    serverName = profileData['syslog'][syslogProfile]['name']
    profileData['syslog'][syslogProfile]['count'] = f"{syslogProfileCount[serverName]['counted']}/{syslogProfileCount[serverName]['total']}"
    syslogProfileCount[serverName]['counted'] += 1

logOutputCount = {}
for key, value in profileData['logOutputs'].items():
    name = value['name']
    if name not in logOutputCount:
        logOutputCount[name] = {'total': 1, 'counted': 1}
    else:
        logOutputCount[name]['total'] += 1
for logOutput in profileData['logOutputs']:
    outputName = profileData['logOutputs'][logOutput]['name']
    profileData['logOutputs'][logOutput]['count'] = f"{logOutputCount[outputName]['counted']}/{logOutputCount[outputName]['total']}"
    logOutputCount[outputName]['counted'] += 1
panCore.logging.info("Done w/ summary data dictionaries.")


###   DEBUG POINT
#del panCore.worksheet
#del panCore.workbook_obj
panCore.initXLSX(args[0].workbookname)
panCore.headers = []
for device in panoInventory:
    for key in panoInventory[device].keys():
        if key not in panCore.headers:
            panCore.headers.append(key)

####### Output Panorama inventory to panCore.worksheet
panCore.logging.info("Writing Panorama device inventory panCore.worksheet:")
panCore.worksheet = panCore.workbook_obj.add_worksheet("PanoramaFirewallInventory")
panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
msg = '--> Writing Panorama Firewall Inventory {0} on row {1}'
for device in panoInventory:
    panCore.logging.info(msg.format(device, row))
    col = 0
    for item in panCore.headers:
        # Iterate over column headers encountered in Panorama's "Show devices all" command
        if item in panoInventory[device]:
            # Some firewalls lack fields others have. Testing if 'item' is here for this particular firewall
            panCore.worksheet.write(row, col, panoInventory[device][item])
            if all([item == 'connected', panoInventory[device]['connected'] == 'no']):
                # If we're in the 'connected' field and the firewall isn't highlight the fact with alertText
                panCore.worksheet.write(row, col, panoInventory[device][item],
                                panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
        else:
            #If we've hit a field this particular firewall doesn't have put a black box in the excel sheet and move on.
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row += 1

panCore.logging.info("Finished\n")

panCore.logging.info("Writing Firewall details worksheet:")
##### Write Firewall Details panCore.worksheet
panCore.headers = []
for device in firewallDetails:
    for header in firewallDetails[device]['system'].keys():
        if header not in panCore.headers:
            panCore.headers.extend([header])
panCore.worksheet = panCore.workbook_obj.add_worksheet("Firewall Show System Info")
panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
msg = '--> Writing system info for {0} on row {1}'
for device in firewallDetails:
    col = 0
    panCore.logging.info(msg.format(device, row))
    for item in panCore.headers:
        if item in firewallDetails[device]['system']:
            if 'release-date' not in item:
                panCore.worksheet.write(row, col, firewallDetails[device]['system'][item])
            else:
                if firewallDetails[device]['system'][item] == 'unknown':
                    panCore.worksheet.write(row, col, firewallDetails[device]['system'][item])
                else:
                    rawItemDate = firewallDetails[device]['system'][item]
                    # Check if item ends with a digit, and if so parse it as time.
                    # 2nd criteria protects against numeric timezone representations
                    if (re.search(r'\d+$', rawItemDate)) and not (rawItemDate[-3] == "+"):
                        itemDate = datetime.datetime.strptime(rawItemDate, '%Y/%m/%d %H:%M:%S')
                    else:
                        # Otherwise strip the four character (text or number) timezone label, and then parse it as time.
                        itemDate = datetime.datetime.strptime(rawItemDate[:-4], '%Y/%m/%d %H:%M:%S')
                    # Check if the item date is earlier than or equal to thirty days ago.
                    # If so write it with 'alertText' style
                    if itemDate.date() <= (todayDate - datetime.timedelta(days=30)):
                        panCore.worksheet.write(row, col, firewallDetails[device]['system'][item], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
                    else:
                        panCore.worksheet.write(row, col, firewallDetails[device]['system'][item])
        else:
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row += 1
panCore.logging.info("Finished Writing Firewall Details worksheet\n")

panCore.logging.info("Writing Dynamic Content Update Schedule worksheet:")
panCore.headers = []
for device in firewallDetails:
    for header in firewallDetails[device]['schedules'].keys():
        if header not in panCore.headers:
            panCore.headers.extend([header])
panCore.worksheet = panCore.workbook_obj.add_worksheet("Update Schedules")
panCore.worksheet.write(0, 0, "Serial #", panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
panCore.worksheet.write(0, 1, "Hostname", panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
panCore.worksheet.write_row(0, 2, sorted(panCore.headers), panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
msg = '--> Writing Dynamic Content Schedule for {0} on row {1}'
for device in firewallDetails:
    panCore.worksheet.write(row, 0, device)
    panCore.worksheet.write(row, 1, firewallDetails[device]['system']['hostname'])
    col = 2
    panCore.logging.info(msg.format(device, row))
    for item in sorted(panCore.headers):
        if item in firewallDetails[device]['schedules']:
            panCore.worksheet.write(row, col, firewallDetails[device]['schedules'][item])
        else:
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row += 1
panCore.logging.info("Finished Writing Dynamic Content Update Schedule worksheet\n")

panCore.logging.info("Writing Cluster Inventory worksheet:")
panCore.headers = ['clusterGUID', 'clusterMember', 'passiveLinkStateMatchesPeer', 'enabled', 'mode', 'running-sync', 'running-sync-enabled']
for cluster in clusterDetails:
    for node in clusterDetails[cluster]:
        for key in clusterDetails[cluster][node]['haConfig']['local-info'].keys():
            header = 'local-info.' + key
            if header not in panCore.headers:
                panCore.headers.extend([header])
        for key in clusterDetails[cluster][node]['haConfig']['peer-info'].keys():
            header = 'peer-info.' + key
            if header not in panCore.headers:
                panCore.headers.extend([header])
        for key in clusterDetails[cluster][node]['haConfig']['link-monitoring'].keys():
            header = 'link-monitoring.' + key
            if header not in panCore.headers:
                panCore.headers.extend([header])
        for key in clusterDetails[cluster][node]['haConfig']['path-monitoring'].keys():
            header = 'path-monitoring.' + key
            if header not in panCore.headers:
                panCore.headers.extend([header])

panCore.worksheet = panCore.workbook_obj.add_worksheet("ClusterShowHA-All")
panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
msg = "--> Writing cluster inventory for cluster member {0} of cluster group {1} on row {2}"
for clusterGUID in clusterDetails:
    for device in clusterDetails[clusterGUID]:
        panCore.logging.info(msg.format(device, clusterGUID, row))
        col = 0
        for item in panCore.headers:
            if item in clusterDetails[clusterGUID][device]['haConfig']:
                panCore.worksheet.write(row, col, clusterDetails[clusterGUID][device]['haConfig'][item])
            elif item.replace('local-info.','') in clusterDetails[clusterGUID][device]['haConfig']['local-info']:
                panCore.worksheet.write(row, col, clusterDetails[clusterGUID][device]['haConfig']['local-info'][item.replace('local-info.','')])
            elif item.replace('peer-info.', '') in clusterDetails[clusterGUID][device]['haConfig']['peer-info']:
                panCore.worksheet.write(row, col, clusterDetails[clusterGUID][device]['haConfig']['peer-info'][item.replace('peer-info.', '')])
            elif item.replace('link-monitoring.', '') in clusterDetails[clusterGUID][device]['haConfig']['link-monitoring']:
                panCore.worksheet.write(row, col, clusterDetails[clusterGUID][device]['haConfig']['link-monitoring'][item.replace('link-monitoring.', '')])
            elif item.replace('path-monitoring.', '') in clusterDetails[clusterGUID][device]['haConfig']['path-monitoring']:
                panCore.worksheet.write(row, col, clusterDetails[clusterGUID][device]['haConfig']['path-monitoring'][item.replace('path-monitoring.', '')])
            else:
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
        panCore.worksheet.write(row, 0, clusterGUID, panCore.workbook_obj.add_format((panExcelStyles.styles['normalText'])))
        panCore.worksheet.write(row, 1, device, panCore.workbook_obj.add_format((panExcelStyles.styles['normalText'])))
        if clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'] == "Mismatch between peers":
            panCore.worksheet.write(row, 2, clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'], panCore.workbook_obj.add_format((panExcelStyles.styles['alertText'])))
        elif clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'] == "Peer Device Not Audited":
            panCore.worksheet.write(row, 2, clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'], panCore.workbook_obj.add_format((panExcelStyles.styles['alertText'])))
        elif clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'] == "both shutdown":
            panCore.worksheet.write(row, 2, clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'], panCore.workbook_obj.add_format((panExcelStyles.styles['warnText'])))
        else:
            panCore.worksheet.write(row, 2, clusterDetails[clusterGUID][device]['passiveLinkStateMatchesPeer'], panCore.workbook_obj.add_format((panExcelStyles.styles['normalText'])))
        row += 1
panCore.logging.info("Finished Writing Cluster Inventory worksheet\n")

panCore.logging.info("Writing LinkMonitoring worksheet:")
panCore.headers = ['clusterSerial', 'clusterMember', 'linkMonitoringMatch', 'linkMonitorEnabled', 'linkMonitorFailCond',
           'linkGroupName', 'groupMemberDown', 'linkGroupEnabled', 'linkGroupFailCond', 'linkGroupInterfaces']
panCore.worksheet = panCore.workbook_obj.add_worksheet("HALinkGroups")
panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
panCore.worksheet.set_column(0, 0, 30, panCore.workbook_obj.add_format(panExcelStyles.styles['vAlignCenter']))
# Set column 0 through 0 to width 30 and align center.
panCore.worksheet.set_column(1, 9, 20, panCore.workbook_obj.add_format(panExcelStyles.styles['vAlignCenter']))
# Set column 1 through 9 width 20 and align center.
row = 1
msg = "--> Writing HA Link Group inventory for link group {0} on cluster member {1} of cluster group {2} at row {3}"
for cluster in clusterDetails:
    for node in clusterDetails[cluster]:
        #Accomodate cloud-hosted VMs where 'link-monitoring' XML xpath does not exist
        if 'link-monitoring' not in clusterDetails[cluster][node].keys():
            panCore.worksheet.write(row, 0, cluster)
            panCore.worksheet.write(row, 0, node)
            panCore.worksheet.merge_range(row, 2, row, 9, "N/A - Link monitoring doesn't exist for this cluster.")
            row = row+1
            continue
        else:
            endRow = max(
                row + len(clusterDetails[cluster][node]['link-monitoring']['groups']) - 1,
                row + 1)
        panCore.worksheet.merge_range(row, 0, endRow, 0, cluster)
        panCore.worksheet.merge_range(row, 1, endRow, 1, node)
        if clusterDetails[cluster][node]['linkMonitoringMatchesPeer']:
            panCore.worksheet.merge_range(row, 2, endRow, 2, clusterDetails[cluster][node][
                'linkMonitoringMatchesPeer'])
        else:
            panCore.worksheet.merge_range(row, 2, endRow, 2, clusterDetails[cluster][node][
                'linkMonitoringMatchesPeer'], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
        panCore.worksheet.merge_range(row, 3, endRow, 3,
                              clusterDetails[cluster][node]['link-monitoring'][
                                  'linkMonitorEnabled'])
        panCore.worksheet.merge_range(row, 4, endRow, 4,
                              clusterDetails[cluster][node]['link-monitoring'][
                                  'linkMonitorFailCond'])
        if len(clusterDetails[cluster][node]['link-monitoring']['groups']) >= 1:
            for intGroup in clusterDetails[cluster][node]['link-monitoring']['groups']:
                panCore.logging.info(msg.format(intGroup, node, cluster, row))
                panCore.worksheet.write(row, 5, intGroup)
                if \
                clusterDetails[cluster][node]['link-monitoring']['groups'][intGroup][
                    'groupMemberDown'] == "No":
                    panCore.worksheet.write(row, 6, "No")
                else:
                    panCore.worksheet.write(row, 6, "Yes", panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
                panCore.worksheet.write(row, 7,
                                clusterDetails[cluster][node]['link-monitoring'][
                                    'groups'][intGroup]['groupEnabled'])
                panCore.worksheet.write(row, 8,
                                clusterDetails[cluster][node]['link-monitoring'][
                                    'groups'][intGroup]['groupFailCond'])
                interfaceMemo = ""
                i = 1
                for iface in \
                clusterDetails[cluster][node]['link-monitoring']['groups'][intGroup][
                    'Interfaces']:
                    interfaceMemo += iface + " (" + \
                                     clusterDetails[cluster][node]['link-monitoring'][
                                         'groups'][intGroup]['Interfaces'][iface] + ")"
                    if i < len(clusterDetails[cluster][node]['link-monitoring'][
                                   'groups'][intGroup]['Interfaces']):
                        interfaceMemo += "\n"
                    else:
                        pass
                    i += 1
                panCore.worksheet.write(row, 9, interfaceMemo, panCore.workbook_obj.add_format(panExcelStyles.styles['wrappedText']))
                row = row + 1
        else:
            panCore.worksheet.merge_range(row, 5, row, 9, "NotConfigured", panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
        row = endRow + 1
panCore.logging.info("Finished writing Link Monitoring worksheet\n")

panCore.logging.info("Writing firewall interface (Logical) worksheet\n")
panCore.headers = ['fwName']
for device in firewallDetails:
    for interface in firewallDetails[device]['interfaces']['logical']:
        for header in firewallDetails[device]['interfaces']['logical'][interface].keys():
            if header not in panCore.headers:
                panCore.headers.extend([header])


panCore.logging.info("Writing zone info worksheet.")
panCore.worksheet = panCore.workbook_obj.add_worksheet("zoneInfo")
panCore.logging.info("--> Writing 'Zones with multiple configs' report section.")
panCore.headers = ['name','configNum', 'firewallsUsingZone']
for zoneName in zoneReport['zonesWithMultipleConfigs']:
    for config in zoneList[zoneName].keys():
        for keyName in zoneList[zoneName][config]['config'].keys():
            if keyName not in panCore.headers:
                panCore.headers.extend([keyName])

width = len(panCore.headers)
panCore.worksheet.merge_range(0, 0, 0,width-1,"Zones with Multiple Configs", panCore.workbook_obj.add_format(panExcelStyles.styles['label']))
panCore.worksheet.write_row(1,0,panCore.headers,panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 2
for zoneName in zoneReport['zonesWithMultipleConfigs']:
    for configNum in zoneList[zoneName].keys():
        col = 0
        for item in panCore.headers:
            if item == "configNum":
                panCore.worksheet.write(row,col,configNum)
            elif item == "firewallsUsingZone":
                panCore.worksheet.write(row,col,str(zoneList[zoneName][configNum]['firewalls']))
            elif item not in zoneList[zoneName][configNum]['config'].keys():
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            else:
                panCore.worksheet.write(row, col, zoneList[zoneName][configNum]['config'][item])
            col += 1
        row += 1

panCore.logging.info("--> Writing 'Zones without interfaces' report section.")
panCore.headers = ['name', 'firewall']
row += 2
panCore.worksheet.merge_range(row,0,row,2,"Zones without Interfaces",panCore.workbook_obj.add_format(panExcelStyles.styles['label']))
row += 1
panCore.worksheet.write(row,0,"Name",panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
panCore.worksheet.merge_range(row,1,row,2,"Firewalls",panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row += 1
for zoneKey in zoneReport['zonesWithoutInterfaces']:
    panCore.worksheet.write(row,0,zoneReport['zonesWithoutInterfaces'][zoneKey]['zoneName'])
    panCore.worksheet.merge_range(row, 1, row, 2, str(zoneReport['zonesWithoutInterfaces'][zoneKey]['zoneFirewalls']))
    row += 1
row += 2

panCore.logging.info("-- > Writing 'All zones' report section.")
panCore.headers = ['name','configNum', 'firewallsUsingZone']
for zoneName in zoneList.keys():
    for config in zoneList[zoneName].keys():
        for keyName in zoneList[zoneName][config]['config'].keys():
            if keyName not in panCore.headers:
                panCore.headers.extend([keyName])

width = len(panCore.headers)
panCore.worksheet.merge_range(row, 0, row,width-1,"All Zones", panCore.workbook_obj.add_format(panExcelStyles.styles['label']))
row += 1
panCore.worksheet.write_row(row,0,panCore.headers,panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row += 1
for zoneName in zoneList.keys():
    for configNum in zoneList[zoneName].keys():
        col = 0
        for item in panCore.headers:
            if item == "configNum":
                panCore.worksheet.write(row,col,configNum)
            elif item == "firewallsUsingZone":
                panCore.worksheet.write(row,col,str(zoneList[zoneName][configNum]['firewalls']))
            elif item not in zoneList[zoneName][configNum]['config'].keys():
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            else:
                panCore.worksheet.write(row, col, zoneList[zoneName][configNum]['config'][item])
            col += 1
        row += 1

panCore.headers = ['fwName']
for device in firewallDetails:
    for interface in firewallDetails[device]['interfaces']['logical']:
        for key in firewallDetails[device]['interfaces']['logical'][interface].keys():
            if key not in panCore.headers:
                panCore.headers.append(key)


panCore.worksheet = panCore.workbook_obj.add_worksheet("NetworkInterfaces-Logical")
panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
msg = '--> Writing logical network interface {0} on row {1}'
for device in firewallDetails:
    fwName = firewallDetails[device]['system']['hostname']
    for interface in firewallDetails[device]['interfaces']['logical']:
        col = 0
        panCore.logging.info(msg.format(interface,row))
        for item in panCore.headers:
            if item == 'fwName':
                panCore.worksheet.write(row,col,fwName)
            elif item not in firewallDetails[device]['interfaces']['logical'][interface].keys():
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            else:
                panCore.worksheet.write(row,col,firewallDetails[device]['interfaces']['logical'][interface][item])
            col += 1
        row += 1
panCore.logging.info("Finished writing interface (Logical) worksheet\n")

panCore.logging.info("Writing firewall interface (Hardware) worksheet\n")
panCore.headers = ['fwName']
for device in firewallDetails:
    for interface in firewallDetails[device]['interfaces']['hardware']:
        for header in firewallDetails[device]['interfaces']['hardware'][interface].keys():
            if header not in panCore.headers:
                panCore.headers.extend([header])

panCore.worksheet = panCore.workbook_obj.add_worksheet("NetworkInterfaces-Hardware")
panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
msg = '--> Writing Hardware network interface {0} on row {1}'
for device in firewallDetails:
    fwName = firewallDetails[device]['system']['hostname']
    for interface in firewallDetails[device]['interfaces']['hardware']:
        col = 0
        panCore.logging.info(msg.format(interface, row))
        for item in panCore.headers:
            if item == 'fwName':
                panCore.worksheet.write(row,col,fwName)
            elif item not in firewallDetails[device]['interfaces']['hardware'][interface].keys():
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            else:
                panCore.worksheet.write(row,col,firewallDetails[device]['interfaces']['hardware'][interface][item])
            col += 1
        row += 1
panCore.logging.info("Finished writing interface (Hardware) worksheet\n")

if args[0].interfaces:
    panCore.logging.info("Writing firewall interface (Details) worksheet\n")
    panCore.headers = ['fwName','ifnet.name','ifnet.zone','ifnet.mode']
    for device in firewallDetails:
        for interface in firewallDetails[device]['interfaces']['fullDetails']:
            for header in firewallDetails[device]['interfaces']['fullDetails'][interface].keys():
                if header not in panCore.headers:
                    panCore.headers.extend([header])

    panCore.worksheet = panCore.workbook_obj.add_worksheet("NetworkInterfaces-fullDetails")
    panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
    row = 1
    msg = '--> Writing fullDetails of network interface {0} on row {1}'
    for device in firewallDetails:
        fwName = firewallDetails[device]['system']['hostname']
        for interface in firewallDetails[device]['interfaces']['fullDetails']:
            col = 0
            panCore.logging.info(msg.format(interface, row))
            for item in panCore.headers:
                if item == 'fwName':
                    panCore.worksheet.write(row, col, fwName)
                elif item not in firewallDetails[device]['interfaces']['fullDetails'][interface].keys():
                    panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
                else:
                    panCore.worksheet.write(row, col, firewallDetails[device]['interfaces']['fullDetails'][interface][item])
                col += 1
            row += 1
    panCore.logging.info("Finished writing interface (Full Details) worksheet\n")



panCore.logging.info("Writing firewall Environmental Details worksheet\n")
panCore.headers = {}
for fwModel in fwDetailsByModel.keys():
    for device in fwDetailsByModel[fwModel]:
        panCore.headers[fwModel] = ['fwName','fwModel']
        for header in fwDetailsByModel[fwModel][device]['environmentals']:
            if (header not in panCore.headers[fwModel]) and ('.description' not in header):
                panCore.headers[fwModel].extend([header])

panCore.worksheet = panCore.workbook_obj.add_worksheet("SystemEnvironmentals")
row = 0
msg = '    --> Writing environmental details for {0} on row {1}'
for fwModel in fwDetailsByModel:
    col = 0
    panCore.logging.info(f" -- > Begining report section for {fwModel} on row {row}")
    panCore.worksheet.write_row(row, col, panCore.headers[fwModel], panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
    row += 1
    for device in fwDetailsByModel[fwModel]:
        fwName = firewallDetails[device]['system']['hostname']
        fwModel = firewallDetails[device]['system']['model']
        panCore.logging.info(msg.format(fwName, row))
        col = 0
        for item in panCore.headers[fwModel]:
            if item == 'fwName':
                panCore.worksheet.write(row, col, fwName)
            elif item == 'fwModel':
                panCore.worksheet.write(row, col, fwModel)
            elif item not in firewallDetails[device]['environmentals'].keys():
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            elif ".alarm" in item and firewallDetails[device]['environmentals'][item] == "True":
                panCore.worksheet.write(row, col, firewallDetails[device]['environmentals'][item], panCore.workbook_obj.add_format((panExcelStyles.styles['alertText'])))
            else:
                panCore.worksheet.write(row, col,firewallDetails[device]['environmentals'][item])
            col += 1
        row += 1
    row += 5  # Skip 5 rows when transition from one model to another
panCore.logging.info("Finished writing firewall Environmental Details worksheet\n")

if args[0].systemstate:
    panCore.logging.info("Writing firewall system state spreadsheet.")
    panCore.headers = ['FW Name']
    for device in firewallDetails:
        for key in firewallDetails[device]['systemState'].keys():
            if key not in panCore.headers:
                panCore.headers.append(key)
    panCore.worksheet = panCore.workbook_obj.add_worksheet("System State Details")
    msg = '--> Writing system state details for {0} on row {1}'
    panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
    panCore.headers.remove('FW Name')
    row = 1
    for device in firewallDetails:
        fwName = firewallDetails[device]['system']['hostname']
        panCore.logging.info(msg.format(fwName, row))
        panCore.worksheet.write(row, 0, firewallDetails[device]['system']['hostname'])
        col = 1
        for key in panCore.headers:
            if key in firewallDetails[device]['systemState'].keys():
                panCore.worksheet.write(row, col, firewallDetails[device]['systemState'][key])
                col += 1
            else:
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
                col +=1
        row +=1

panCore.logging.info("Writing Firewall syslog profile summary worksheet...")
panCore.worksheet = panCore.workbook_obj.add_worksheet("SyslogProfiles_Summary")
panCore.worksheet.write_row("A1",['Name', 'Number', 'Address', 'Port', 'Protocol', 'Format', 'Facility', 'FirewallCount', 'FirewallList'], panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for syslogProfile in sorted(profileData['syslog']):
    panCore.logging.info(f"Writing {profileData['syslog'][syslogProfile]['name']} profile data to row {row}")
    panCore.worksheet.write(row, 0, profileData['syslog'][syslogProfile]['name'])
    panCore.worksheet.write(row, 1, profileData['syslog'][syslogProfile]['count'])
    panCore.worksheet.write(row, 2, profileData['syslog'][syslogProfile]['config']['server'])
    panCore.worksheet.write(row, 3, profileData['syslog'][syslogProfile]['config']['port'])
    panCore.worksheet.write(row, 4, profileData['syslog'][syslogProfile]['config']['transport'])
    panCore.worksheet.write(row, 5, profileData['syslog'][syslogProfile]['config']['format'])
    panCore.worksheet.write(row, 6, profileData['syslog'][syslogProfile]['config']['facility'])
    panCore.worksheet.write(row, 7, len(profileData['syslog'][syslogProfile]['firewalls']))
    panCore.worksheet.write(row, 8, str(profileData['syslog'][syslogProfile]['firewalls']))
    row += 1

panCore.logging.info("Writing Firewall syslog profile details worksheet...")
panCore.worksheet = panCore.workbook_obj.add_worksheet("SyslogProfiles_Details2")
panCore.headers = ['fwName', 'Profile', 'ServerName' ]
syslogDetailsHeaders = []
for device in firewallDetails:
    if firewallDetails[device]['syslogProfiles']:
        for profile in firewallDetails[device]['syslogProfiles']:
            for server in firewallDetails[device]['syslogProfiles'][profile]['servers']:
                for key in firewallDetails[device]['syslogProfiles'][profile]['servers'][server].keys():
                    if key not in panCore.headers:
                        panCore.headers.append(key)
                        syslogDetailsHeaders.append(key)
panCore.headers.append('customFormat')
panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for device in firewallDetails:
    if firewallDetails[device]['syslogProfiles']:
        for syslogProfile in firewallDetails[device]['syslogProfiles']:
            for syslogServer in firewallDetails[device]['syslogProfiles'][syslogProfile]['servers']:
                panCore.worksheet.write(row, 0, firewallDetails[device]['system']['hostname'])
                panCore.worksheet.write(row, 1, syslogProfile)
                panCore.worksheet.write(row, 2, syslogServer)
                col = 3
                for header in syslogDetailsHeaders:
                    if header not in firewallDetails[device]['syslogProfiles'][syslogProfile]['servers'][syslogServer].keys():
                        panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
                    else:
                        panCore.worksheet.write(row, col, firewallDetails[device]['syslogProfiles'][syslogProfile]['servers'][syslogServer][header])
                    col += 1
                row +=1
            startRow = (row - len(firewallDetails[device]['syslogProfiles'][syslogProfile]['servers']))
            if row-1 == startRow:
                panCore.worksheet.write(startRow, col, str(firewallDetails[device]['syslogProfiles'][syslogProfile]['customFormats']))
            else:
                panCore.worksheet.merge_range(startRow, col, row-1, col, str(firewallDetails[device]['syslogProfiles'][syslogProfile]['customFormats']))


panCore.logging.info("Writing Device log output summary worksheet")
panCore.worksheet = panCore.workbook_obj.add_worksheet("LogOutputs_Summary")
panCore.worksheet.write_row("A1", ['OutputName', 'Number', 'LogType', 'Description', 'Filter', 'Panorama', 'SNMP', 'E-mail', 'Syslog', 'HTTP', 'FirewallCount', 'firewalls'], panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for logOutput in sorted(profileData['logOutputs']):
    panCore.logging.info(f"Writing {profileData['logOutputs'][logOutput]['name']} Output data to row {row}")
    panCore.worksheet.write(row, 0, profileData['logOutputs'][logOutput]['name'])
    panCore.worksheet.write(row, 1, profileData['logOutputs'][logOutput]['count'])
    panCore.worksheet.write(row, 2, profileData['logOutputs'][logOutput]['config']['logType'])
    panCore.worksheet.write(row, 3, profileData['logOutputs'][logOutput]['config']['ruleDescription'])
    panCore.worksheet.write(row, 4, profileData['logOutputs'][logOutput]['config']['ruleFilter'])
    if 'send-to-panorama' in profileData['logOutputs'][logOutput]['config']['destinations'].keys():
        panCore.worksheet.write(row, 5, "True")
    else:
        panCore.worksheet.write(row, 5, "False")
    if 'send-snmptrap' in profileData['logOutputs'][logOutput]['config']['destinations'].keys():
        panCore.worksheet.write(row, 6, str(
            profileData['logOutputs'][logOutput]['config']['destinations']['send-snmptrap']))
    else:
        panCore.worksheet.write(row, 6, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    if 'send-email' in profileData['logOutputs'][logOutput]['config']['destinations'].keys():
        panCore.worksheet.write(row, 7, str(
            profileData['logOutputs'][logOutput]['config']['destinations']['send-email']))
    else:
        panCore.worksheet.write(row, 7, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    if 'send-syslog' in profileData['logOutputs'][logOutput]['config']['destinations'].keys():
        panCore.worksheet.write(row, 8, str(
            profileData['logOutputs'][logOutput]['config']['destinations']['send-syslog']))
    else:
        panCore.worksheet.write(row, 8, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    if 'send-http' in profileData['logOutputs'][logOutput]['config']['destinations'].keys():
        panCore.worksheet.write(row, 9, str(
            profileData['logOutputs'][logOutput]['config']['destinations']['send-http']))
    else:
        panCore.worksheet.write(row, 9, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    panCore.worksheet.write(row, 10, len(profileData['logOutputs'][logOutput]['firewalls']))
    panCore.worksheet.write(row, 11, str(profileData['logOutputs'][logOutput]['firewalls']))
    row += 1

panCore.logging.info("Writing device log output inventory spreadsheet.")
panCore.headers = ['FW_Name', 'LogType', 'OutputName', 'Description', 'Filter', 'Panorama', 'SNMP', 'E-Mail', 'Syslog', 'HTTP']
panCore.worksheet = panCore.workbook_obj.add_worksheet("LogOutputs")

panCore.worksheet.write_row("A1", panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))

row = 1
for device in firewallDetails:
    fwName = firewallDetails[device]['system']['hostname']
    for logType in firewallDetails[device]['deviceLogOutputs']:
        for rule in firewallDetails[device]['deviceLogOutputs'][logType]:
            panCore.logging.info(f"  --> Writing rule ({rule}) output data for {logType} logs output from {fwName} on row {row}")
            panCore.worksheet.write(row, 0, firewallDetails[device]['system']['hostname'])
            panCore.worksheet.write(row, 1, logType)
            panCore.worksheet.write(row, 2, rule)
            panCore.worksheet.write(row, 3, firewallDetails[device]['deviceLogOutputs'][logType][rule]['ruleDescription'])
            panCore.worksheet.write(row, 4, firewallDetails[device]['deviceLogOutputs'][logType][rule]['ruleFilter'])
            if 'send-to-panorama' in firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations'].keys():
                panCore.worksheet.write(row, 5, "True")
            else:
                panCore.worksheet.write(row, 5, "False")
            if 'send-snmptrap' in firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations'].keys():
                panCore.worksheet.write(row, 6, str(firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations']['send-snmptrap']))
            else:
                panCore.worksheet.write(row, 6, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            if 'send-email' in firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations'].keys():
                panCore.worksheet.write(row, 7, str(firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations']['send-email']))
            else:
                panCore.worksheet.write(row, 7, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            if 'send-syslog' in firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations'].keys():
                panCore.worksheet.write(row, 8, str(firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations']['send-syslog']))
            else:
                panCore.worksheet.write(row, 8, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            if 'send-http' in firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations'].keys():
                panCore.worksheet.write(row, 9, str(firewallDetails[device]['deviceLogOutputs'][logType][rule]['destinations']['send-http']))
            else:
                panCore.worksheet.write(row, 9, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            row += 1

if args[0].license:
    panCore.logging.info("Writing device license spreadsheet.")
    headers = []
    for device in firewallDetails:
        for header in firewallDetails[device]['licensing'].keys():
            if header not in headers:
                headers.append(header)
    panCore.worksheet = panCore.workbook_obj.add_worksheet("Licensing")
    panCore.worksheet.write_row("A1", ["Hostname", "Serial"] + headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
    row = 1
    for device in firewallDetails:
        panCore.worksheet.write(row, 0, firewallDetails[device]['system']['hostname'])
        panCore.worksheet.write(row, 1, firewallDetails[device]['system']['serial'])
        col = 2
        for header in headers:
            if header in firewallDetails[device]['licensing']:
                if header.endswith('.expired') and (firewallDetails[device]['licensing'][header].lower() == 'yes' or firewallDetails[device]['licensing'][header].lower() == 'true'):
                    panCore.worksheet.write(row, col, firewallDetails[device]['licensing'][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
                else:
                    panCore.worksheet.write(row, col, firewallDetails[device]['licensing'][header])
            else:
                panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
        row +=1


panCore.logging.info("Writing template worksheet.")
headers = ['name', 'description', 'devices']
for tplName in tplData['templates'].keys():
    for header in tplData['templates'][tplName]['config'].keys():
        if header not in headers:
            headers.append(header)
extHeaders = ['used in', ' ']
for i in range(1,tplData['tplVarCount']):
    extHeaders.extend([f"Var{i}.name", f"Var{i}.Type", f"Var{i}.Value"])
panCore.worksheet = panCore.workbook_obj.add_worksheet("Templates")
panCore.worksheet.write_row("A1", headers + extHeaders, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for template in tplData['templates'].keys():
    col = 0
    for header in headers:
        if header in tplData['templates'][template]['config'].keys():
            panCore.worksheet.write(row, col, tplData['templates'][template]['config'][header])
        else:
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    panCore.worksheet.write(row, col, ", ".join(tplData['templates'][template]['usedIn']))
    col += 1
    panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    col += 1
    for i in range(1,tplData['tplVarCount']):
        if i in tplData['templates'][template]['variables'].keys():
            panCore.worksheet.write(row, col, tplData['templates'][template]['variables'][i]['name'])
            col += 1
            panCore.worksheet.write(row, col, tplData['templates'][template]['variables'][i]['variable_type'])
            col += 1
            panCore.worksheet.write(row, col, tplData['templates'][template]['variables'][i]['value'])
            col += 1
        else:
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
    row += 1

panCore.logging.info("Writing template stack worksheet.")
headers = ['name', 'description', 'devices', 'templates']
for stkName in tplData['stacks'].keys():
    for header in tplData['stacks'][stkName]['config'].keys():
        if header not in headers:
            headers.append(header)
extHeaders = [' ']
for i in range(1,tplData['stkVarCount']):
    extHeaders.extend([f"Var{i}.name", f"Var{i}.Type", f"Var{i}.Value"])
panCore.worksheet = panCore.workbook_obj.add_worksheet("Template Stacks")
panCore.worksheet.write_row("A1", headers + extHeaders, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for stack in tplData['stacks'].keys():
    col = 0
    for header in headers:
        if header in tplData['stacks'][stack]['config'].keys():
            if type(tplData['stacks'][stack]['config'][header]) is list:
                panCore.worksheet.write(row, col, ", ".join(tplData['stacks'][stack]['config'][header]))
            else:
                panCore.worksheet.write(row, col, tplData['stacks'][stack]['config'][header])
        else:
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    col += 1
    for i in range(1,tplData['stkVarCount']):
        if i in tplData['stacks'][stack]['variables'].keys():
            panCore.worksheet.write(row, col, tplData['stacks'][stack]['variables'][i]['name'])
            col += 1
            panCore.worksheet.write(row, col, tplData['stacks'][stack]['variables'][i]['variable_type'])
            col += 1
            panCore.worksheet.write(row, col, tplData['stacks'][stack]['variables'][i]['value'])
            col += 1
        else:
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
            panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
            col += 1
    row += 1
panCore.workbook_obj.close()
