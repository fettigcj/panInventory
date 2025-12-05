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
    2023-02-02 - Creation Date
    2023-02-07 - Finished audit + Export-to-execl functionality. Separating 'pseudo' passive from 'passive' may hinder analysis. will probably merge in later revision.
    2023-02-09 - Aesthetic cleanup, standardized 'no username or key found' section and corrected var1[:-5] to var1[:-3] typo in passive override report section.
    2024-04-04 - Added Panorama templateStack analysis to show where config is set and allow spotting templates which override one another.
"""

from pancore import panCore, panExcelStyles
import datetime, sys, argparse

parser = argparse.ArgumentParser(
    prog="PanInventory",
    description="Audit Panorama & connected firewalls to generate reports on system state & health")
    #epilog="Text")

parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='OverrideFinder.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='Overrides.xlsx')
args, _ = parser.parse_known_args()

logger = panCore.startLogging(args.logfile)
panCore.configStart(headless=args.headless, configStorage=args.conffile)

if hasattr(panCore, 'panUser'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, 'panKey'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    panCore.logging.critical("Found neither username/password nor API key. Exiting.")
    sys.exit()

def mainProc(fw_obj):
    overrides = {}
    global fwNum, fwCount
    fwAuditStartTime = datetime.datetime.now(datetime.timezone.utc)
    panCore.logging.info(f"Begining audit of {fw_obj.serial}")
    sysInfo = fw_obj.show_system_info()
    serialNumber = sysInfo['system']['serial']
    hostname = sysInfo['system']['hostname']
    panCore.logging.info(f"  {hostname} ({fwNum}/{fwCount}) connected. {fwAuditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    overrides = {'sysInfo': sysInfo['system'],
                               'activeOverrides': {},
                               'pseudoPassiveOverrides': {},
                               'passiveOverrides': {}}
    panCore.logging.info("    Getting local config.")
    time1 = datetime.datetime.now(datetime.timezone.utc)
    localConfig = panCore.xmlToLXML(fw_obj.xapi.get('/config'))
    time2 = datetime.datetime.now(datetime.timezone.utc)
    panCore.logging.info("    Getting panorama config.")
    templateConfig = panCore.xmlToLXML(fw_obj.xapi.get('/config/template/config'))
    time3 = datetime.datetime.now(datetime.timezone.utc)
    panCore.logging.info(
        f"    Got local config in {round(((time2 - time1).total_seconds()), 4)} seconds.\n    Got Panorama config in {round(((time3 - time2).total_seconds()), 4)} seconds.\n    Starting comparison.")
    localTree = panCore.ET.ElementTree(localConfig)
    for node in localConfig.iter():
        nodePath = localTree.getpath(node)
        if templateConfig.xpath(nodePath):
            tplNode = templateConfig.xpath(nodePath)[0]
            nodeAttrib = node.attrib
            tplAttrib = tplNode.attrib
            # Handle none types where text is null
            # Strip strings to eliminate non-printing character issues.
            if node.text:
                nodeText = node.text.strip()
            else:
                nodeText = ""
            if tplNode.text:
                tplText = tplNode.text.strip()
            else:
                tplText = ""
            if 'src' in nodeAttrib.keys() and nodeAttrib['src'] == 'tpl':
                # Skip local config element that is declaratively sourced from a template (Not overridden)
                continue
            if (nodeAttrib == tplAttrib) and (nodeText == tplText):
                # print('passive Override')
                overrides['passiveOverrides'][nodePath] = {'Attributes': node.attrib,
                                                                         'Text': nodeText}
                # Record overrides where the local config isn't from the template, but the config is the same
                # as the template would apply were it able to.
                continue
            if ('ptpl' in tplAttrib.keys()) and ('ptpl' not in nodeAttrib.keys()):
                # print('pseudoPassive')
                del tplAttrib['ptpl']
                # Delete source 'panorama template' tag from template config to capture additional 'passive' override scenario
                if (nodeAttrib == tplAttrib) and (nodeText == tplText):
                    overrides['pseudoPassiveOverrides'][nodePath] = {'Attributes': node.attrib,
                                                                                   'Text': nodeText}
                    continue
                    # Record overrides where the local config would match the template config except for the notation
                    # of which panorama template the TPL config is from.
            overrides['activeOverrides'][nodePath] = {
                'lclAttributes': node.attrib,
                'tplAttributes': tplNode.attrib,
                'lclText': nodeText,
                'tplText': tplText}
    time4 = datetime.datetime.now(datetime.timezone.utc)
    panCore.logging.info(f"    Finished comparison in {round(((time4 - time3).total_seconds()), 4)} seconds.")
    return overrides


def templateOverrides():
    panCore.logging.info("Begining to gather Panorama template data to check for overrides within a template stack")
    panCore.headers = []
    panCore.devData = {}
    templates = panCore.xmlToLXML(pano_obj.xapi.get("/config/devices/entry[@name='localhost.localdomain']/template"))
    for template in templates.xpath('//template/entry'):
        templateName = template.get('name')
        panCore.logging.info(f"\t > Parsing XML data for {templateName}")
        panCore.devData[templateName] = {}
        for child in template.getchildren():
            panCore.iterator(child, templateName)
    allTemplates = panCore.devData
    panCore.logging.info("Got Template data. Beginning to parse template stack information")
    stackData = {}
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get("/config/devices/entry[@name='localhost.localdomain']/template-stack"))
    for stack in xmlData.xpath('.//template-stack/entry'):
        stackName = stack.get('name')
        stackData[stackName] = {}
        panCore.logging.info(f"\t > Parsing XML data for {stackName}")
        stackData[stackName]['members'] = []
        for tpl in stack.xpath('.//templates/member'):
            stackData[stackName]['members'].append(tpl.text)
        stackData[stackName]['members'].reverse()
        # Panorama returns the template list HIGHEST priority first.
        # Reversing lets us start our analysis from the least-specific, "default" value to more specific "override" value
        stackData[stackName]['headers'] = []
        for templateName in stackData[stackName]['members']:
            panCore.logging.info(f"\t\t > Parsing XML data for {templateName}")
            for xmlKey in allTemplates[templateName].keys():
                if xmlKey not in stackData[stackName]['headers']:
                    stackData[stackName]['headers'].append(xmlKey)
    return allTemplates, stackData


def writeFirewallData(overrides):
    fwName = overrides['sysInfo']['hostname']
    global overridesRows
    # Active overrides
    if len(overrides['activeOverrides']):
        for xpath in overrides['activeOverrides'].keys():
            if xpath in skipPath:
                continue
            lcl_attr = overrides['activeOverrides'][xpath]['lclAttributes']
            tpl_attr = overrides['activeOverrides'][xpath]['tplAttributes']
            lcl_attr_str = ""
            if len(lcl_attr):
                var1 = ""
                for key in lcl_attr:
                    var1 += f"{key}: {lcl_attr[key]} | "
                lcl_attr_str = var1[:-3]
            tpl_attr_str = ""
            if len(tpl_attr):
                var1 = ""
                for key in tpl_attr:
                    var1 += f"{key}: {tpl_attr[key]} | "
                tpl_attr_str = var1[:-3]
            overridesRows['active'].append([
                fwName,
                xpath.replace("/response/result", ""),
                overrides['activeOverrides'][xpath]['lclText'],
                overrides['activeOverrides'][xpath]['tplText'],
                lcl_attr_str,
                tpl_attr_str
            ])
    # Passive overrides
    if len(overrides['passiveOverrides']):
        for xpath in overrides['passiveOverrides']:
            if xpath in skipPath:
                continue
            attrib = overrides['passiveOverrides'][xpath]['Attributes']
            attrib_str = ""
            if len(attrib):
                var1 = ""
                for key in attrib:
                    var1 += f"{key}: {attrib[key]} | "
                attrib_str = var1[:-3]
            overridesRows['passive'].append([
                fwName,
                xpath.replace("/response/result", ""),
                overrides['passiveOverrides'][xpath]['Text'],
                attrib_str
            ])
    # Pseudo-passive overrides
    if len(overrides['pseudoPassiveOverrides']):
        for xpath in overrides['pseudoPassiveOverrides']:
            if xpath in skipPath:
                continue
            attrib = overrides['pseudoPassiveOverrides'][xpath]['Attributes']
            attrib_str = ""
            if len(attrib):
                var1 = ""
                for key in attrib:
                    var1 += f"{key}: {attrib[key]} | "
                attrib_str = var1[:-3]
            overridesRows['pseudo'].append([
                fwName,
                xpath.replace("/response/result", ""),
                overrides['pseudoPassiveOverrides'][xpath]['Text'],
                attrib_str
            ])


#Prep report gathering state & logging info
startTime = datetime.datetime.now(datetime.timezone.utc)
# Initialize workbook using new workbook module
from pancore import panWorkbookFunctions
workbook = panWorkbookFunctions.initXLSX(args.workbookname)
panCore.logging.info(f"Starting audit at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
fwCount = len(firewalls)
fwNum = 0
# Prepare in-memory collections for writer functions
overridesRows = {'active': [], 'passive': [], 'pseudo': []}
skipPath = ['/response', '/response/result']

for fw_obj in firewalls:
    fwNum += 1
    if not fw_obj.state.connected:
        panCore.logging.warning(f'Firewall {fw_obj.serial} ({fwNum}/{fwCount}) is not connected. Skipping.')
        continue
    try:
        overrides = mainProc(fw_obj)
        writeFirewallData(overrides)
    except Exception as e:
        panCore.logging.exception(f"Exception encountered: {e.message}")

allTemplates, stackData = templateOverrides()
# Delegate all worksheet creation/writing to panWorkbookFunctions (align with panInventory standards)
panWorkbookFunctions.writeWorksheet_Overrides(workbook, overridesRows)
panWorkbookFunctions.writeWorksheet_OverrideTemplateStacks(workbook, allTemplates, stackData)

endTime = datetime.datetime.now(datetime.timezone.utc)
panCore.logging.info(f"Finished gathering data from Panorama at {endTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}. (In {round((((endTime - startTime).total_seconds())/60),4)} minutes)")

workbook.close()