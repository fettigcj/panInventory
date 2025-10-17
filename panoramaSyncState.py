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
2024-03-01 File creation

Goals
Report panorama syncronization / issues:
    Call out uncommitted changes in Panorama
    Call out firewalls out of sync with Panorama Template
    Call out firewalls out of sync with Panorama Device Group
    Call out lack of HA sync
    Call out commit warnings
        - Errors
        - Warnings
        - App Dependencies
        - Rule Shadows
"""

import panos
from pancore import panCore, panExcelStyles
from panos.panorama import PanoramaCommitAll
import sys, json, ast
import datetime, argparse, time


parser = argparse.ArgumentParser(
    prog="panoSync",
    description="Audit Panorama & report out-of-sync issues")
    #epilog="Text")

"""
In order to have a default behavior of reports being "ENABLED" we default=True below, but then use "store_false" when 
 a flag is activated. This strange "enabling a negative" is counter-intuitive, but the reversed behavior upon 
 ENABLING the flag to DISABLE the report simplifies the user interactions and allows the default to be overruled 
 when the flag is used.
"""
parser.add_argument('-I', '--headless', help="Disable Interactions; operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='panoSync.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='panoSync.xlsx')
args = parser.parse_known_args()

todayDate = datetime.date.today()
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
panCore.logging.info(f"Beginning audit at {auditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
panCore.logging.info(f"Using 'show config list changes' to gather uncommitted changes from panorama at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
# Call out uncommitted changes in Panorama:
uncommittedChanges = {}
changeNumber = 1
xmlData = panCore.xmlToLXML(pano_obj.op('show config list changes'))
for change in xmlData.findall('.//journal/entry'):
    uncommittedChanges[changeNumber] = {}
    for changeElement in change.getchildren():
        uncommittedChanges[changeNumber][changeElement.tag] = changeElement.text
    changeNumber += 1

# Call out firewalls out of sync with Panorama Template:
panCore.logging.info(f"Using 'show templates' to gather template data at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
xmlData = panCore.xmlToLXML(pano_obj.op('show templates'))
templateSyncStates = {}
templateStackList = []
for template in xmlData.findall('.//templates/entry'):
    if template.find('./devices') is not None:
        tpl_Name = template.attrib['name']
        if template.xpath('./template-stack')[0].text == 'yes':
            tpl_Type = 'TemplateStack'
            templateStackList.append(tpl_Name)
        else:
            tpl_Type = 'Template'
        for device in template.findall('./devices/entry'):
            panCore.devData = {device.get('name'): {'templateName': tpl_Name,
                                                    'templateType': tpl_Type}}
            panCore.headers = []
            for child in device.getchildren():
                if len(child):
                    panCore.iterator(child, device.get('name'))
                else:
                    panCore.devData[device.get('name')][child.tag] = child.text
                    if child.tag not in panCore.headers:
                        panCore.headers.append(child.tag)
            templateSyncStates[device.get('name')] = panCore.devData[device.get('name')]


# Call out template stacks w/ local config data
panCore.logging.info(f"Gathering template config info for template stacks w/ devices assigned at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
templateStacks = {}
for templateStack in templateStackList:
    panCore.logging.info(f"\t> Gathering template stack config info for {templateStack}")
    templateConfig, templateDescription, templateDevices, templateSettings, templateMembers, templateUserIdentificationMasterDevice, templateVariables = [""] * 7
    templateConfigLineCount = 0
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='{templateStack}']"))
    tplCounter = len(xmlData.xpath('./result/entry/templates/member'))
    for tplMember in xmlData.xpath('./result/entry/templates/member'):
        templateMembers += f"{tplCounter}) {tplMember.text}"
        if tplCounter > 1:
            templateMembers += "\r\n"
        tplCounter -= 1
    tplCounter = 1
    for templateVariable in xmlData.xpath('./result/entry/variable/entry'):
        templateVariables += f"{tplCounter}) {templateVariable.get('name')} ({templateVariable[0][0].tag}) == {templateVariable[0][0].text}"
        if tplCounter < len(xmlData.xpath('./result/entry/variable/entry')):
            templateVariables += "\r\n"
        tplCounter += 1
    if len(xmlData.xpath('./result/entry/settings')) > 0:
        tplCounter = 1
        for templateSetting in xmlData.xpath('./result/entry/settings')[0].getchildren():
            templateSettings += f"{tplCounter}) {templateSetting.tag} == {templateSetting.text}"
            if tplCounter < len(xmlData.xpath('./result/entry/settings')[0].getchildren()):
                templateSettings += "\r\n"
            tplCounter += 1
    tplCounter = 1
    for device in xmlData.xpath('./result/entry/devices/entry'):
        templateDevices += device.get('name')
        if tplCounter < len(xmlData.xpath('./result/entry/devices/entry')):
            templateDevices += "\r\n"
        tplCounter += 1
    if len(xmlData.xpath('./result/entry/config')):
        templateConfig = panCore.ET.tostring(xmlData.xpath('./result/entry/config')[0], pretty_print=True).decode()
        templateConfigLineCount = len(templateConfig.splitlines())
    if len(xmlData.xpath('./result/entry/description')):
        templateDescription = xmlData.xpath('./result/entry/description')[0].text
    if len(xmlData.xpath('./result/entry/user-group-source/master-device/device')):
        templateUserIdentificationMasterDevice = xmlData.xpath('./result/entry/user-group-source/master-device/device')[0].text
    templateStacks[templateStack] = {
        'templateConfig': templateConfig,
        'templateConfigLineCount': templateConfigLineCount,
        'templateDescription': templateDescription,
        'templateDevices': templateDevices,
        'templateSettings': templateSettings,
        'templateMembers': templateMembers,
        'templateUserIdentificationMasterDevice': templateUserIdentificationMasterDevice,
        'templateVariables': templateVariables}



"""
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"/config/devices/entry[@name='localhost.localdomain']/template-stack"))
    for test in xmlData.xpath('./result/template-stack/entry/user-group-source'):
        print("************** CEBU *************")
        pp(panCore.ET.tostring(test, pretty_print=True).decode())
"""


# Call out firewalls out of sync with Panorama Device Group:
panCore.logging.info(f"Using 'show devicegroups' to gather device group data at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
dgWithDevices = []
xmlData = panCore.xmlToLXML(pano_obj.op('show devicegroups'))
deviceGroupSyncStates = {}
for deviceGroup in xmlData.findall('.//devicegroups/entry'):
    if deviceGroup.find('./devices') is not None:
        dg_Name = deviceGroup.attrib['name']
        dgWithDevices.append(dg_Name)
        for device in deviceGroup.findall('./devices/entry'):
            panCore.devData = {device.get('name'): {'deviceGroupName': dg_Name}}
            panCore.headers = []
            for child in device.getchildren():
                if len(child):
                    panCore.iterator(child, device.get('name'))
                else:
                    panCore.devData[device.get('name')][child.tag] = child.text
                    if child.tag not in panCore.headers:
                        panCore.headers.append(child.tag)
            deviceGroupSyncStates[device.get('name')] = panCore.devData[device.get('name')]

# Call out lack of HA sync
panCore.logging.info(f"Using 'show high-availability all' to gather HA data at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
xmlData = panCore.xmlToLXML(pano_obj.op('show high-availability all'))
panCore.devData = {'haAll': {}}
panCore.headers = []
for child in xmlData[0].getchildren():
    panCore.iterator(child, 'haAll')
highAvaialabilityState = panCore.devData


# Call out commit warnings
validateJobIDs = []
panCore.logging.info(f"Initiating 'Validate all' jobs to collect commit warnings, application dependency warnings, and rule shadowing messages at at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
for dgName in dgWithDevices:
    try:
        jobID = pano_obj.commit_all(cmd=f"<commit-all><shared-policy><description>Health Check Script Validation Job</description><include-template>yes</include-template><validate-only>yes</validate-only><device-group><entry name='{dgName}'/></device-group></shared-policy></commit-all>")
        if jobID.isdigit():
            validateJobIDs.append(int(jobID))
        panCore.logging.info(f"\t> Initiated validation job {jobID} for device group {dgName}")
    except Exception as exception_details:
        panCore.logging.exception(f"\t> Error encountered while initiating validation job for {dgName}")
        panCore.logging.exception(exception_details)
time.sleep(60)
finishedJobsXML = []
loopCount = 1
panCore.logging.info(f"Collecting validation job results from {len(validateJobIDs)} config/commit validation jobs.")
while len(validateJobIDs) > 0 and loopCount < 11:
    doneJobs = []
    panCore.logging.info(f"\t> {len(validateJobIDs)} jobs remaining. Collection/Wait loop #{loopCount} at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    for jobID in validateJobIDs:
        jobStatus = panCore.xmlToLXML(pano_obj.op(f"<show><jobs><id>{jobID}</id></jobs></show>", cmd_xml=False))
        if jobStatus.find('.//result/job/status').text.lower() == 'act':
            pass
        elif jobStatus.find('.//result/job/status').text.lower() == 'fin':
            finishedJobsXML.append(jobStatus)
            doneJobs.append(jobID)
        else:
            statusCode = jobStatus.find('.//result/job/status').text.lower()
            panCore.logging.error(f"Job {jobID} encountered job status other than 'fin' and 'act': {statusCode}")
    for jobID in doneJobs:
        validateJobIDs.remove(jobID)
    panCore.logging.info(f"\t\t> Finished loop #{loopCount} at {datetime.datetime.now(datetime.timezone.utc).strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    if len(validateJobIDs) and loopCount <10:
        panCore.logging.info(f"\t> {len(validateJobIDs)} were still incomplete during the previous loop. Waiting 60 seconds for additional jobs to complete and trying again...")
        time.sleep(60)
    else:
        panCore.logging.error(f"\t> {len(validateJobIDs)} job results remain outstanding after {loopCount} attempts to retrieve all completed jobs. Giving up on remaining jobs as we seem to be stuck in an infinite loop... Please investigate.")
    loopCount += 1

jobResults = {}
genericWarnings = {}
appDependencies = {}
rulesShadowed = {}
for jobData in finishedJobsXML:
    jobID = jobData.xpath('./result/job/id')[0].text
    panCore.devData = {jobID: {}}
    panCore.headers = []
    for child in jobData.xpath('./result/job')[0].getchildren():
        if child.tag != 'devices':
            panCore.iterator(child, jobID)
    jobResults[jobID] = panCore.devData[jobID]
    jobResults[jobID]['devices'] = {}
    for device in jobData.xpath('./result/job/devices/entry'):
        deviceSN = device.xpath('./serial-no')[0].text
        deviceName = device.xpath('./devicename')[0].text
        panCore.devData = {deviceSN: {}}
        panCore.headers = []
        for child in device.getchildren():
            #if child.tag != 'details':
            panCore.iterator(child, deviceSN)
        jobResults[jobID]['devices'][deviceSN] = panCore.devData[deviceSN]
        jobResults[jobID]['devices'][deviceSN]['errorLines'] = ""
        jobResults[jobID]['devices'][deviceSN]['warningLines'] = ""
        for errorLine in device.xpath('./details/msg/errors/line'):
            jobResults[jobID]['devices'][deviceSN]['errorLines'] = jobResults[jobID]['devices'][deviceSN]['errorLines'] + errorLine.text + "\r\n"
        for warningLine in device.xpath('./details/msg/warnings/line'):
            jobResults[jobID]['devices'][deviceSN]['warningLines'] = jobResults[jobID]['devices'][deviceSN]['warningLines'] + warningLine.text + "\r\n"
        genericWarnings[deviceSN] = {'serial': deviceSN,
                                     'hostname': deviceName,
                                     'errors': jobResults[jobID]['devices'][deviceSN]['errorLines'],
                                     'warnings': jobResults[jobID]['devices'][deviceSN]['warningLines']}
        for appWarning in device.xpath('./details/msg/app-warn/entry'):
            warningDict = ast.literal_eval(appWarning.text)
            ruleID = warningDict['uuid']
            for vsysListItem in warningDict['vsys']:
                ruleUsage = f"{deviceName} ({deviceSN}) - {vsysListItem['id']}"
                ruleData = {'ruleName': warningDict['rulename'],
                            'ruleType': warningDict['ruletype'],
                            'dependentApps': vsysListItem['dependent-apps']}
            if warningDict['uuid'] not in appDependencies.keys():
                appDependencies[ruleID] = {0: {'ruleData': ruleData,
                                               'ruleUsedIn': [ruleUsage]}}
            else:
                matchFound = False
                for ruleInstance in appDependencies[warningDict['uuid']].keys():
                    if appDependencies[ruleID][ruleInstance]['ruleData'] == ruleData:
                        appDependencies[ruleID][ruleInstance]['ruleUsedIn'].append(ruleUsage)
                        matchFound = True
                if not matchFound:
                    newID = max(appDependencies[warningDict['uuid']].keys()) + 1
                    appDependencies[ruleID] = {newID: {'ruleData': ruleData,
                                                       'ruleUsedIn': [ruleUsage]}}
        for shadowWarning in device.xpath('./details/msg/shadow-warn/entry'):
            warningDict = ast.literal_eval(shadowWarning.text)
            ruleID = warningDict['uuid']
            for vsysListItem in warningDict['vsys']:
                ruleUsage = f"{deviceName} ({deviceSN}) - {vsysListItem['id']}"
                ruleData = {'ruleName': warningDict['rulename'],
                            'ruleType': warningDict['ruletype'],
                            'shadowsRules': vsysListItem['shadowed-rule']}
            if warningDict['uuid'] not in rulesShadowed.keys():
                rulesShadowed[ruleID] = {0: {'ruleData': ruleData,
                                               'ruleUsedIn': [ruleUsage]}}
            else:
                matchFound = False
                for ruleInstance in rulesShadowed[warningDict['uuid']].keys():
                    if rulesShadowed[ruleID][ruleInstance]['ruleData'] == ruleData:
                        rulesShadowed[ruleID][ruleInstance]['ruleUsedIn'].append(ruleUsage)
                        matchFound = True
                if not matchFound:
                    newID = max(rulesShadowed[warningDict['uuid']].keys()) + 1
                    rulesShadowed[ruleID] = {newID: {'ruleData': ruleData,
                                                       'ruleUsedIn': [ruleUsage]}}

jobResultsPerDevice = {}
for jobID in jobResults.keys():
    jobDetails = {}
    for key in jobResults[jobID].keys():
        if key not in jobDetails.keys() and key != 'devices':
            jobDetails[key] = jobResults[jobID][key]
    for device in jobResults[jobID]['devices'].keys():
        deviceDetails = {}
        for key in jobResults[jobID]['devices'][device].keys():
            if key not in deviceDetails.keys():
                deviceDetails[key] = jobResults[jobID]['devices'][device][key]
        jobResultsPerDevice[device] = {**jobDetails, **deviceDetails}

with open(args[0].workbookname.replace(".xlsx", ".txt"), 'w') as writer:
    writer.write(json.dumps(jobResults, indent=4))





panCore.initXLSX(args[0].workbookname)

worksheet = panCore.workbook_obj.add_worksheet('Uncommitted Panorama Changes')
headers = ['ChangeNumber']
for changeNumber in uncommittedChanges:
    for key in uncommittedChanges[changeNumber].keys():
        if key not in headers:
            headers.append(key)
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
headers.remove('ChangeNumber')
row = 1
for changeNumber in uncommittedChanges:
    worksheet.write(row, 0, changeNumber)
    col = 1
    for header in headers:
        if header in uncommittedChanges[changeNumber]:
            worksheet.write(row, col, uncommittedChanges[changeNumber][header])
        else:
            worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row += 1

worksheet = panCore.workbook_obj.add_worksheet("Panorama HA State")
headers = []
for key in highAvaialabilityState['haAll']:
    if key not in headers:
        headers.append(key)
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
col = 0
for header in headers:
    worksheet.write(row, col, highAvaialabilityState['haAll'][header])
    col += 1


worksheet = panCore.workbook_obj.add_worksheet("ValidationJobDetails")
headers = ['serial-no', 'devicename']
for device in jobResultsPerDevice:
    for key in jobResultsPerDevice[device]:
        if key not in headers:
            headers.append(key)

worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for deviceSN in jobResultsPerDevice:
    col = 0
    for header in headers:
        if header in jobResultsPerDevice[deviceSN]:
            worksheet.write(row, col, jobResultsPerDevice[deviceSN][header])
        else:
            worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row +=1


worksheet = panCore.workbook_obj.add_worksheet("ValidationMessages")
headers = ['serial', 'hostname']
for deviceSN in genericWarnings:
    for key in genericWarnings[deviceSN]:
        if key not in headers:
            headers.append(key)
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for deviceSN in genericWarnings:
    worksheet.write(row, 0, deviceSN)
    if genericWarnings[deviceSN]['hostname'] is not None:
        worksheet.write(row, 1, genericWarnings[deviceSN]['hostname'])
    else:
        worksheet.write(row, 1, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    if genericWarnings[deviceSN]['errors'] != "":
        worksheet.write(row, 2, genericWarnings[deviceSN]['errors'], panCore.workbook_obj.add_format((panExcelStyles.styles['wrappedText'])))
    else:
        worksheet.write(row, 2, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    if genericWarnings[deviceSN]['warnings'] != "":
        worksheet.write(row, 3, genericWarnings[deviceSN]['warnings'], panCore.workbook_obj.add_format((panExcelStyles.styles['wrappedText'])))
    else:
        worksheet.write(row, 3, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
    row +=1

worksheet = panCore.workbook_obj.add_worksheet('TemplateStackDetails')
headers = ['Name', 'Description', 'MemberTemplates', 'Devices', 'Settings', 'templateVariables', 'ConfigLineCount', 'LocalConfig', 'UserID_MasterDevice']
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for templateStack in templateStacks:
    worksheet.write(row, 0, templateStack)
    worksheet.write(row, 1, templateStacks[templateStack]['templateDescription'])
    worksheet.write(row, 2, templateStacks[templateStack]['templateMembers'], panCore.workbook_obj.add_format((panExcelStyles.styles['wrappedText'])))
    worksheet.write(row, 3, templateStacks[templateStack]['templateDevices'], panCore.workbook_obj.add_format((panExcelStyles.styles['wrappedText'])))
    worksheet.write(row, 4, templateStacks[templateStack]['templateSettings'], panCore.workbook_obj.add_format((panExcelStyles.styles['wrappedText'])))
    worksheet.write(row, 5, templateStacks[templateStack]['templateVariables'], panCore.workbook_obj.add_format((panExcelStyles.styles['wrappedText'])))
    worksheet.write(row, 6, templateStacks[templateStack]['templateConfigLineCount'])
    worksheet.write(row, 7, templateStacks[templateStack]['templateConfig'], panCore.workbook_obj.add_format((panExcelStyles.styles['wrappedText'])))
    worksheet.write(row, 8, templateStacks[templateStack]['templateUserIdentificationMasterDevice'])
    row += 1


worksheet = panCore.workbook_obj.add_worksheet("TemplateSyncStates")
headers = ['serial', 'hostname', 'templateName', 'templateType']
for deviceSN in templateSyncStates:
    for key in templateSyncStates[deviceSN]:
        if key not in headers:
            headers.append(key)
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for deviceSN in templateSyncStates:
    col = 0
    for header in headers:
        if header in templateSyncStates[deviceSN]:
            if header == 'template-status' and templateSyncStates[deviceSN][header].lower() != "in sync":
                worksheet.write(row, col, templateSyncStates[deviceSN][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
            elif header == 'template-no-content-preview-status' and templateSyncStates[deviceSN][header].lower() != 'in sync':
                worksheet.write(row, col, templateSyncStates[deviceSN][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
            elif header == 'unsupported-version' and templateSyncStates[deviceSN][header] != 'no':
                worksheet.write(row, col, templateSyncStates[deviceSN][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
            elif header == 'connected' and templateSyncStates[deviceSN][header] != 'yes':
                worksheet.write(row, col, templateSyncStates[deviceSN][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
            else:
                worksheet.write(row, col, templateSyncStates[deviceSN][header])
        else:
            worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row +=1


worksheet = panCore.workbook_obj.add_worksheet("DeviceGroupSyncStates")
headers = ['serial', 'hostname', 'deviceGroupName']
for deviceSN in deviceGroupSyncStates:
    for key in deviceGroupSyncStates[deviceSN]:
        if key not in headers:
            headers.append(key)
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for deviceSN in deviceGroupSyncStates:
    col = 0
    for header in headers:
        if header in deviceGroupSyncStates[deviceSN]:
            if header == 'shared-policy-status' and deviceGroupSyncStates[deviceSN][header].lower() != "in sync":
                worksheet.write(row, col, deviceGroupSyncStates[deviceSN][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
            elif header == 'unsupported-version' and deviceGroupSyncStates[deviceSN][header] != 'no':
                worksheet.write(row, col, deviceGroupSyncStates[deviceSN][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
            elif header == 'connected' and deviceGroupSyncStates[deviceSN][header] != 'yes':
                worksheet.write(row, col, deviceGroupSyncStates[deviceSN][header], panCore.workbook_obj.add_format(panExcelStyles.styles['alertText']))
            else:
                worksheet.write(row, col, deviceGroupSyncStates[deviceSN][header])
        else:
            worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row +=1

worksheet = panCore.workbook_obj.add_worksheet("ApplicationDependencies")
headers = ['rule UUID', 'Instance', 'Rule Name', 'Rule Type', 'AppNumber', 'App-ID', 'RequiredApps', 'usedBy']
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for ruleID in appDependencies:
    for ruleInstance in appDependencies[ruleID]:
        for appNum, ignored in enumerate(appDependencies[ruleID][ruleInstance]['ruleData']['dependentApps']):
            for appName in appDependencies[ruleID][ruleInstance]['ruleData']['dependentApps'][appNum].keys():
                worksheet.write(row, 0, ruleID)
                worksheet.write(row, 1, ruleInstance)
                worksheet.write(row, 2, appDependencies[ruleID][ruleInstance]['ruleData']['ruleName'])
                worksheet.write(row, 3, appDependencies[ruleID][ruleInstance]['ruleData']['ruleType'])
                worksheet.write(row, 4, appNum)
                worksheet.write(row, 5, appName)
                worksheet.write(row, 6, str(appDependencies[ruleID][ruleInstance]['ruleData']['dependentApps'][appNum][appName]))
                worksheet.write(row, 7, str(appDependencies[ruleID][ruleInstance]['ruleUsedIn']))
                row += 1


worksheet = panCore.workbook_obj.add_worksheet("ShadowingRules")
headers = ['rule UUID', 'Instance', 'Rule Name', 'Rule Type', 'RulesShadowed', 'usedBy']
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for ruleID in rulesShadowed:
    for ruleInstance in rulesShadowed[ruleID]:
        worksheet.write(row, 0, ruleID)
        worksheet.write(row, 1, ruleInstance)
        worksheet.write(row, 2, rulesShadowed[ruleID][ruleInstance]['ruleData']['ruleName'])
        worksheet.write(row, 3, rulesShadowed[ruleID][ruleInstance]['ruleData']['ruleType'])
        worksheet.write(row, 4, str(rulesShadowed[ruleID][ruleInstance]['ruleData']['shadowsRules']))
        worksheet.write(row, 5, str(rulesShadowed[ruleID][ruleInstance]['ruleUsedIn']))
        row += 1

panCore.workbook_obj.close()