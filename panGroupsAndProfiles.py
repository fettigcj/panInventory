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
    2023-01-26
    Make output prettier by accommodating lack of rules/exceptions in some profiles by adding if len<1 and not merging rows 
    in Excel if no rules or exceptions exist in the respective report sections.

    2023-12-29
    Add if __name__ == __main__: to local code to allow 'migrateToPanorama.py' to call this file without
    executing all code in file so that it can access the 'getProfiles' functions

Goals:
 -  Add ability to parse 'inline ML' section of URL filtering profile.
 -  Add ability to process multiple file types in the "Wildfire" profile spreadsheet output instead of only noting
    the last file type in the profile.
 -  Add "URL Categories & Groups" header to "ProfileList" so the reason device groups without other profiles
    were added to the list is more obvious (Probably just a "Present" flag...)
 -  Incorporate 'source_obj' as well as 'confPath' for each function. Finish splitting main() from other functions and create
    two calling 'utility' files so fw_obj or pano_obj can be processed depending on use case.
 -  Color code URL objects in URL filtering profile report for 'predefined' vs 'custom' URL object.

"""

#Import custom library modules
from pancore import panCore, panExcelStyles
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="PanSecurityGroupsAndProfiles",
        description="Audit Panorama report back on security profiles and security profile groups.")
    parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
    parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='groupsAndProfiles.log')
    parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
    parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='SecurityProfilesAndGroups.xlsx')
    args = parser.parse_known_args()
    #
    panCore.startLogging(args[0].logfile)
    panCore.configStart(headless=args[0].headless, configStorage=args[0].conffile)
    if hasattr(panCore, 'panUser'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
    elif hasattr(panCore, 'panKey'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
    else:
        panCore.logging.critical("Found neither username/password nor API key. Exiting.")
        sys.exit()

def getGroups(confPath):
    panCore.logging.info("    Profile Groups.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profile-group"))
    devData = {}
    groups = xmlData.xpath('//response/result/profile-group')
    if len(groups):
        for group in groups[0].getchildren():
            groupname = group.get('name')
            devData[groupname] = {"GroupName": groupname}
            for child in group.getchildren():
                devData[groupname].update({child.tag: child.getchildren()[0].text})
        return devData
    else:
        return False


def getAntivirusProfiles(confPath):
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profiles/virus"))
    devData = {}
    avProfiles = xmlData.xpath('//response/result/virus/entry')
    if len(avProfiles):
        for avProfile in avProfiles:
            profileName = avProfile.get('name')
            devData[profileName] = {}
            for decoder in avProfile.xpath('./decoder/entry'):
                decoderName = decoder.get('name')
                devData[profileName][decoderName] = {}
                for action in decoder.getchildren():
                    devData[profileName][decoderName].update({action.tag: action.text})
        return devData
    else:
        return False


def getVulnerabilityProfiles(confPath):
    panCore.logging.info("    Vulnerability Protection profiles.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profiles/vulnerability"))
    devData = {}
    vulnerabilityProfiles = xmlData.xpath('//response/result/vulnerability/entry')
    if len(vulnerabilityProfiles):
        for vulnerabilityProfile in vulnerabilityProfiles:
            profileName = vulnerabilityProfile.get('name')
            devData[profileName] = {}
            if (vulnerabilityProfile.xpath('./description') == []):
                devData[profileName].update({'Description': ""})
            else:
                devData[profileName].update({'Description': vulnerabilityProfile.xpath('./description')[0].text})
            devData[profileName]['rules'] = {}
            for rule in vulnerabilityProfile.xpath('./rules/entry'):
                ruleName = rule.get('name')
                ruleAction = rule.xpath('./action')[0][0].tag
                devData[profileName]['rules'][ruleName] = {'name': ruleName, 'packet-capture': 'Default (Disabled)'}
                for element in rule.getchildren():
                    if (not (len(element))):
                        devData[profileName]['rules'][ruleName].update({element.tag: element.text})
                    else:
                        string = ""
                        i = 1
                        for child in element:
                            if child.text == '\n              ':
                                child.text = None
                            try:
                                string += child.text
                            except:
                                string += child.tag
                            if i < len(element):
                                string += ", "
                                i += 1
                        devData[profileName]['rules'][ruleName].update({element.tag: string})
            devData[profileName]['exceptions'] = {1: 'None'}
            exceptionNumber = 0
            for exception in vulnerabilityProfile.xpath('./threat-exception/entry'):
                exceptionNumber += 1
                exceptionID = exception.get('name')
                devData[profileName]['exceptions'][exceptionNumber] = {'ThreatID': exceptionID}
                for element in exception.getchildren():
                    if (not (len(element))):
                        devData[profileName]['exceptions'][exceptionNumber].update({element.tag: element.text})
                    else:
                        string = ""
                        i = 1
                        for child in element:
                            if (child.text == '\n            ') or (child.text == '\n              '):
                                child.text = None
                            try:
                                string += child.text
                            except:
                                if (child.tag == 'entry'):
                                    try:
                                        string += child.get('name')
                                    except:
                                        string += child.tag
                                else:
                                    string += child.tag
                            if i < len(element):
                                string += ", "
                                i += 1
                        devData[profileName]['exceptions'][exceptionNumber].update({element.tag: string})
        return devData
    else:
        return False


def getAntiSpywareProfiles(confPath):
    panCore.logging.info("    Anti-Spyware profiles.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profiles/spyware"))
    devData = {}
    asProfiles = xmlData.xpath('//response/result/spyware/entry')
    if len(asProfiles):
        for asProfile in asProfiles:
            profileName = asProfile.get('name')
            devData[profileName] = {'Name': profileName}
            if (asProfile.xpath('./description') == []):
                devData[profileName].update({'Description': ""})
            else:
                devData[profileName].update({'Description': asProfile.xpath('./description')[0].text})
            devData[profileName]['rules'] = {}
            for rule in asProfile.xpath('./rules/entry'):
                ruleName = rule.get('name')
                devData[profileName]['rules'][ruleName] = {'name': ruleName}
                for element in rule.getchildren():
                    if (not (len(element))):
                        devData[profileName]['rules'][ruleName].update({element.tag: element.text})
                    else:
                        string = ""
                        i = 1
                        for child in element:
                            if (child.text == '\n            ') or (child.text == '\n              '):
                                child.text = None
                            try:
                                string += child.text
                            except:
                                string += child.tag
                            if i < len(element):
                                string += ", "
                                i += 1
                        devData[profileName]['rules'][ruleName].update({element.tag: string})
            dnsSettings = asProfile.xpath('./botnet-domains')[0]
            devData[profileName]['dnsSettings'] = {}
            if (dnsSettings.xpath('./packet-capture')):
                devData[profileName]['dnsSettings'].update(
                    {'packetCapture': dnsSettings.xpath('./packet-capture')[0].text})
            else:
                devData[profileName]['dnsSettings'].update({'packetCapture': 'disable'})
            if (dnsSettings.xpath('./sinkhole/ipv4-address')):
                devData[profileName]['dnsSettings'].update(
                    {'ipv4Sinkhole': dnsSettings.xpath('./sinkhole/ipv4-address')[0].text})
            else:
                devData[profileName]['dnsSettings'].update({'ipv4Sinkhole': 'disable'})
            if (dnsSettings.xpath('./sinkhole/ipv6-address')):
                devData[profileName]['dnsSettings'].update(
                    {'ipv6Sinkhole': dnsSettings.xpath('./sinkhole/ipv6-address')[0].text})
            else:
                devData[profileName]['dnsSettings'].update({'ipv6Sinkhole': 'disable'})
            devData[profileName]['dnsSettings']['lists'] = {}
            for dnsList in asProfile.xpath('./botnet-domains/lists/entry'):
                devData[profileName]['dnsSettings']['lists'][dnsList.get('name')] = {}
                devData[profileName]['dnsSettings']['lists'][dnsList.get('name')].update({'name': dnsList.get('name')})
                devData[profileName]['dnsSettings']['lists'][dnsList.get('name')].update(
                    {'action': dnsList.xpath('./action')[0][0].tag})
            devData[profileName]['dnsSettings']['exceptions'] = {1: 'None'}
            i = 1
            for dnsException in asProfile.xpath('./botnet-domains/threat-exception/entry'):
                devData[profileName]['dnsSettings']['exceptions'].update({i: dnsException.get('name')})
                i += 1
            devData[profileName]['exceptions'] = {1: 'None'}
            exceptionNumber = 0
            for exception in asProfile.xpath('./threat-exception/entry'):
                exceptionNumber += 1
                exceptionID = exception.get('name')
                devData[profileName]['exceptions'][exceptionNumber] = {'ThreatID': exceptionID}
                for element in exception.getchildren():
                    if (not (len(element))):
                        devData[profileName]['exceptions'][exceptionNumber].update({element.tag: element.text})
                    else:
                        string = ""
                        i = 1
                        for child in element:
                            if (child.text == '\n            ') or (child.text == '\n              '):
                                child.text = None
                            try:
                                string += child.text
                            except:
                                if (child.tag == 'entry'):
                                    try:
                                        string += child.get('name')
                                    except:
                                        string += child.tag
                                else:
                                    string += child.tag
                            if i < len(element):
                                string += ", "
                                i += 1
                        devData[profileName]['exceptions'][exceptionNumber].update({element.tag: string})
        return devData
    else:
        return False


def getPredefinedurlCategories(confPath):
    panCore.logging.info("    Predefined URL objects.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"/config/predefined/{confPath}"))
    devData = []
    categories = xmlData.xpath(f"//response/result/{confPath}/entry")
    for category in categories:
        categoryName = category.get('name')
        if categoryName not in devData:
            devData.append(categoryName)
    return devData


def geturlCategories(confPath):
    panCore.logging.info("    Custom URL objects.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profiles/custom-url-category"))
    devData = []
    categories = xmlData.xpath('//response/result/custom-url-category/entry')
    if len(categories):
        for category in categories:
            categoryName = category.get('name')
            if categoryName not in devData:
                devData.append(categoryName)
        return devData
    else:
        return False


def getURLProfiles(confPath, customCategories):
    panCore.logging.info("    URL profiles.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profiles/url-filtering"))
    devData = {}
    urlProfiles = xmlData.xpath('//response/result/url-filtering/entry')
    if len(urlProfiles):
        for urlProfile in urlProfiles:
            profileName = urlProfile.get('name')
            devData[profileName] = {
                'name': '',
                'description': '',
                'customBlockAction': '',
                'lists': {
                    'allow': {1: 'None'},
                    'alert': {1: 'None'},
                    'block': {1: 'None'},
                    'continue': {1: 'None'},
                    'override': {1: 'None'},
                    'ignore': customCategories[:],
                    'customAllowList': {1: 'None'},
                    'customBlockList': {1: 'None'},
                    'customObjects': customCategories[:]
                },
                'settings': {
                    'logContainerPageOnly': 'Default (True)',
                    'safeSearchEnforce': 'Default (False)',
                    'headerLogging_UserAgent': 'Default',
                    'headerLogging_Referer': 'Default',
                    'headerLogging_XFF': 'Default'
                },
                'credentialEnforcement': {
                    'mode': 'Default',
                    'logSeverity': 'Default/Disabled',
                    'lists': {
                        'allow': {1: 'None/Disabled'},
                        'alert': {1: 'None/Disabled'},
                        'block': {1: 'None/Disabled'},
                        'continue': {1: 'None/Disabled'}
                    }
                },
                'httpHeaderInsertion': {
                    1: {
                        'name': 'NotConfigured'
                    }
                }
            }
            devData[profileName]['name'] = profileName
            try:
                devData[profileName]['customBlockAction'] = urlProfile.xpath('./action')[0].text
            except:
                devData[profileName]['customBlockAction'] = "notFound"
            assignedCategories = []
            if (urlProfile.xpath('./description')):  # Check if a description exists.
                devData[profileName].update({'description': urlProfile.xpath('./description')[0].text})
            if (urlProfile.xpath('./allow-list')):  # Check that the custom allow list isn't empty before trying to retrieve it
                i = 1
                for item in urlProfile.xpath('./allow-list')[0].getchildren():
                    devData[profileName]['lists']['customAllowList'].update({i: item.text})
                    i += 1
            if (urlProfile.xpath(
                    './block-list')):  # Check that the custom block list isn't empty before trying to retrieve it
                i = 1
                for item in urlProfile.xpath('./block-list')[0].getchildren():
                    devData[profileName]['lists']['customBlockList'].update({i: item.text})
                    i += 1
            if (urlProfile.xpath('./allow')):  # Check if any custom objects have been explicitly allowed (Predefined categories aren't explicitly allowed but rather implicitly allowed by virtue of not existing elsewhere.)
                i = 1
                for item in urlProfile.xpath('./allow')[0].getchildren():
                    devData[profileName]['lists']['allow'].update({i: item.text})
                    if item.text not in assignedCategories:
                        assignedCategories.append(item.text)
                    if item.text in devData[profileName]['lists']['ignore']:
                        devData[profileName]['lists']['ignore'].remove(item.text)
                    i += 1
            if (urlProfile.xpath('./alert')):  # check that there are some categories set to 'alert'
                i = 1
                for item in urlProfile.xpath('./alert')[0].getchildren():
                    devData[profileName]['lists']['alert'].update({i: item.text})
                    if item.text not in assignedCategories:
                        assignedCategories.append(item.text)
                    if item.text in devData[profileName]['lists']['ignore']:
                        devData[profileName]['lists']['ignore'].remove(item.text)
                    i += 1
            if (urlProfile.xpath('./block')):  # check that there are some categories set to 'block'
                i = 1
                for item in urlProfile.xpath('./block')[0].getchildren():
                    devData[profileName]['lists']['block'].update({i: item.text})
                    if item.text not in assignedCategories:
                        assignedCategories.append(item.text)
                    if item.text in devData[profileName]['lists']['ignore']:
                        devData[profileName]['lists']['ignore'].remove(item.text)
                    i += 1
            if (urlProfile.xpath('./continue')):  # check that there are some categories set to 'continue'
                i = 1
                for item in urlProfile.xpath('./continue')[0].getchildren():
                    devData[profileName]['lists']['continue'].update({i: item.text})
                    if item.text not in assignedCategories:
                        assignedCategories.append(item.text)
                    if item.text in devData[profileName]['lists']['ignore']:
                        devData[profileName]['lists']['ignore'].remove(item.text)
                    i += 1
            if (urlProfile.xpath('./override')):  # check that there are some categories set to 'override'
                i = 1
                for item in urlProfile.xpath('./override')[0].getchildren():
                    devData[profileName]['lists']['override'].update({i: item.text})
                    if item.text not in assignedCategories:
                        assignedCategories.append(item.text)
                    if item.text in devData[profileName]['lists']['ignore']:
                        devData[profileName]['lists']['ignore'].remove(item.text)
                    i += 1
            # Search for unhandled URL categories which will be allowed (Without being logged) if not assigned to another action
            i = 1
            if devData[profileName]['lists']['allow'][1] != 'None':
                i = max(devData[profileName]['lists']['allow'].keys()) + 1
            for category in dgData['predefined']['urlCategories']:
                if category not in assignedCategories:
                    devData[profileName]['lists']['allow'].update({i: category})
                    i += 1
            if (urlProfile.xpath('./log-http-hdr-xff')):
                devData[profileName]['settings']['headerLogging_XFF'] = urlProfile.xpath('./log-http-hdr-xff')[0].text
            if (urlProfile.xpath('./log-http-hdr-user-agent')):
                devData[profileName]['settings']['headerLogging_UserAgent'] = \
                urlProfile.xpath('./log-http-hdr-user-agent')[0].text
            if (urlProfile.xpath('./log-http-hdr-referer')):
                devData[profileName]['settings']['headerLogging_Referer'] = urlProfile.xpath('./log-http-hdr-referer')[
                    0].text
            if (urlProfile.xpath('./safe-search-enforcement')):
                devData[profileName]['settings']['safeSearchEnforce'] = urlProfile.xpath('./safe-search-enforcement')[
                    0].text
            if (urlProfile.xpath('./log-container-page-only')):
                devData[profileName]['settings']['logContainerPageOnly'] = \
                urlProfile.xpath('./log-container-page-only')[0].text
            if (urlProfile.xpath('./credential-enforcement')):
                mode = urlProfile.xpath('./credential-enforcement/mode')[0][0]
                if mode.tag == 'group-mapping':
                    devData[profileName]['credentialEnforcement']['mode'] = mode.tag + ' (' + mode.text + ')'
                else:
                    devData[profileName]['credentialEnforcement']['mode'] = mode.tag
                if not mode.tag == 'disabled':
                    devData[profileName]['credentialEnforcement']['logSeverity'] = \
                    urlProfile.xpath('./credential-enforcement/log-severity')[0].text
                    if (urlProfile.xpath('./credential-enforcement/allow/member')):
                        i = 1
                        for member in urlProfile.xpath('./credential-enforcement/allow/member'):
                            devData[profileName]['credentialEnforcement']['lists']['allow'][i] = member.text
                            i += 1
                    if (urlProfile.xpath('./credential-enforcement/alert/member')):
                        i = 1
                        for member in urlProfile.xpath('./credential-enforcement/alert/member'):
                            devData[profileName]['credentialEnforcement']['lists']['alert'][i] = member.text
                            i += 1
                    if (urlProfile.xpath('./credential-enforcement/block/member')):
                        i = 1
                        for member in urlProfile.xpath('./credential-enforcement/block/member'):
                            devData[profileName]['credentialEnforcement']['lists']['block'][i] = member.text
                            i += 1
                    if (urlProfile.xpath('./credential-enforcement/continue/member')):
                        i = 1
                        for member in urlProfile.xpath('./credential-enforcement/continue/member'):
                            devData[profileName]['credentialEnforcement']['lists']['continue'][i] = member.text
                            i += 1
            if (urlProfile.xpath('./http-header-insertion')):
                rule = 1
                for entry in urlProfile.xpath('./http-header-insertion/entry'):
                    devData[profileName]['httpHeaderInsertion'][rule] = {}
                    devData[profileName]['httpHeaderInsertion'][rule]['name'] = entry.get('name')
                    devData[profileName]['httpHeaderInsertion'][rule]['type'] = entry[0][0].get('name')
                    devData[profileName]['httpHeaderInsertion'][rule]['domains'] = {1: "None"}
                    i = 1
                    for domain in entry.xpath('./type/entry/domains/member'):
                        devData[profileName]['httpHeaderInsertion'][rule]['domains'][i] = domain.text
                        i += 1
                    devData[profileName]['httpHeaderInsertion'][rule]['headers'] = {1: "None"}
                    i = 1
                    for header in entry.xpath('./type/entry/headers/entry'):
                        devData[profileName]['httpHeaderInsertion'][rule]['headers'][i] = {}
                        devData[profileName]['httpHeaderInsertion'][rule]['headers'][i]['header'] = \
                        header.xpath('./header')[0].text
                        devData[profileName]['httpHeaderInsertion'][rule]['headers'][i]['value'] = \
                        header.xpath('./value')[0].text
                        devData[profileName]['httpHeaderInsertion'][rule]['headers'][i]['log'] = header.xpath('./log')[
                            0].text
                        i += 1
                    rule += 1
        return devData
    else:
        return False


def getFileBlockingProfiles(confPath):
    panCore.logging.info("    File blocking profiles.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profiles/file-blocking"))
    devData = {}
    fileBlockingProfiles = xmlData.xpath('//response/result/file-blocking/entry')
    if len(fileBlockingProfiles):
        for fileBlockingProfile in fileBlockingProfiles:
            fileBlockingProfileName = fileBlockingProfile.get('name')
            if fileBlockingProfile.xpath('./description'):
                fileBlockingProfileDescription = fileBlockingProfile.xpath('./description')[0].text
            else:
                fileBlockingProfileDescription = ''
            devData[fileBlockingProfileName] = {
                'name': fileBlockingProfileName,
                'description': fileBlockingProfileDescription,
                'rules': {
                    0: {
                        'name': '',
                        'applications': {0: ''},
                        'fileTypes': {0: ''},
                        'direction': '',
                        'action': ''
                    }
                }
            }
            ruleNum = 0
            for rule in fileBlockingProfile.xpath('./rules/entry'):
                devData[fileBlockingProfileName]['rules'][ruleNum] = {}
                ruleName = rule.get('name')
                devData[fileBlockingProfileName]['rules'][ruleNum]['name'] = ruleName
                i = 0
                devData[fileBlockingProfileName]['rules'][ruleNum]['applications'] = {0: ''}
                for app in rule.xpath('./application/member'):
                    devData[fileBlockingProfileName]['rules'][ruleNum]['applications'][i] = app.text
                    i += 1
                i = 0
                devData[fileBlockingProfileName]['rules'][ruleNum]['fileTypes'] = {0: ''}
                for fileType in rule.xpath('./file-type/member'):
                    devData[fileBlockingProfileName]['rules'][ruleNum]['fileTypes'][i] = fileType.text
                    i += 1
                if rule.xpath('./direction'):
                    devData[fileBlockingProfileName]['rules'][ruleNum]['direction'] = rule.xpath('./direction')[0].text
                if rule.xpath('./action'):
                    devData[fileBlockingProfileName]['rules'][ruleNum]['action'] = rule.xpath('./action')[0].text
                ruleNum += 1
        return devData
    else:
        return False


def getWildfireProfiles(confPath):
    panCore.logging.info("    Wildfire profiles.")
    xmlData = panCore.xmlToLXML(pano_obj.xapi.get(f"{confPath}/profiles/wildfire-analysis"))
    devData = {}
    wildfireProfiles = xmlData.xpath('//response/result/wildfire-analysis/entry')
    if len(wildfireProfiles):
        for profile in wildfireProfiles:
            profileName = profile.get('name')
            if profile.xpath('./description'):
                profileDescription = profile.xpath('./description')[0].text
            else:
                profileDescription = ''
            devData[profileName] = {
                'name': profileName,
                'description': profileDescription,
                'rules': {}}
            for rule in profile.xpath('./rules/entry'):
                ruleName = rule.get('name')
                ruleDirection = rule.xpath('./direction')[0].text
                ruleAnalysis = rule.xpath('./analysis')[0].text
                devData[profileName]['rules'][ruleName] = {
                    'name': ruleName,
                    'direction': ruleDirection,
                    'analysis': ruleAnalysis}
                i = 0
                devData[profileName]['rules'][ruleName]['applications'] = {i: 'None'}
                for app in rule.xpath('./application/member'):
                    devData[profileName]['rules'][ruleName]['applications'].update({i: app.text})
                    i += 1
                i = 0
                devData[profileName]['rules'][ruleName]['fileTypes'] = {i: 'None'}
                for fileType in rule.xpath('./file-type/member'):
                    devData[profileName]['rules'][ruleName]['fileTypes'].update({i: fileType.text})
        return devData
    else:
        return False


def buildAll(confPath):
    devData = {}
    devData.update({'SecurityProfileGroups': getGroups(confPath)})
    devData.update({'AntiVirusProfiles': getAntivirusProfiles(confPath)})
    devData.update({'VulnerabilityProfiles': getVulnerabilityProfiles(confPath)})
    devData.update({'AntiSpywareProfiles': getAntiSpywareProfiles(confPath)})
    devData.update({'urlCategories': geturlCategories(confPath)})
    devData.update({'fileBlockingProfiles': getFileBlockingProfiles(confPath)})
    devData.update({'wildfireProfiles': getWildfireProfiles(confPath)})
    return devData

if __name__ == "__main__":
    # Code to run if executed as a freestanding script rather than imported:
    dgCount = len(deviceGroups)
    dgNum = 1
    startTime = datetime.datetime.now(datetime.timezone.utc)
    predefinedURLsFrom = "pan-url-categories"  # Use this one if you're leveraging PANW URL categories
    # predefinedURLsFrom = "bc-url-categories" # Use this one if you're leveraging BrightCloud URL categories
    dgData = {}
    panCore.logging.info(f"Starting audit at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    panCore.logging.info(f"  Adding predefined elements:")
    dgData['predefined'] = buildAll('/config/predefined')
    dgData['predefined'].update({'urlCategories': getPredefinedurlCategories(predefinedURLsFrom)})
    dgData['predefined']['urlProfiles'] = getURLProfiles('/config/predefined',[])
    panCore.logging.info(f"  Adding shared elements.")
    dgData['shared'] = buildAll('/config/shared')
    dgData['shared']['urlProfiles'] = getURLProfiles('/config/shared', dgData['shared']['urlCategories'])
    for dg_obj in deviceGroups:
        dgAuditStartTime = datetime.datetime.now(datetime.timezone.utc)
        panCore.logging.info("*********")
        panCore.logging.info(f"Starting audit of device group {dg_obj.name} ({dgNum}/{dgCount}) at {dgAuditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
        dgData[dg_obj.name] = buildAll(dg_obj.xpath())
        if dgData[dg_obj.name]['urlCategories']:
            # If the device group has locally defined URL category objects incorporate them into "Custom URL categories"
            dgData[dg_obj.name]['urlProfiles'] = getURLProfiles(dg_obj.xpath(), (dgData['shared']['urlCategories'] + dgData[dg_obj.name]['urlCategories']))
        else:
            # else just use shared (If 'Shared' has custom URL objects.... )
            if dgData['shared']['urlCategories']:
                dgData[dg_obj.name]['urlProfiles'] = getURLProfiles(dg_obj.xpath(), (dgData['shared']['urlCategories']))
            else:
                dgData[dg_obj.name]['urlProfiles'] = getURLProfiles(dg_obj.xpath(), [])
        dgNum +=1
    endTime = datetime.datetime.now(datetime.timezone.utc)
    panCore.logging.info(f"Finished gathering data from Panorama at {endTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}. (In {round((((endTime - startTime).total_seconds())/60),4)} minutes)")
    # Parse whether or not a DG has local profiles to report or simply inherits all profiles from "Shared"
    deviceGroupsToReport = []
    for dgName in dgData.keys():
        reportDG = False
        for profile in dgData[dgName].keys():
            if dgData[dgName][profile]:
                #Since earlier data retrieval functions return "False" we can trigger off that boolean here.
                reportDG = True
        if reportDG:
            deviceGroupsToReport.append(dgName)
    # Write Excel report detailing profiles discovered
    workbook = xlsxwriter.Workbook(args[0].workbookname)
    headers = ['deviceGroup', 'SecurityProfileGroups', 'AntiVirusProfiles', 'AntiSpywareProfiles', 'VulnerabilityProfiles', 'urlProfiles', 'fileBlockingProfiles', 'wildfireProfiles']
    ####
    #### List all Security Profiles & Security Profile Groups in the summary tab:
    ####
    worksheet = workbook.add_worksheet(('profileList'))
    worksheet.merge_range('A1:G1', 'Security Profiles found',workbook.add_format(panExcelStyles.styles['label']))
    worksheet.write_row('A2',headers,workbook.add_format(panExcelStyles.styles['rowHeader']))
    row = 1
    col = 0
    for dgName in deviceGroupsToReport:
        dgStartRow = dgEndRow = row +1
        for header in headers:
            row = dgStartRow
            col = headers.index(header)
            if header == 'deviceGroup':
                # We don't know how many rows the device group will occupy yet.
                pass
            elif header not in dgData[dgName].keys():
                # if there are no profiles of a particular type for this device group skip that profile type.
                pass
            elif dgData[dgName][header]:
                # if there are no profiles of a particular type for this device group skip that profile type.
                # (This test keys off the boolean "False" returned by the get... functions earlier)
                for profileName in dgData[dgName][header].keys():
                    #print(f"    Writing {profileName} on row {row}")
                    worksheet.write(row,col,profileName)
                    dgEndRow = max(dgEndRow, row)
                    row += 1
        col = headers.index('deviceGroup')
        rowNums = range(dgStartRow, dgEndRow)
        for row in range(dgStartRow, dgEndRow+1):
            # Range doesn't include its end number, so add one.
            worksheet.write(row,col,dgName)
    ####
    #### List all Security Profiles Groups, and show what profiles they contain:
    ####
    headers = []
    deviceGroupsWithSPGs = []
    for dgName in dgData.keys():
        if dgData[dgName]['SecurityProfileGroups']:
            deviceGroupsWithSPGs.append(dgName)
            for spg in dgData[dgName]['SecurityProfileGroups'].keys():
                if dgData[dgName]['SecurityProfileGroups'][spg]:
                    for profileType in dgData[dgName]['SecurityProfileGroups'][spg].keys():
                        if profileType not in headers:
                            headers.append(profileType)
    worksheet = workbook.add_worksheet('profileGroups')
    worksheet.merge_range(0, 0, 0, len(headers), 'Security Profile Groups',workbook.add_format(panExcelStyles.styles['label']))
    worksheet.write_row('B2',headers,workbook.add_format(panExcelStyles.styles['rowHeader']))
    worksheet.write(1, 0, 'DeviceGroup',workbook.add_format(panExcelStyles.styles['rowHeader']))
    row = 2
    col = 0
    for dgName in deviceGroupsWithSPGs:
        for spg in dgData[dgName]['SecurityProfileGroups'].keys():
            worksheet.write(row, 0, dgName)
            for header in headers:
                if header in dgData[dgName]['SecurityProfileGroups'][spg].keys():
                    worksheet.write(row,headers.index(header)+1,dgData[dgName]['SecurityProfileGroups'][spg][header])
                    # Allow for Device Group name at column 0 and shift everything right 
                    # by adding 1 to header's position in the headers list.
            row += 1
    ####
    #### Antivirus Profiles
    ####
    deviceGroupsWithAntivirus = []
    for dgName in dgData.keys():
        if dgData[dgName]['AntiVirusProfiles']:
            deviceGroupsWithAntivirus.append(dgName)
    headers = ['deviceGroup', 'ProfileName', 'decoder', 'action', 'wildfire-action']
    worksheet = workbook.add_worksheet('AntivirusProfiles')
    worksheet.merge_range('A1:E1', "Antivirus Profiles",workbook.add_format(panExcelStyles.styles['label']))
    worksheet.write_row(1, 0, headers, workbook.add_format(panExcelStyles.styles['rowHeader']))
    row = 2
    for dgName in deviceGroupsWithAntivirus:
        for profileName in dgData[dgName]['AntiVirusProfiles'].keys():
            profileHeight = len(dgData[dgName]['AntiVirusProfiles'][profileName])-1
            for decoder in dgData[dgName]['AntiVirusProfiles'][profileName].keys():
                worksheet.write(row, 0, dgName, workbook.add_format(panExcelStyles.styles['label']))
                worksheet.write(row, 1, profileName, workbook.add_format(panExcelStyles.styles['label']))
                worksheet.write(row, 2, decoder)
                worksheet.write(row, 3, dgData[dgName]['AntiVirusProfiles'][profileName][decoder]['action'])
                worksheet.write(row, 4, dgData[dgName]['AntiVirusProfiles'][profileName][decoder]['wildfire-action'])
                row += 1
    ####
    #### Vulnerability Profiles
    ####
    worksheet = workbook.add_worksheet('VulnerabilityProfiles')
    deviceGroupsWithVulnerabiltyProfiles = []
    for dgName in dgData.keys():
        if dgData[dgName]['VulnerabilityProfiles']:
            deviceGroupsWithVulnerabiltyProfiles.append(dgName)
    worksheet.merge_range('A1:J1', 'Vulnerability Profiles', workbook.add_format(panExcelStyles.styles['rowHeader']))
    row = 1
    ruleHeaders = ['name', 'action', 'vendor-id', 'severity', 'cve', 'threat-name', 'host', 'category', 'packet-capture']
    exceptionHeaders = ['ThreatID', 'action', 'packet-capture', 'exempt-ip']
    for dgName in deviceGroupsWithVulnerabiltyProfiles:
        for profile in dgData[dgName]['VulnerabilityProfiles']:
            profileStartRow = row
            col = 0  # Start in column 'A'
            worksheet.write(row, col, 'Device Group', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 9, dgName, workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            worksheet.write(row, col, 'Profile', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 9, profile, workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            rulesHeight = len(dgData[dgName]['VulnerabilityProfiles'][profile]['rules'])
            if rulesHeight < 1:
                worksheet.write(row, col, 'Rules: ', workbook.add_format(panExcelStyles.styles['label']))
            else:
                worksheet.merge_range(row, col, row + rulesHeight, col, 'Rules: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write_row(row, col + 1, ruleHeaders, workbook.add_format(panExcelStyles.styles['rowHeader']))
            row += 1
            for rule in dgData[dgName]['VulnerabilityProfiles'][profile]['rules']:
                col = 1
                for item in ruleHeaders:
                    worksheet.write(row, col, dgData[dgName]['VulnerabilityProfiles'][profile]['rules'][rule][item])
                    col += 1
                row += 1
            row += 1  # Whitespace after rules
            col = 0  # Reset column to "A" after printing last rule
            exceptionsHeight = len(dgData[dgName]['VulnerabilityProfiles'][profile]['exceptions'])
            if exceptionsHeight < 1:
                worksheet.write(row, col, 'Exceptions: ', workbook.add_format(panExcelStyles.styles['label']))
            else:
                worksheet.merge_range(row, col, row + exceptionsHeight, col, 'Exceptions: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write_row(row, col + 1, exceptionHeaders, workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            if (dgData[dgName]['VulnerabilityProfiles'][profile]['exceptions'][1] == 'None'):
                worksheet.write(row, col + 1, 'None')
                row += 1
            else:
                for exception in dgData[dgName]['VulnerabilityProfiles'][profile]['exceptions']:
                    col = 1
                    for item in exceptionHeaders:
                        if (item in dgData[dgName]['VulnerabilityProfiles'][profile]['exceptions'][exception].keys()):
                            worksheet.write(row, col, dgData[dgName]['VulnerabilityProfiles'][profile]['exceptions'][exception][item])
                        else:
                            pass
                        col += 1
                    row += 1
            worksheet.merge_range(row, 0, row, 9, '', workbook.add_format(panExcelStyles.styles['blackBox']))
            row += 1  # Black row after exceptions
    ####
    #### Antispyware Profiles
    ####
    worksheet = workbook.add_worksheet('AntiSpywareProfiles')
    deviceGroupsWithAntiSpyware = []
    for dgName in dgData.keys():
        if dgData[dgName]['AntiSpywareProfiles']:
            deviceGroupsWithAntiSpyware.append(dgName)
    worksheet.merge_range('A1:G1','Antispyware Profiles',workbook.add_format(panExcelStyles.styles['label']))
    row = 1
    ruleHeaders = ['name', 'action', 'severity', 'threat-name', 'category', 'packet-capture']
    exceptionHeaders = ['ThreatID', 'action', 'packet-capture', 'exempt-ip']
    for dgName in deviceGroupsWithAntiSpyware:
        for profile in dgData[dgName]['AntiSpywareProfiles']:
            col = 0
            worksheet.write(row, col, 'Device Group: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 6, dgName, workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            worksheet.write(row, col, 'Profile: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 6, profile, workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            worksheet.write(row, col, 'Description: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 6, dgData[dgName]['AntiSpywareProfiles'][profile]['Description'],workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            #
            #### Handle Rules.
            #
            height = len(dgData[dgName]['AntiSpywareProfiles'][profile]['rules'])
            if (height < 1):
                worksheet.write(row, col, 'Rules :', workbook.add_format(panExcelStyles.styles['label']))
            else:
                worksheet.merge_range(row, col, row + height, col, 'Rules :', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write_row(row, col + 1, ruleHeaders, workbook.add_format(panExcelStyles.styles['rowHeader']))
            row += 1  # Iterate row counter after writing header row
            for rule in dgData[dgName]['AntiSpywareProfiles'][profile]['rules']:
                col = 1  # Start in "B" column after section block in column A
                for item in ruleHeaders:
                    if (item in dgData[dgName]['AntiSpywareProfiles'][profile]['rules'][rule].keys()):
                        worksheet.write(row, col, dgData[dgName]['AntiSpywareProfiles'][profile]['rules'][rule][item])
                    else:
                        pass
                    col += 1
                row += 1
            worksheet.merge_range(row, 0, row, 6, '') #, workbook.add_format(panExcelStyles.styles['blackBox']
            row += 1
            col = 0  # Reset to Column "A" after last rule output
            #
            #### Handle Exceptions
            #
            height = len(dgData[dgName]['AntiSpywareProfiles'][profile]['exceptions'])
            worksheet.merge_range(row, col, row + height, col, 'Exceptions :', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write_row(row, col + 1, exceptionHeaders, workbook.add_format(panExcelStyles.styles['rowHeader']))
            row += 1  # Iterate row counter after writing header row
            if (dgData[dgName]['AntiSpywareProfiles'][profile]['exceptions'][1] == 'None'):
                worksheet.write(row, col + 1, 'None')
                row += 1
            else:
                for exception in dgData[dgName]['AntiSpywareProfiles'][profile]['exceptions']:
                    col = 1  # Start in "B" column after section block in column A
                    for item in exceptionHeaders:
                        if (item in dgData[dgName]['AntiSpywareProfiles'][profile]['exceptions'][exception].keys()):
                            worksheet.write(row, col, dgData[dgName]['AntiSpywareProfiles'][profile]['exceptions'][exception][item])
                        else:
                            pass
                        col += 1
                    row += 1
            worksheet.merge_range(row, 0, row, 6, '') #, workbook.add_format(panExcelStyles.styles['blackBox']))
            row += 1
            col = 0  # Reset to column "A" after last exception output
            #
            #### Handle DNS Settings
            #
            worksheet.merge_range(row, col, row, col + 6, 'DNS Signatures & Settings', workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            worksheet.write(row, col, 'IPv4 Sinkhole:', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write(row, col + 1, dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['ipv4Sinkhole'])
            worksheet.write(row, col + 2, 'IPv6 Sinkhole:', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write(row, col + 3, dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['ipv6Sinkhole'])
            worksheet.write(row, col + 4, 'Packet Capture:', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write(row, col + 5, dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['packetCapture'])
            row += 1
            row += 1  # Whitespace between general DNS settings and EDL & Exceptions lists
            worksheet.merge_range('A{0}:B{0}'.format(row), 'External Dynamic Lists', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range('D{0}:E{0}'.format(row), 'Threat ID Exceptions', workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            worksheet.write('A%s' % row, 'EDL Name', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write('B%s' % row, 'Action', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write('D%s' % row, 'Exception', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write('E%s' % row, 'Exception ID #', workbook.add_format(panExcelStyles.styles['label']))
            row += 1  # Iterate to next row after writing headers
            listsRow = row
            for dnsList in dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['lists']:
                worksheet.write('A%s' % row, dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['lists'][dnsList]['name'])
                worksheet.write('B%s' % row, dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['lists'][dnsList]['action'])
                # worksheet.write_row('A%s' %row,list(pano_asProfiles[profile]['dnsSettings']['lists'][dnsList].values()))
                row += 1
            rowAfterDNSLists = row
            row = listsRow
            for dnsException in dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['exceptions']:
                worksheet.write('D%s' % row, dnsException)
                worksheet.write('E%s' % row, dgData[dgName]['AntiSpywareProfiles'][profile]['dnsSettings']['exceptions'][dnsException])
                # worksheet.write_row('D%s' %row,dnsException)
                row += 1
            rowAfterDNSExceptions = row
            row = max(rowAfterDNSExceptions, rowAfterDNSLists)
            worksheet.merge_range(row, 0, row, 6, '', workbook.add_format(panExcelStyles.styles['blackBox']))
            row += 1
    ####
    #### URL Categories / Custom Objects
    ####
    worksheet = workbook.add_worksheet('URL Categories and Groups')
    deviceGroupsWithUrlCategories = []
    for dgName in dgData.keys():
        if dgData[dgName]['urlCategories']:
            deviceGroupsWithUrlCategories.append(dgName)
    row = 0
    colLimit = 5 #Set limit to 5 to enforce a six wide limit for when we splat out the 'available categories'
    for dgName in deviceGroupsWithUrlCategories:
        col = 0
        worksheet.merge_range(row, col, row, colLimit, dgName, workbook.add_format(panExcelStyles.styles['rowHeader']))
        row +=1
        for urlCategory in dgData[dgName]['urlCategories']:
            if col > colLimit:
                col = 0
                row += 1
            worksheet.write(row,col,urlCategory)
            col += 1
        row += 2
    ####
    #### URL Profiles
    ####
    deviceGroupsWithUrlProfiles = []
    for dgName in dgData.keys():
        if dgData[dgName]['urlProfiles']:
            deviceGroupsWithUrlProfiles.append(dgName)
    #
    # Preamble section ahead of URL filtering report
    #
    worksheet = workbook.add_worksheet('URL Filtering')
    worksheet.merge_range('A1:H1','URL Filtering Profiles',workbook.add_format(panExcelStyles.styles['label']))
    row = 1
    col = 0
    colLimit = 7
    # wider column limit for actual report to accomodate all the headers.
    # Use auto-scale to 1 page wide as appropriate for your report.
    worksheet.merge_range(row,col,row,colLimit,'URL Filtering Profiles',workbook.add_format(panExcelStyles.styles['label']))
    row += 1
    worksheet.merge_range(row,col,row+4,col,'Notes: ',workbook.add_format(panExcelStyles.styles['label']))
    worksheet.merge_range(row,col+1,row,colLimit,'"Allow" will NOT log the site access. Use "Alert" to permit and log the site access in the URL filtering logs')
    row += 1
    worksheet.merge_range(row,col+1,row,colLimit,'"Continue" will require the user to acknowledge a prompt and click "OK" to continue.')
    row += 1
    worksheet.merge_range(row,col+1,row,colLimit,'"override" will require the user to enter a (Firewall-specific) password to continue to the site.')
    row += 1
    worksheet.merge_range(row,col+1,row,colLimit,'"Ignore" is for custom URL objects ONLY. The custom URL will default back to the category to which it would otherwise belong')
    row += 1
    worksheet.merge_range(row,col+1,row,colLimit,'"Ignore" is useful for custom URL objects which exist to be a destination in security policies but should not be treated differently in terms of category.')
    row += 1 #Whitespace after notes
    #
    # URL filtering profiles themselves, starting with Black box cell merged across the top of each URL filtering profile.
    #
    cols = {
        'allow' : 0,
        'alert' : 1,
        'block' : 2,
        'continue' : 3,
        'override' : 4,
        'ignore' : 5,
        'customAllowList' : 6,
        'customBlockList' : 7}
    for dgName in deviceGroupsWithUrlProfiles:
        for profile in dgData[dgName]['urlProfiles']:
            if dgData[dgName]['urlProfiles'][profile]['lists']['ignore'] == []:
                dgData[dgName]['urlProfiles'][profile]['lists']['ignore'] = ['None']
            # Profile header & settings info:
            row += 1
            worksheet.merge_range(row, col, row, colLimit, '', workbook.add_format(panExcelStyles.styles['blackBox']))
            row += 1
            worksheet.write(row, col, 'Device Group: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, colLimit, dgName)
            row += 1
            worksheet.write(row, col, 'Profile Name: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, colLimit, dgData[dgName]['urlProfiles'][profile]['name'])
            row += 1
            worksheet.write(row, col, 'Description: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, colLimit, dgData[dgName]['urlProfiles'][profile]['description'])
            row += 1
            worksheet.write(row, col, 'Log Container Page Only: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write(row, col + 1, dgData[dgName]['urlProfiles'][profile]['settings']['logContainerPageOnly'])
            worksheet.merge_range(row, col + 2, row, col + 3, 'HTTP Header Logging', workbook.add_format(panExcelStyles.styles['rowHeader']))
            row += 1
            worksheet.write(row, col, 'Safe Search Enforcement: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write(row, col + 1, dgData[dgName]['urlProfiles'][profile]['settings']['safeSearchEnforce'])
            worksheet.write(row, col + 2, 'User Agent: ')
            worksheet.write(row, col + 3, dgData[dgName]['urlProfiles'][profile]['settings']['headerLogging_UserAgent'])
            row += 1
            worksheet.write(row, col + 2, 'Referer :')
            worksheet.write(row, col + 3, dgData[dgName]['urlProfiles'][profile]['settings']['headerLogging_Referer'])
            row += 1
            worksheet.write(row, col + 2, 'XFF :')
            worksheet.write(row, col + 3, dgData[dgName]['urlProfiles'][profile]['settings']['headerLogging_XFF'])
            row += 1
            worksheet.merge_range(row, col, row, colLimit, '')
            row += 1
            ####
            ## Finished general settings
            ## Start Credential Detection
            ####
            worksheet.write(row, col, 'User Credential Detection: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write(row, col + 1, dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['mode'])
            row += 1
            worksheet.write(row, col, 'LogSeverity: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.write(row, col + 1, dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['logSeverity'])
            row += 1
            worksheet.write(row, cols['allow'], 'Allow', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['alert'], 'Alert', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['block'], 'Block', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['continue'], 'Continue', workbook.add_format(panExcelStyles.styles['rowHeader']))
            row += 1
            startRow = row
            endRow = 0
            for i in dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['allow']:
                worksheet.write(row, cols['allow'], dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['allow'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['alert']:
                worksheet.write(row, cols['alert'], dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['alert'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['block']:
                worksheet.write(row, cols['block'], dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['block'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['continue']:
                worksheet.write(row, cols['continue'],
                                dgData[dgName]['urlProfiles'][profile]['credentialEnforcement']['lists']['continue'][i])
                row += 1
            endRow = max(row, endRow)
            row = endRow
            row += 2
            ####
            ## Finished Credential Detection
            ## Start HTTP Header Insertion
            ####
            worksheet.merge_range(row, col, row, colLimit, 'HTTP Header Insertion Rules',
                                  workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            worksheet.write(row, col, 'Rule Number', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 1, 'Type', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 2, 'Domains', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 3, 'Header', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 4, 'Value', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 5, 'Log', workbook.add_format(panExcelStyles.styles['rowHeader']))
            row += 1
            if dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][1]['name'] == 'NotConfigured':
                worksheet.merge_range(row, col, row, colLimit, "None Configured.")
                row += 1
            else:
                for rule in dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion']:
                    startRow = row
                    endRow = 0
                    worksheet.write(row, col, rule, workbook.add_format({'right': 1}))
                    worksheet.write(row, col + 1, dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][rule]['type'])
                    for i in dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][rule]['domains']:
                        worksheet.write(row, col + 2, dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][rule]['domains'][i])
                        row += 1
                    row += 1
                    endrow = max(row, endRow)
                    row = startRow
                    for i in dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][rule]['headers']:
                        worksheet.write(row, col + 3,
                                        dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][rule]['headers'][i]['header'])
                        worksheet.write(row, col + 4,
                                        dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][rule]['headers'][i]['value'])
                        worksheet.write(row, col + 5,
                                        dgData[dgName]['urlProfiles'][profile]['httpHeaderInsertion'][rule]['headers'][i]['log'])
                        row += 1
                    row += 1
                    endRow = max(row, endRow)
                    row = endRow
                row += 1
            row += 1
            worksheet.merge_range(row, col, row, colLimit, 'Categories by assignment in profile:',
                                  workbook.add_format(panExcelStyles.styles['label']))
            row += 1
            worksheet.write(row, cols['allow'], 'Allow', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['alert'], 'Alert', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['block'], 'Block', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['continue'], 'Continue', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['override'], 'Override', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['ignore'], 'Ignore', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['customAllowList'], 'Profile Allow', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, cols['customBlockList'],
                            'Profile Custom (%s)' % dgData[dgName]['urlProfiles'][profile]['customBlockAction'],
                            workbook.add_format(panExcelStyles.styles['rowHeader']))
            row += 1
            startRow = row
            endRow = 0
            for i in dgData[dgName]['urlProfiles'][profile]['lists']['allow']:
                worksheet.write(row, cols['allow'], dgData[dgName]['urlProfiles'][profile]['lists']['allow'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['lists']['alert']:
                worksheet.write(row, cols['alert'], dgData[dgName]['urlProfiles'][profile]['lists']['alert'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['lists']['block']:
                worksheet.write(row, cols['block'], dgData[dgName]['urlProfiles'][profile]['lists']['block'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['lists']['continue']:
                worksheet.write(row, cols['continue'], dgData[dgName]['urlProfiles'][profile]['lists']['continue'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['lists']['override']:
                worksheet.write(row, cols['override'], dgData[dgName]['urlProfiles'][profile]['lists']['override'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for item in dgData[dgName]['urlProfiles'][profile]['lists']['ignore']:
                worksheet.write(row, cols['ignore'], item)
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['lists']['customAllowList']:
                worksheet.write(row, cols['customAllowList'], dgData[dgName]['urlProfiles'][profile]['lists']['customAllowList'][i])
                row += 1
            endRow = max(row, endRow)
            row = startRow
            for i in dgData[dgName]['urlProfiles'][profile]['lists']['customBlockList']:
                worksheet.write(row, cols['customBlockList'], dgData[dgName]['urlProfiles'][profile]['lists']['customBlockList'][i])
                row += 1
            endRow = max(row, endRow)
            row = endRow
    ####
    #### File blocking Profile
    ####
    worksheet = workbook.add_worksheet('FileBlocking')
    deviceGroupsWithFileBlockingProfiles = []
    for dgName in dgData.keys():
        if dgData[dgName]['fileBlockingProfiles']:
            deviceGroupsWithFileBlockingProfiles.append(dgName)
    row = 0
    col = 0
    for dgName in deviceGroupsWithFileBlockingProfiles:
        for profile in dgData[dgName]['fileBlockingProfiles'].keys():
            worksheet.write(row, col, 'Device Group: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 4, dgData[dgName]['fileBlockingProfiles'][profile]['name'])
            row += 1
            worksheet.write(row, col, 'Profile: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 4, dgName)
            row += 1
            worksheet.write(row, col, 'Description: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 4, dgData[dgName]['fileBlockingProfiles'][profile]['description'])
            row += 1
            worksheet.write(row, col, 'RuleName', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 1, 'Applications', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 2, 'File Types', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 3, 'Direction', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 4, 'Action', workbook.add_format(panExcelStyles.styles['rowHeader']))
            # row += 1
            for rule in dgData[dgName]['fileBlockingProfiles'][profile]['rules']:
                row += 1
                startRow = row
                endRow = 0
                worksheet.write(row, col, dgData[dgName]['fileBlockingProfiles'][profile]['rules'][rule]['name'])
                for app in dgData[dgName]['fileBlockingProfiles'][profile]['rules'][rule]['applications']:
                    worksheet.write(row, col + 1, dgData[dgName]['fileBlockingProfiles'][profile]['rules'][rule]['applications'][app])
                    row += 1
                endRow = max(row, endRow)
                row = startRow
                for fileType in dgData[dgName]['fileBlockingProfiles'][profile]['rules'][rule]['fileTypes']:
                    worksheet.write(row, col + 2, dgData[dgName]['fileBlockingProfiles'][profile]['rules'][rule]['fileTypes'][fileType])
                    row += 1
                endRow = max(row, endRow)
                row = startRow
                worksheet.write(row, col + 3, dgData[dgName]['fileBlockingProfiles'][profile]['rules'][rule]['direction'])
                worksheet.write(row, col + 4, dgData[dgName]['fileBlockingProfiles'][profile]['rules'][rule]['action'])
                row += 1
                endRow = max(row, endRow)
                row = endRow
            worksheet.merge_range(row, col, row, col + 4, '', workbook.add_format(panExcelStyles.styles['blackBox']))
            row += 1
    ####
    #### Wildfire Profiles
    ####
    deviceGroupsWithWildfireProfiles = []
    for dgName in dgData.keys():
        if dgData[dgName]['wildfireProfiles']:
            deviceGroupsWithWildfireProfiles.append(dgName)
    row = 0
    col = 0
    worksheet = workbook.add_worksheet('Wildfire Analysis')
    for dgName in deviceGroupsWithWildfireProfiles:
        for profile in dgData[dgName]['wildfireProfiles'].keys():
            worksheet.write(row, col, 'Device Group: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 4, dgName)
            row += 1
            worksheet.write(row, col, 'Profile: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 4, dgData[dgName]['wildfireProfiles'][profile]['name'])
            row += 1
            worksheet.write(row, col, 'Description: ', workbook.add_format(panExcelStyles.styles['label']))
            worksheet.merge_range(row, col + 1, row, col + 4, dgData[dgName]['wildfireProfiles'][profile]['description'])
            row += 1
            worksheet.write(row, col, 'RuleName', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 1, 'Applications', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 2, 'File Types', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 3, 'Direction', workbook.add_format(panExcelStyles.styles['rowHeader']))
            worksheet.write(row, col + 4, 'Analysis', workbook.add_format(panExcelStyles.styles['rowHeader']))
            for rule in dgData[dgName]['wildfireProfiles'][profile]['rules']:
                row += 1
                startRow = row
                endRow = 0
                worksheet.write(row, col, dgData[dgName]['wildfireProfiles'][profile]['rules'][rule]['name'])
                for app in dgData[dgName]['wildfireProfiles'][profile]['rules'][rule]['applications']:
                    worksheet.write(row, col + 1, dgData[dgName]['wildfireProfiles'][profile]['rules'][rule]['applications'][app])
                    row += 1
                endRow = max(row, endRow)
                row = startRow
                for fileType in dgData[dgName]['wildfireProfiles'][profile]['rules'][rule]['fileTypes']:
                    worksheet.write(row, col + 2, dgData[dgName]['wildfireProfiles'][profile]['rules'][rule]['fileTypes'][fileType])
                    row += 1
                endRow = max(row, endRow)
                row = startRow
                worksheet.write(row, col + 3, dgData[dgName]['wildfireProfiles'][profile]['rules'][rule]['direction'])
                worksheet.write(row, col + 4, dgData[dgName]['wildfireProfiles'][profile]['rules'][rule]['analysis'])
                row += 1
                endRow = max(row, endRow)
                row = endRow
            worksheet.merge_range(row, col, row, col + 4, '', workbook.add_format(panExcelStyles.styles['blackBox']))
            row += 1
    workbook.close()