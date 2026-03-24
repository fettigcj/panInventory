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
 -  add new PAN-OS 11 features:
    - cloud-inline-analysis
    - disable-override
    - inline-exception-edl-url
    - inline-exception-ip-address
    - mica-engine-vulnerability-enabled

"""
import panos

#Import custom library modules
from pancore import panCore, panExcelStyles, panGatherFunctions
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse


def buildAll(confPath):
    devData = {}
    devData.update({'SecurityProfileGroups': panGatherFunctions.panorama_ProfileGroups(pano_obj, confPath)})
    devData.update({'AntiVirusProfiles': panGatherFunctions.panorama_AntiVirusProfiles(pano_obj, confPath)})
    devData.update({'VulnerabilityProfiles': panGatherFunctions.panorama_VulnerabilityProfiles(pano_obj, confPath)})
    devData.update({'AntiSpywareProfiles': panGatherFunctions.panorama_AntiSpywareProfiles(pano_obj, confPath)})
    devData.update({'urlCategories': panGatherFunctions.panorama_CustomUrlCategories(pano_obj, confPath)})
    devData.update({'fileBlockingProfiles': panGatherFunctions.panorama_FileBlockingProfiles(pano_obj, confPath)})
    devData.update({'wildfireProfiles': panGatherFunctions.panorama_WildfireProfiles(pano_obj, confPath)})
    return devData

if __name__ == "__main__":
    # Initialize CLI, logging, config, and Panorama connection
    parser = argparse.ArgumentParser(
        prog="PanSecurityGroupsAndProfiles",
        description="Audit Panorama report back on security profiles and security profile groups.")
    parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
    parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='groupsAndProfiles.log')
    parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
    parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='SecurityProfilesAndGroups.xlsx')
    parser.add_argument('--urlSource', dest='urlSource', choices=['panw', 'brightcloud'], default='panw', help="Select predefined URL category source: 'panw' or 'brightcloud'. Default: panw")
    args, _ = parser.parse_known_args()
    panCore.startLogging(args.logfile)
    panCore.configStart(headless=args.headless, configStorage=args.conffile)
    if hasattr(panCore, 'panUser'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
    elif hasattr(panCore, 'panKey'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
    else:
        panCore.logging.critical("Found neither username/password nor API key. Exiting.")
        sys.exit()

    dgCount = len(deviceGroups)
    dgHierarchy = panGatherFunctions.panorama_DeviceGroupHierarchy_topdown_with_firewalls(pano_obj)
    dgNum = 1
    startTime = datetime.datetime.now(datetime.timezone.utc)
    dgData = {}
    panCore.logging.info(f"Starting audit at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    panCore.logging.info(f"  Adding predefined elements:")
    dgData['predefined'] = buildAll('/config/predefined')
    dgData['predefined'].update({'urlCategories': panGatherFunctions.panorama_PredefinedUrlCategories(pano_obj, args.urlSource)})
    dgData['predefined']['urlProfiles'] = panGatherFunctions.panorama_UrlFilteringProfiles(
            pano_obj,
            '/config/predefined',
            [],
            dgData['predefined']['urlCategories'],
        )
    panCore.logging.info(f"  Adding shared elements.")
    dgData['shared'] = buildAll('/config/shared')
    dgData['shared']['urlObjects_detailed'] = panGatherFunctions.either_CustomUrlCategories_detailed(pano_obj)
    dgData['shared']['urlProfiles'] = panGatherFunctions.panorama_UrlFilteringProfiles(
            pano_obj,
            '/config/shared',
            dgData['shared']['urlCategories'] or [],
            dgData['predefined']['urlCategories'],
        )
    for dg_obj in deviceGroups:
        dgAuditStartTime = datetime.datetime.now(datetime.timezone.utc)
        panCore.logging.info("*********")
        panCore.logging.info(f"Starting audit of device group {dg_obj.name} ({dgNum}/{dgCount}) at {dgAuditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
        dgData[dg_obj.name] = buildAll(dg_obj.xpath())
        dgData[dg_obj.name]['urlObjects_detailed'] = panGatherFunctions.either_CustomUrlCategories_detailed(dg_obj)
        if dgData[dg_obj.name]['urlCategories']:
            # If the device group has locally defined URL category objects incorporate them into "Custom URL categories"
            dgData[dg_obj.name]['urlProfiles'] = panGatherFunctions.panorama_UrlFilteringProfiles(
                            pano_obj,
                            dg_obj.xpath(),
                            (dgData['shared']['urlCategories'] + dgData[dg_obj.name]['urlCategories']),
                            dgData['predefined']['urlCategories'],
                        )
        else:
            # else just use shared (If 'Shared' has custom URL objects.... )
            if dgData['shared']['urlCategories']:
                dgData[dg_obj.name]['urlProfiles'] = panGatherFunctions.panorama_UrlFilteringProfiles(pano_obj, dg_obj.xpath(), (dgData['shared']['urlCategories']))
            else:
                dgData[dg_obj.name]['urlProfiles'] = panGatherFunctions.panorama_UrlFilteringProfiles(pano_obj, dg_obj.xpath(), [])
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
    workbook = xlsxwriter.Workbook(args.workbookname)
    headers = ['deviceGroup', 'SecurityProfileGroups', 'AntiVirusProfiles', 'AntiSpywareProfiles', 'VulnerabilityProfiles', 'urlProfiles', 'fileBlockingProfiles', 'wildfireProfiles', 'urlObjects_detailed']
    ####
    #### List all Security Profiles & Security Profile Groups in the summary tab:
    ####
    worksheet = workbook.add_worksheet(('profileList'))
    worksheet.merge_range('A1:I1', 'Security Profiles found',workbook.add_format(panExcelStyles.styles['label']))
    worksheet.write_row('A2',headers,workbook.add_format(panExcelStyles.styles['rowHeader']))
    row = 1
    col = 0
    for dgName in deviceGroupsToReport:
        dgStartRow = dgEndRow = row +1
        for header in headers:
            row = dgStartRow
            col = headers.index(header)
            if header == 'deviceGroup':
                # We don't know how many rows the device group will occupy yet, wait until after this loop to write the device group name to the rows we're about to write.'
                pass
            elif header not in dgData[dgName].keys():
                # if there are no profiles of a particular type for this device group skip that profile type.
                pass
            elif dgData[dgName][header]:
                # if there are no profiles of a particular type for this device group skip that profile type.
                # (This test keys off the boolean "False" returned by the get... functions earlier)
                if header == 'urlObjects_detailed':
                    # Don't splat every URL object, just the count will do.
                    worksheet.write(row,col,len(dgData[dgName][header]))
                    dgEndRow = max(dgEndRow, row)
                    row += 1
                else:
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
    #### Detailed URL objects
    ####
    worksheet = workbook.add_worksheet("Detailed URL objects")
    # Banner per Device Group across four columns, then headers and details
    row = 0
    col_start = 0
    # Build dynamic headers for this worksheet from union of keys across all URL objects.
    for dgName in dgData.keys():
        url_objects = dgData.get(dgName, {}).get('urlObjects_detailed')
        if not isinstance(url_objects, dict) or len(url_objects) == 0:
            continue
        # Determine headers dynamically based on object records (SDK .about() keys)
        labels_seen = []  # maintain insertion order
        for object_name in sorted(url_objects.keys()):
            record = url_objects.get(object_name) or {}
            if isinstance(record, dict):
                for label in record.keys():
                    if label not in labels_seen:
                        labels_seen.append(label)
        # We always show a first column for the object name
        # Prefer readable, stable column order: Name, then common fields if present, then any others.
        preferred_order = ['type', 'description', 'url_value']
        dynamic_headers = ['Name']
        for key in preferred_order:
            if key in labels_seen:
                if key == 'url_value':
                    dynamic_headers.append('Values')
                    # Add a computed member count column immediately after Values
                    dynamic_headers.append('memberCount')
                elif key == 'description':
                    dynamic_headers.append('Description')
                elif key == 'type':
                    dynamic_headers.append('Type')
        # Append any remaining labels (excluding ones already mapped) in sorted order for determinism
        remaining = [k for k in labels_seen if k not in preferred_order]
        for key in sorted(remaining):
            # Avoid duplicating a header named 'name' since we already include 'Name' as first column
            if key.lower() == 'name':
                continue
            dynamic_headers.append(key)
        # Device Group banner across the computed number of columns
        last_col = col_start + max(0, len(dynamic_headers) - 1)
        worksheet.merge_range(row, col_start, row, last_col, dgName, workbook.add_format(panExcelStyles.styles['label']))
        row += 1
        # Column headers
        worksheet.write_row(row, col_start, dynamic_headers, workbook.add_format(panExcelStyles.styles['rowHeader']))
        row += 1
        # Helper to normalize arbitrary values for display
        def _normalize_value(value):
            try:
                if value is None:
                    return 'None'
                # If it's a list-like or set, join items
                if isinstance(value, (list, tuple, set)):
                    items = [str(v) for v in value if v is not None and str(v).strip() != '']
                    return ", ".join(items) if items else 'None'
                # If it's a dict, join its values
                if isinstance(value, dict):
                    items = [str(v) for v in value.values() if v is not None and str(v).strip() != '']
                    return ", ".join(items) if items else 'None'
                # Strings: strip; if string representation looks like list, keep as-is for now
                text = str(value).strip()
                return text if text else 'None'
            except Exception:
                return 'None'
        # Rows for each URL object (sorted by name for deterministic output)
        for object_name in sorted(url_objects.keys()):
            record = url_objects.get(object_name) or {}
            col_offset = 0
            # First column: object name
            worksheet.write(row, col_start + col_offset, object_name)
            col_offset += 1
            # Remaining columns map back to labels
            for header_label in dynamic_headers[1:]:
                key = header_label
                # Map presentation headers back to SDK keys for common fields
                if header_label == 'Type':
                    key = 'type'
                elif header_label == 'Description':
                    key = 'description'
                elif header_label == 'Values':
                    key = 'url_value'
                value = record.get(key) if isinstance(record, dict) else None
                if header_label == 'Values':
                    # Write the raw Python list-formatted object intact (e.g., ["a", "b", "c"]).
                    if value is None:
                        display_text = 'None'
                    elif isinstance(value, (list, tuple, set)):
                        try:
                            display_text = repr(list(value)) if len(value) > 0 else 'None'
                        except Exception:
                            display_text = 'None'
                    elif isinstance(value, dict):
                        # Not expected for url_value; fallback to Pythonic list from dict values
                        try:
                            vals = list(value.values())
                            display_text = repr(vals) if len(vals) > 0 else 'None'
                        except Exception:
                            display_text = 'None'
                    else:
                        # For strings or other scalars, just cast to str and keep as-is
                        text = str(value).strip()
                        display_text = text if text else 'None'
                    worksheet.write(row, col_start + col_offset, display_text)
                elif header_label == 'memberCount':
                    # Compute count of entries in the Values (url_value) field
                    values_field = record.get('url_value') if isinstance(record, dict) else None
                    try:
                        if isinstance(values_field, (list, tuple, set)):
                            count_value = len(values_field)
                        elif isinstance(values_field, dict):
                            count_value = len(values_field)
                        elif values_field is None:
                            count_value = 0
                        else:
                            # As a fallback, attempt to interpret stringified list; otherwise 0
                            import ast
                            parsed = ast.literal_eval(values_field) if isinstance(values_field, str) else []
                            count_value = len(parsed) if isinstance(parsed, (list, tuple, set)) else 0
                    except Exception:
                        count_value = 0
                    worksheet.write(row, col_start + col_offset, count_value)
                else:
                    worksheet.write(row, col_start + col_offset, _normalize_value(value))
                col_offset += 1
            row += 1
        # Whitespace after each DG section
        row += 1
    
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