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
Changelog 2023-11-09:
    Migrate file, reformat to argParser format

Goals:
    Finish "show system files"
    Finish getSysResources()
"""

#Import custom library modules
from pancore import panCore, panExcelStyles
#Import stock/public library modules
import time, datetime, xlsxwriter, argparse, sys

#workBookName = "PanSysHealth.xlsx"  # Name the Excel workbook we'll write to later

details = {} #Dictionary to record what details are desired and which should be skipped
details['individualInterfaces'] = False  # "Show interface xx" responses
details['systemResources'] = True  # "show system resources"
details['systemEnvironmentals'] = True # "show system environmentals"
details['globalCounters'] = True #show counter global
details['globalCounterSeverity'] = "warn" #minimum severity to include global counter - "Info > Warn > error > drop"
details['globalCounterTimeFrame'] = 30 #time in seconds to average for global counter checks.
details['globalCounterInterval'] = 5 #time in seconds to wait between global counter checks


parser = argparse.ArgumentParser(
    prog="panSysHealth",
    description="Gathers in depth analytics about Palo Alto Networks firewalls' health.")
    #epilog="Text")

parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='adHoc.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='PanSysHealth.xlsx')
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

todayDate = datetime.date.today()

def getSysGlobalCounters():
    panCore.logging.info('---> Checking global counters over 30 second interval')
    msg = '----> interval {0} of {1} - {2}'
    i = 1
    iMax = (details['globalCounterTimeFrame']/details['globalCounterInterval'])+1 #+1 to accomodate a "first iteration at time zero"
    sysGlobalCounters = {}
    while i <= iMax:
        panCore.logging.info(msg.format(i,iMax,datetime.datetime.now(datetime.timezone.utc).strftime("%Y/%m/%d, %H:%M:%S - %Z")))
        panCore.headers = []
        panCore.devData = {'globalCounters': {}}
        startTime = datetime.datetime.now(datetime.timezone.utc)
        xmlData = panCore.xmlToLXML(fw_obj.op("<show><counter><global><filter><severity>{0}</severity></filter></global></counter></show>".format(details['globalCounterSeverity']),cmd_xml=False))
        for entry in xmlData.xpath("/response/result/global/counters/entry"):
            panCore.iterator(entry,'globalCounters')
        sysGlobalCounters[i] = panCore.devData
        sysGlobalCounters[i]['auditTime'] = startTime.strftime("%Y/%m/%d, %H:%M:%S - %Z")
        time.sleep(5)
        i += 1
    sysGlobalCounters['average'] = {'globalCounters': {}}
    for counter in sysGlobalCounters[1]['globalCounters'].keys():
        if 'rate' in counter:
            sysGlobalCounters['average']['globalCounters'][counter] = []
    for counter in sysGlobalCounters['average']['globalCounters'].keys():
        temp = []
        for i in sysGlobalCounters.keys():
            if i != 'average':
                temp.append(int(sysGlobalCounters[i]['globalCounters'][counter]))
        sysGlobalCounters['average']['globalCounters'][counter] = (sum(temp)/len(temp))
    return(sysGlobalCounters)



def getSysResources():
    print('cebu')


def getResourceMonitor():
    panCore.logging.info('----> gathering resource-monitor weekly stats')
    xmlData = panCore.xmlToLXML(fw_obj.op('show running resource-monitor week'))
    panCore.headers = []
    panCore.devData = {'resourceMonitor': {}}
    for fwDP in xmlData.xpath("//resource-monitor/data-processors")[0].getchildren():
        panCore.devData['resourceMonitor'][fwDP.tag] = {'CPU_Load_Average': {'tockInterval':fwDP[0].tag, 'cores': {}}}
        for fwCore in fwDP.xpath("//cpu-load-average/entry"):
            panCore.devData['resourceMonitor'][fwDP.tag]['CPU_Load_Average']['cores'][fwCore[0].tag+"_"+fwCore[0].text] = [fwCore[1].text]
        panCore.devData['resourceMonitor'][fwDP.tag]['CPU_Load_Max'] = {'tockInterval': fwDP[0].tag, 'cores': {}}
        for fwCore in fwDP.xpath("//cpu-load-maximum/entry"):
            panCore.devData['resourceMonitor'][fwDP.tag]['CPU_Load_Max']['cores'][fwCore[0].tag+"_"+fwCore[0].text] = [fwCore[1].text]
        panCore.devData['resourceMonitor'][fwDP.tag]['resource-utilization'] = {'tockInterval': fwDP[0].tag, 'cores': {}}
        for fwCore in fwDP.xpath("//resource-utilization/entry"):
            panCore.devData['resourceMonitor'][fwDP.tag]['resource-utilization']['cores'][fwCore[0].tag+"_"+fwCore[0].text] = [fwCore[1].text]
    return(panCore.devData['resourceMonitor'])


def getFileList():
    xmlData = panCore.xmlToLXML(fw_obj.op("show system files"))



#######################################################################################
#######################################################################################
############ Fetch Firewall Health Info Via Panorama API Proxy ########################


panCore.logging.info("Gathering System Health & Counters from Firewalls:")
fwDetails = {}
fwDetailsByModel = {}
clusterDetails = {}
fwCount = len(firewalls)
fwNum = 1
for fw_obj in firewalls:
    try:
        fwAuditStartTime = datetime.datetime.now(datetime.timezone.utc)
        fw_serial = fw_obj.serial
        if not fw_obj.state.connected:
            panCore.logging.info(f"--> Device Offline: {fw_serial} ({fwNum}/{fwCount}) at {fwAuditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
            fwNum += 1
            continue
        fw_obj.refresh_system_info()  # Update PAN-OS version, platform & serial, load into fw_obj for later reference
        device = fw_obj.serial
        fwDetails[device] = {'systemInfo': fw_obj.show_system_info()['system']}
        fwName = fwDetails[device]['systemInfo']['hostname']
        panCore.logging.info(f"--> Starting FirewallAudit of Device: {fwName} ({fwNum}/{fwCount}) ... {fwAuditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
        fwDetails[device]['resourceMonitor'] = getResourceMonitor()
        fwDetails[device]['globalCounters'] = getSysGlobalCounters()
        fwAuditFinishTime = datetime.datetime.now(datetime.timezone.utc)
        fwAuditDuration = fwAuditFinishTime - fwAuditStartTime
        fwNum += 1
        panCore.logging.info(f"<-- Finished FirewallAudit of {fwName} ({fwNum}/{fwCount}) in {fwAuditDuration.total_seconds()} seconds")
    except Exception as exception_details:
        panCore.logging.exception(f"ERROR ENCOUNTERED WHILE AUDITING {fw_obj.serial}")
        panCore.logging.exception(exception_details)

#######################################################################################
#######################################################################################
############################## Write Excel workbook ## ################################

panCore.initXLSX(args[0].workbookname)

panCore.logging.info("Writing firewall resource monitor data:")
panCore.headers = ['Firewall','Dataplane','ResourceMeter', 'Core', 'tockInterval',1,2,3,4,5,6,7,8,9,10,11,12,13]
panCore.worksheet = panCore.workbook_obj.add_worksheet("resourceMonitor")
panCore.worksheet.write_row(0,0, panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for device in fwDetails:
    for dp in fwDetails[device]['resourceMonitor']:
        for monitor in fwDetails[device]['resourceMonitor'][dp]:
            tockInterval = fwDetails[device]['resourceMonitor'][dp][monitor]['tockInterval']
            for core in fwDetails[device]['resourceMonitor'][dp][monitor]['cores']:
                panCore.worksheet.write(row, 0, fwDetails[device]['systemInfo']['hostname'])
                panCore.worksheet.write(row, 1, dp)
                panCore.worksheet.write(row, 2, monitor)
                panCore.worksheet.write(row, 3, core)
                panCore.worksheet.write(row, 4, tockInterval)
                readingsString = fwDetails[device]['resourceMonitor'][dp][monitor]['cores'][core][0]
                readings = [int(e) if e.isdigit() else e for e in readingsString.split(',')]
                panCore.worksheet.write(row, 5, max(i for i in readings if isinstance(i, int)))
                col = 6
                for reading in readings:
                    panCore.worksheet.write(row,col,reading)
                    col += 1
                row += 1
panCore.logging.info("Finished writing firewall resource monitor data\n")

panCore.logging.info("Writing global Counter data:")
panCore.worksheet = panCore.workbook_obj.add_worksheet("GlobalCounters")
panCore.headers = ['Firewall','Audit','auditTime']
for device in fwDetails:
    for i in fwDetails[device]['globalCounters']:
        for header in fwDetails[device]['globalCounters'][i]['globalCounters']:
            if header not in panCore.headers:
                panCore.headers.append(header)
panCore.worksheet.write_row(0,0, panCore.headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for device in fwDetails:
    for i in fwDetails[device]['globalCounters']:
        panCore.worksheet.write(row, 0, fwDetails[device]['systemInfo']['hostname'])
        panCore.worksheet.write(row, 1, i)
        if i == 'average':
            panCore.worksheet.write(row, 2, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        else:
            panCore.worksheet.write(row, 2, fwDetails[device]['globalCounters'][i]['auditTime'])
        col = 3
        for header in panCore.headers:
            if header in ['Firewall','Audit','auditTime']:
                pass
            else:
                if header in fwDetails[device]['globalCounters'][i]['globalCounters']:
                    panCore.worksheet.write(row, col, fwDetails[device]['globalCounters'][i]['globalCounters'][header])
                else:
                    panCore.worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
                col += 1
        row +=1


panCore.workbook_obj.close()






