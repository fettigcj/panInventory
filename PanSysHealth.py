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


from pancore import panCore, panExcelStyles
#import json, requests
# from collections import OrderedDict
#import re
import datetime,time
#import pandevice  # Because we hate reinventing the wheel
#from pandevice import ha, panorama, base, firewall



workBookName = "PanSysHealth.xlsx"  # Name the Excel workbook we'll write to later
todayDate = datetime.date.today()
details = {} #Dictionary to record what details are desired and which should be skipped
details['individualInterfaces'] = False  # "Show interface xx" responses
details['systemResources'] = True  # "show system resources"
details['systemEnvironmentals'] = True # "show system environmentals"
details['globalCounters'] = True #show counter global
details['globalCounterSeverity'] = "warn" #minimum severity to include global counter - "Info > Warn > error > drop"
details['globalCounterTimeFrame'] = 30 #time in seconds to average for global counter checks.
details['globalCounterInterval'] = 5 #time in seconds to wait between global counter checks



def getSysGlobalCounters():
    print('---> Checking global counters over 30 second interval')
    msg = '----> interval {0} of {1} - {2}'
    i = 1
    iMax = (details['globalCounterTimeFrame']/details['globalCounterInterval'])+1 #+1 to accomodate a "first iteration at time zero"
    sysGlobalCounters = {}
    while i <= iMax:
        print(msg.format(i,iMax,datetime.datetime.now(datetime.timezone.utc).strftime("%Y/%m/%d, %H:%M:%S - %Z")))
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
    print ('----> gathering resource-monitor weekly stats')
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

panCore.initXLSX(workBookName)
panCore.configStart()
pano_obj, deviceGroups, firewalls = panCore.buildPano_obj(panCore.panAddress,panCore.panUser,panCore.panPass)

#######################################################################################
#######################################################################################
############ Fetch Firewall Health Info Via Panorama API Proxy ########################
print("Gathering System Health & Counters from Firewalls:")
fwDetails = {}
fwDetailsByModel = {}
clusterDetails = {}
fwCount = len(firewalls)
fwNum = 1
for fw_obj in firewalls:
    if not fw_obj.state.connected:
        print("--> Device Offline: {0} ({1}/{2}".format(device, fwNum, fwCount))
        fwNum += 1
        continue
    fwAuditStartTime = datetime.datetime.now(datetime.timezone.utc)
    fw_obj.refresh_system_info()  # Update PAN-OS version, platform & serial, load into fw_obj for later reference
    device = fw_obj.serial
    #fwSysInfo = fw_obj.show_system_info()['system']
    fwDetails[device] = {'systemInfo': fw_obj.show_system_info()['system']}
    #fwName = fwSystemInfo['hostname']
    #fwDetailsByModel
    print("--> Starting FirewallAudit of Device: {0} ({1}/{2}) ... {3}".format(fwDetails[device]['systemInfo']['hostname'], fwNum, fwCount,fwAuditStartTime.strftime("%Y/%m/%d, %H:%M:%S - %Z")))
    fwDetails[device]['resourceMonitor'] = getResourceMonitor()
    fwDetails[device]['globalCounters'] = getSysGlobalCounters()
    fwAuditFinishTime = datetime.datetime.now(datetime.timezone.utc)
    fwAuditDuration = fwAuditFinishTime - fwAuditStartTime
    fwNum += 1
    print("<-- Finished FirewallAudit of {0} in {1} seconds".format(fwDetails[device]['systemInfo']['hostname'],fwAuditDuration.total_seconds()))


#######################################################################################
#######################################################################################
############################## Write Excel workbook ## ################################

#panCore.init(workBookName)

print("Writing firewall resource monitor data:")
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
                col = 5
                for reading in fwDetails[device]['resourceMonitor'][dp][monitor]['cores'][core][0].split(','):
                    panCore.worksheet.write(row,col,reading)
                    col += 1
                row += 1
print("Finished writing firewall resource monitor data\n")

print("Writing global Counter data:")
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






