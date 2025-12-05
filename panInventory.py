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
2024-01-11 - Added zone protection profiles worksheet.
2024-04-03 - Adding pending local config changes
2025-08-28 - Added additional modules to pancore, began splitting gather & workbook functions from main script to dedicated modules
2025-08-29 - Reworked ZoneInfo report. changed 'has no interfaces' logic to any config of the zone rather than a per-config test
2025-10-17 - finished rewrite to split gather and workbook functions to separate modules.

Goals
    On "zoneInfo" worksheet the "Zones withouth interfaces" report should use colspan() to spread the
    list of firewalls with these zones out to avoid auto-width from messing with the other tables' views.

    'HALinkGroups' worksheet is showing stand-alone firewalls as though they were a
    single-node cluster. This is not desired.

    Test 'gatherSyslogProfiles' function on multi-vsys firewall, validate /config/shared is
    sole path. Incorporate "for vsys" loop if necessary.

    Implement additional arg to skip syslog/logForwarding/ZPP outputs if not required.

    Cope with timeouts, add additional error handling in "for fw_obj in firewalls" loop to
    allow for passing over errors rather than crashing.

    Update zoneList{}, syslog, logforwarding report methodologies to match ZPP data method to
    simplify code readability. /possibly/ create framework function to process arbitrary profiles...

    Would like to address the scenario where fw_obj.pending_changes() tests as true but fw_obj.op("show config list changes") returns no 'journaled' changes.
    Examples have been where plugins or telemetry configs have changed, which appears sufficient to trigger a "pending_changes" flag even though no "journaled"
    changes are reported by the "show config list changes" command.
"""
from typing import Any, Optional
from pancore import panCore
import argparse, logging
import sys, datetime, panos
from panos import ha, panorama, base, firewall

parser = argparse.ArgumentParser(
    prog="PanInventory",
    description="Audit Panorama & connected firewalls to generate reports on system state & health")
    #epilog="Text")

"""
In order to have a default behavior of reports being enabled we default=True below, but then use "store_false" when a flag is activated. 
This strange "enabling a negative" is counter-intuitive, but the reversed behavior upon ENABLING the flag to DISABLE the report simplifies 
the user interactions and allows the default (enabled) to be overruled when the flag is used.
"""
parser.add_argument('-I', '--headless', help="Disable Interactions; operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='panInventory.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='PanInventory.xlsx')
args, _ = parser.parse_known_args()
logger = panCore.startLogging(args.logfile)

# Import child modules only after logging is instantiated, so the log output is captured to the parent logger.
from pancore import panWorkbookFunctions, panGatherFunctions

def tryAudit(audit_name: str, func_or_name: object, *args: object, **kwargs: object) -> Optional[Any]:
    """
    Execute an audit function safely.
    - audit_name: Friendly name for logging (usually the function name).
    - func_or_name: Either a callable or a string name of a function in panGatherFunctions.
    - *args, **kwargs: Forwarded to the audit function.
    Returns the function's result or None on failure.
    """
    try:
        func = func_or_name
        if isinstance(func_or_name, str):
            # Resolve by name from panGatherFunctions
            func = getattr(panGatherFunctions, func_or_name)
        return func(*args, **kwargs)
    except Exception as e:
        logger.exception(f"Audit '{audit_name}' failed")
        logger.exception(e)
        return None


def auditFirewall(fw_obj: panos.firewall.Firewall, fwSerial: str):
    try:
        fwName = fw_obj.show_system_info()['system']['hostname']
        fwNameSerial = f"{fwName} ({fwSerial})"
        logger.info(f"Gathering audits for Device: {fwNameSerial} ({fwNum}/{fwCount})")
        logger.info("\t Caching running config")
        getConf = tryAudit('get_config', lambda: panCore.xmlToLXML(fw_obj.xapi.get('/config')))
        firewallData = {fwNameSerial: {
            'systemState': tryAudit('firewall_SystemState', panGatherFunctions.firewall_SystemState, fw_obj),
            'interfaces': tryAudit('firewall_Interfaces', panGatherFunctions.firewall_Interfaces, fw_obj),
            'schedules': tryAudit('firewall_schedules', panGatherFunctions.firewall_schedules, getConf),
            'zones': tryAudit('firewall_ZoneData', panGatherFunctions.firewall_ZoneData, fw_obj),
            'licensing': tryAudit('either_LicenseInfo', panGatherFunctions.either_LicenseInfo, fw_obj),
            'resourceMonitorHistory': tryAudit('firewall_ResourceMonitorHistory', panGatherFunctions.firewall_ResourceMonitorHistory, fw_obj),
            'syslogProfiles': tryAudit('firewall_SyslogProfiles', panGatherFunctions.firewall_SyslogProfiles, fw_obj),
            'deviceLogOutputs': tryAudit('firewall_DeviceLogSettings', panGatherFunctions.firewall_DeviceLogSettings, fw_obj),
            'logCollectorStatus': tryAudit('firewall_LogCollectorStatus', panGatherFunctions.firewall_LogCollectorStatus, fw_obj),
            'pendingChanges': tryAudit('firewall_PendingLocalChanges', panGatherFunctions.firewall_PendingLocalChanges, fw_obj),
            'zoneProtectionProfiles': tryAudit('firewall_zoneProtectionProfiles', panGatherFunctions.firewall_ZoneProtectionProfiles, getConf),
            'system': tryAudit('either_ShowSystemInfo', panGatherFunctions.either_ShowSystemInfo, fw_obj, fwNameSerial)
        }}
        #### Check if the firewall is in an HA cluster, and if so gather the info about the cluster
        if 'ha.peer.serial' not in panoInventory['devices'][fwSerial]:
            logger.info(f"\t> Skipping HA config audit for {fwNameSerial}, no HA peer serial number found in Panorama Inventory")
            firewallData[fwNameSerial]['haClusterMember'] = False
        else:
            firewallData[fwNameSerial]['highAvailability'] = panGatherFunctions.firewall_highAvailability(fw_obj)
        logger.info("Finished Gathering Audit Data\n")
        return firewallData
    except Exception as exception_details:
        logger.exception(f"ERROR ENCOUNTERED WHILE AUDITING {fw_obj.serial}")
        logger.exception(exception_details)
        return {}


todayDate = datetime.date.today()
panCore.configStart(headless=args.headless, configStorage=args.conffile)
if hasattr(panCore, 'panUser'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, 'panKey'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    logger.critical("Found neither username/password nor API key. Exiting.")
    sys.exit()

### Start Gathering Information ###
logger.info("Gathering Panorama inventory data")
panoInventory = {'devices': tryAudit('Show Panorama Devices (All)', panGatherFunctions.panorama_showDevicesAll, pano_obj),
                 'licenses': tryAudit('Show Panorama licenses', panGatherFunctions.either_LicenseInfo, pano_obj),
                 'system': tryAudit('Show Panorama System Info', panGatherFunctions.either_ShowSystemInfo, pano_obj, pano_obj.serial)}
templateData = tryAudit('Panorama Templates', panGatherFunctions.panorama_Templates, templates, tStacks)
templateStackData = tryAudit('Panorama Template Stacks', panGatherFunctions.panorama_ParseStackData, tStacks)

logger.info("Gathering Detailed Inventory from Firewalls:")
firewallDetails = {}
firewallDetailsByModel = {}
fwCount = len(firewalls)
fwNum = 0
for fw_obj in firewalls:
    fwNum += 1
    fwSerial = fw_obj.serial
    if not fw_obj.state.connected:
        logger.info(f"-> Device Offline: {fwSerial} ({fwNum}/{fwCount})")
        continue # Jump to next fw_obj if this one is offline. Do not execute further code for this fw_obj.
    try:
        fw_obj.refresh_system_info()
        # Refresh model, PAN-OS version, etc
        fwModel = fw_obj.platform
        result = auditFirewall(fw_obj, fwSerial)
        if isinstance(result, dict):
            firewallDetails.update(result)
        else:
            logger.warning(f"Skipping firewall {fw_obj.serial}: audit returned no data")
        # The "System Environmentals" report has different headers per firewall model.
        # To avoid lots of "Null" columns in our spreadsheets, we use model-specific dictionaries for this report's data.
        if fwModel not in firewallDetailsByModel.keys():
            firewallDetailsByModel[fwModel] = {}
        firewallDetailsByModel[fwModel][fwSerial] = {'environmentals': tryAudit('firewall_SystemEnvironmentals', panGatherFunctions.firewall_SystemEnvironmentals, fw_obj)}
    except Exception as exception_details:
        logger.exception(f"ERROR ENCOUNTERED WHILE AUDITING {fw_obj.serial}")
        logger.exception(exception_details)
        continue

logger.info("Begining building dictionaries for summaries & reports")
firewallReports = {
    'highAvailability': tryAudit('postProcessing_HA-Config', panGatherFunctions.postProcessing_highAvailability, firewallDetails, panoInventory),
    'zoneReport': tryAudit('postProcessing_Zones', panGatherFunctions.postProcessing_Zones, firewallDetails),
    'syslogProfiles': tryAudit('postProcessing_syslogProfiles', panGatherFunctions.postProcessing_syslogProfiles, firewallDetails),
    'zoneProtectionProfiles': tryAudit('postProcessing_zoneProtectionProfiles', panGatherFunctions.postProcessing_zoneProtectionProfiles, firewallDetails),
    'logOutputs': tryAudit('postProcessing_deviceLogOutputs', panGatherFunctions.postProcessing_deviceLogOutputs, firewallDetails),
}
logger.info("Done w/ summary data dictionaries.")


workbook = panWorkbookFunctions.initXLSX(args.workbookname)
#workbook = panWorkbookFunctions.initXLSX('test.xlsx')
panWorkbookFunctions.writeWorksheet_PanoramaInventory(workbook, panoInventory['devices'])
panWorkbookFunctions.writeWorksheet_FirewallDetails(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_Templates(workbook, templateData)
panWorkbookFunctions.writeWorksheet_TemplateStacks(workbook, templateStackData)
panWorkbookFunctions.writeWorksheet_HAClusterSummary(workbook, firewallReports['highAvailability'])
panWorkbookFunctions.writeWorksheet_HAConfigDetails(workbook, firewallReports['highAvailability'])
panWorkbookFunctions.writeWorksheet_HALinkMonitoring(workbook, firewallReports['highAvailability'])
panWorkbookFunctions.writeWorksheet_HAPathMonitoring(workbook, firewallReports['highAvailability'])
panWorkbookFunctions.writeWorksheet_ResourceMonitorHistory(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_DynamicUpdateSchedule(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_NetworkInterfacesLogical(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_NetworkInterfacesHardware(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_NetworkInterfacesDetails(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_ZoneInfo(workbook, firewallReports['zoneReport'])
panWorkbookFunctions.writeWorksheet_ZoneProtectionProfile(workbook, firewallReports['zoneProtectionProfiles'])
panWorkbookFunctions.writeWorksheet_Licensing(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_SystemState(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_EnvironmentalDetails(workbook, firewallDetails, firewallDetailsByModel)
panWorkbookFunctions.writeWorksheet_SyslogProfiles(workbook, firewallReports['syslogProfiles'])
panWorkbookFunctions.writeWorksheet_DeviceLogOutputSummary(workbook, firewallReports.get('logOutputs', {}))
panWorkbookFunctions.writeWorksheet_LogCollectorStatusSummary(workbook, firewallDetails)
panWorkbookFunctions.writeWorksheet_LogCollectorStatusDetails(workbook, firewallDetails)
workbook.close()