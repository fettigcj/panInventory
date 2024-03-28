from pancore import panCore, panExcelStyles
#import panGroupsAndProfiles
import panos_upgrade_assurance
from panos_upgrade_assurance.check_firewall import CheckFirewall
from panos_upgrade_assurance.firewall_proxy import FirewallProxy
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse, re, time, panos, requests, json, copy, zoneinfo, inspect


def getSessionCount(fw_obj):
    try:
        devData = panCore.xmlToLXML(fw_obj.op('show session info'))
    except Exception as exceptionDetails:
        panCore.logging.error(f"    Failed to get session info.")
        panCore.logging.error(f"    Exception details: {exceptionDetails}")
    else:
        activeSessions = devData.xpath('//response/result/num-active')[0].text
        if activeSessions:
            return int(activeSessions)
        else:
            panCore.logging.error(f"    Failed to get session info.")
            return False

parser = argparse.ArgumentParser(
    prog="RebootMaxUptime",
    description="Reboot everything that has not been rebooted since specified date.")
    #epilog="Text")
parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='rebootLog.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="_naas_panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='RebootLog.xlsx')
parser.add_argument('-t', '--timezone', help="Desired timezone in output file", default="US/Eastern")
parser.add_argument('-T', '--Thread_limit', help="Limit number of threads to prevent overwhelming API destination", default=100)
parser.add_argument('-W', '--Wait', help="Seconds to wait before starting next batch of threads in multi-threaded operations.", default=2)
parser.add_argument('-d', '--disabledryrun', help="Default mode is log only. Disable 'Dry Run' to take action", default=False, action='store_true')
parser.add_argument('-S', '--rebootStandalone', help="Default mode will not reboot Stand alone firewalls. Enable this flag to reboot them.", default=False, action='store_true')
parser.add_argument('-D', '--targetDate', help="Target reboot date. Reboot anything that hasn't been rebooted since this date.", default='3/1/2024')
args = parser.parse_known_args()

panCore.startLogging(args[0].logfile)
panCore.configStart(headless=args[0].headless, configStorage=args[0].conffile)
if hasattr(panCore, 'panUser') and panCore.panUser is not None:
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, 'panKey') and panCore.panKey is not None:
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    panCore.logging.critical("Found neither username/password nor API key. Exiting.")
    sys.exit()


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

snapshots_config = [
  'nics',
  'routes',
  'license',
  'arp_table',
  'content_version',
  'session_stats',
  'ip_sec_tunnels']


startTime = datetime.datetime.now(tz=zoneinfo.ZoneInfo(args[0].timezone))
targetDate = datetime.datetime(int(args[0].targetDate.split('/')[2]), int(args[0].targetDate.split('/')[0]), int(args[0].targetDate.split('/')[1]), tzinfo=datetime.timezone.utc)
rebootList = {}
fwCount = len(firewalls)
fwNum = 0
for fw_obj in firewalls:
    fwNum += 1
    if not fw_obj.state.connected:
        panCore.logging.info(f"{fw_obj.serial} is not connected to Panorama. Skipping. ({fwNum}/{fwCount})")
        rebootList[fw_obj.serial] = {**({'hostname': panoInventory[fw_obj.serial]['hostname']} if 'hostname' in panoInventory[fw_obj.serial].keys() else {'hostname': "N/A - Hostname Not Found"}),
                                     'actionTaken': "N/A - Device Offline"}
        continue
    try:
        fwSettings = panos.device.SystemSettings()
        fw_obj.add(fwSettings)
        fwSettings.refresh()
        fwDetails = fw_obj.show_system_info()
        fwTime = datetime.datetime.strptime(fwDetails['system']['time'].strip(), '%a %b %d %H:%M:%S %Y').replace(tzinfo=zoneinfo.ZoneInfo(fwSettings.timezone))
        hostname = fwDetails['system']['hostname']
        uptimeString = fwDetails['system']['uptime']
        uptimeSeconds = int(uptimeString.split(' ')[2].split(':')[2])
        uptimeMinutes = int(uptimeString.split(' ')[2].split(':')[1])
        uptimeHours = int(uptimeString.split(' ')[2].split(':')[0])
        uptimeDays = int(uptimeString.split(' ')[0])
        rebootDate = fwTime - datetime.timedelta(days=uptimeDays, hours=uptimeHours, minutes=uptimeMinutes, seconds=uptimeSeconds)
        haInfo = fw_obj.show_highavailability_state()
        haState = haInfo[0]
        rebootList[fw_obj.serial] = {'hostname': hostname,
                                     'Serial': fw_obj.serial,
                                     'haState': haState,
                                     'haConfigSynced': fw_obj.config_synced(),
                                     'pendingLocalChanges': fw_obj.pending_changes(),
                                     'appVersion': fwDetails['system']['app-version'],
                                     'SW_Version': fwDetails['system']['sw-version'],
                                     'lastRebootTime': rebootDate,
                                     'actionTaken': "None"}
        if rebootDate > targetDate:
            rebootList[fw_obj.serial]['actionTaken'] = f"None needed. Already rebooted after {targetDate}"
            panCore.logging.info(f"{hostname} ({fw_obj.serial}) has been rebooted since {targetDate}. Skipping. ({fwNum}/{fwCount})")
            continue
        else:
            panCore.logging.info(f"{hostname} ({fw_obj.serial}) was last rebooted on {rebootDate} Gathering data to prepare for reboot or HA Suspension. ({fwNum}/{fwCount})")
            if haState == 'disabled':
                if args[0].rebootStandalone:
                    if args[0].disabledryrun:
                        fw_obj.op('request restart system')
                        rebootList[fw_obj.serial]['actionTaken'] = "Rebooted stand-alone firewall as requested."
                        panCore.logging.info(f"\t> Rebooted {hostname} ({fw_obj.serial}) at {datetime.datetime.now(tz=zoneinfo.ZoneInfo(args[0].timezone))}")
                        continue
                    else:
                        rebootList[fw_obj.serial]['actionTaken'] = "[DRY RUN - 'would have'] Rebooted stand-alone firewall as requested."
                        panCore.logging.info(f"\t> [DRY RUN - 'would have'] Rebooted stand-alone firewall as requested.")
                        continue
                else:
                    rebootList[fw_obj.serial]['actionTaken'] = 'Skipped Reboot - Not rebooting stand-alone firewalls'
                    panCore.logging.info(f"\t> 'Skipped Reboot - Not rebooting stand-alone firewalls")
                    continue
            elif haState == 'passive':
                if args[0].disabledryrun:
                    if fw_obj.pending_changes():
                        xmlData = panCore.xmlToLXML(fw_obj.op('show config list changes'))
                        if len(xmlData[0]):
                            rebootList[fw_obj.serial]['actionTaken'] = "Skipped reboot due to pending config changes"
                            panCore.logging.info(f"\t> {hostname} is passive, however it has pending config changes that would be lost in a reboot. Skipping. ({fwNum}/{fwCount})")
                            continue
                        else:
                            panCore.logging.info(f"\t\t {hostname} reported pending changes, but none found.")
                    panCore.logging.info(f"\t> Firewall is passive without pending config changes. rebooting ({fwNum}/{fwCount})")
                    fw_obj.op('request restart system')
                    rebootList[fw_obj.serial]['actionTaken'] = "Rebooted."
                    panCore.logging.info(f"{hostname} ({fw_obj.serial}) Rebooted at {datetime.datetime.now(tz=zoneinfo.ZoneInfo('US/Eastern'))}")
                    continue
                else:
                    rebootList[fw_obj.serial]['actionTaken'] = "[DRY RUN - 'would have'] Rebooted."
                    panCore.logging.info(f"\t> {hostname} ({fw_obj.serial}) needs to be rebooted, but we are in dry run mode. at {datetime.datetime.now(tz=zoneinfo.ZoneInfo('US/Eastern'))}")
                continue
            elif haState == 'active':
                peer_obj = pano_obj.find(panoInventory[fw_obj.serial]['ha.peer.serial'])
                if not peer_obj.state.connected:
                    peerName = "Peer Not In PanoInventory{}"
                    if peer_obj.serial in panoInventory:
                        if 'hostname' in panoInventory[peer_obj.serial]:
                            peerName = panoInventory[peer_obj.serial]['hostname']
                    rebootList[fw_obj.serial]['actionTaken'] = f"Unable to suspend. HA peer ({peerName}) not connected to Panorama."
                    panCore.logging.warning(f"\t {hostname}'s HA peer ({peerName}) is not connected to Panorama. Unable to consider suspension. ({fwNum}/{fwCount})")
                    continue
                peerDetails = peer_obj.show_system_info()
                peerName = peerDetails['system']['hostname']
                fw_obj.set_ha_peers(peer_obj)
                ha_obj = panos.ha.HighAvailability()
                fw_obj.add(ha_obj)
                ha_obj.refresh()
                if not fw_obj.config_synced():
                    rebootList[fw_obj.serial]['actionTaken'] = "Skipped HA Suspension because config not synchronized"
                    panCore.logging.error(f"\t> {hostname} config is not synchronized with {peerName} suspending it might change active behavior. Skipping. ({fwNum}/{fwCount})")
                    continue
                else:
                    preSessions, peerSessions = None, None
                    preSessions = getSessionCount(fw_obj)
                    peerSessions = getSessionCount(peer_obj) #  Don't actually care what this value is, just need to be sure the peer is communicating.
                    if not preSessions or not peerSessions:
                        panCore.logging.error(f"\t> Unable to check pre-session count {hostname} returned {preSessions}. {peerName} returned {peerSessions}. ({fwNum}/{fwCount})")
                        rebootList[fw_obj.serial]['actionTaken'] = f"Unable to suspend. Failed pre-session check: {hostname} returned {preSessions}. {peerName} returned {peerSessions}"
                        continue
                    if args[0].disabledryrun:
                        panCore.logging.info(f"\t> {hostname} is actively running {preSessions} sessions. {peerName} shows {peerSessions}. Suspending {hostname}")
                        fw_obj.op('request high-availability state suspend')
                        time.sleep(10)
                        fw_obj.op('request high-availability state functional')  # This assumes no preemption in HA config that will auto-revert fw_obj to active state when it's made functional again...
                        time.sleep(10)
                        postSessions = getSessionCount(peer_obj)
                        if postSessions < preSessions * .5:
                            panCore.logging.warning(f"\t> {peerName} session count ({postSessions}) not within expected range of {hostname} pre-suspension count ({preSessions}). REVERTING SUSPENSION.")
                            peer_obj.op('request high-availability state suspend')
                            time.sleep(10)
                            peer_obj.op('request high-availability state functional')
                            rebootList[fw_obj.serial]['actionTaken'] = "Attempted to suspend, but had to revert suspension due to session count out of range."
                            time.sleep(10)
                            finalSessionCount = getSessionCount(fw_obj)
                            rebootList[fw_obj.serial]['actionTaken'] = "Reverted HA suspension due to sessions out of range."
                            if finalSessionCount not in range(int((preSessions * .7)), int((preSessions * 1.3))):
                                panCore.logging.error(f"\t\t> ****** ERROR ***** {hostname} FINAL SESSION COUNT ({finalSessionCount}) NOT WITHIN 30 PERCENT OF PRE-SUSPENSION! INVESTIGATE IMMEDIATELY.")
                        else:
                            panCore.logging.info(f"\t> Successfully suspended {hostname} and verified {peerName} operational with {postSessions} running sessions.")
                            rebootList[fw_obj.serial]['actionTaken'] = "Suspended HA to await reboot."
                        continue
                    else:
                        panCore.logging.info(f"\t> Ready to suspend {hostname}, but dry run is enabled. {hostname} reported {preSessions} sessions. {peerName} reported {peerSessions} running sessions.")
                        rebootList[fw_obj.serial]['actionTaken'] = "[DRY RUN - 'would have'] Suspended HA to await reboot."
    except Exception as exception_details:
        panCore.logging.exception(f"ERROR ENCOUNTERED WHILE AUDITING {fw_obj.serial}")
        panCore.logging.exception(exception_details)



                #fwTest_obj = panos_upgrade_assurance.check_firewall.CheckFirewall(panos_upgrade_assurance.firewall_proxy.FirewallProxy(fw_obj))
                #peerTest_obj = panos_upgrade_assurance.check_firewall.CheckFirewall(panos_upgrade_assurance.firewall_proxy.FirewallProxy(peer_obj))
                #fwSnapshot = fwTest_obj.run_snapshots(snapshots_config)






headers = ['hostname', 'Serial', 'haState', 'haConfigSynced', 'pendingLocalChanges', 'appVersion', 'SW_Version', 'lastRebootTime', 'actionTaken']
for reboot in rebootList:
    for key in rebootList[reboot].keys():
        if key not in headers:
            headers.append(key)

panCore.initXLSX(args[0].workbookname)
worksheet = panCore.workbook_obj.add_worksheet("rebootLog")
worksheet.write_row("A1", headers, panCore.workbook_obj.add_format(panExcelStyles.styles['rowHeader']))

test = type(datetime.datetime)
row = 1
for reboot in rebootList:
    col = 0
    for header in headers:
        if header in rebootList[reboot].keys():
            if isinstance(rebootList[reboot][header], datetime.datetime):
                worksheet.write(row, col, rebootList[reboot][header].astimezone(zoneinfo.ZoneInfo('UTC')).strftime("%Y-%m-%d %H:%M:%S"))
            else:
                worksheet.write(row, col, rebootList[reboot][header])
        else:
            worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col +=1
    row +=1

panCore.workbook_obj.close()

