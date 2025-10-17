#!/usr/bin/env python

################################################################################
# script:	PanInventory.py
# by:		Christopher Fettig, Palo Alto Networks
# rqmts:	Panorama IP Address, [username, password]
#
# © 2020 Palo Alto Networks, Inc.  All rights reserved.
#
################################################################################
"""
Changelog
2023-11-08: Started Project
2023-11-29: Base functionality finished.
2024-01-03: Reformat SMTP to utilize arg parser input, reconfigured 'firewalls' input to accept txt file input optionally
2024-01-29: added 5 second wait after HA swap and changed from fw_obj."suspend peer" to peer_obj."suspend Self"
            logic after seeming false positive in session count mismatch.

"""

#Import custom library modules
from pancore import panCore, panExcelStyles
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse, re, time, panos, smtplib
#from email.message import EmailMessage
from email.mime.text import MIMEText

parser = argparse.ArgumentParser(
    prog="FirewallUpgrade",
    description="UpgradeFirewalls.")
    #epilog="Text")

parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='upgrade-firewalls.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='upgradeFirewalls.xlsx')
parser.add_argument('-m', '--maxUpgrades', help="Maximum upgrades (and thus reboots) to perform on a firewall.", default=5)
parser.add_argument('-V', '--targetVersion', help="What version to upgrade to", default="10.2.9-h1")
parser.add_argument('-A', '--upgradeActive', help="Suspend & upgrade active IF passive already upgraded.", default=False, action='store_true')
parser.add_argument('-U', '--enableUpgrade', help="Enable upgrading of firewalls. Otherwise report only", default=False, action='store_true')
parser.add_argument('-S', '--upgradeStandalone', help='Upgrade & Reboot non-HA firewalls. WILL CAUSE OUTAGE DURING REBOOT.', default=False, action='store_true')
parser.add_argument('-E', '--mailEnable', help='Enable SMTP e-mail reporting.', default=False, action='store_true')
parser.add_argument('-F', '--mailFrom', help='SMTP source address')
parser.add_argument('-T', '--mailTo', help='SMTP destination address')
parser.add_argument('-M', '--Mailserver', help='SMTP server address')
parser.add_argument('-f','--filename', help='file containing line break separated serial number list to limit scope.')
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

# If a filename was specified override the 'firewalls' list retrieved from panorama
# with the explicit serial numbers in the file
if args[0].filename:
    panCore.logging.info(f"Filename set to {args[0].filename}. Attempting to retrieve firewall list from text file")
    firewalls = []
    with open(args[0].filename) as file:
        for line in file:
            firewalls.append(line.rstrip())
    panCore.logging.info(f"Serial numbers retrieved from list: {firewalls}")



def sendmail(fileName, fwName, reason, sessionCountInRange):
    with open(fileName, 'r', newline=None) as contents:
        bodyContent = contents.read()
    body = ""
    for line in bodyContent.splitlines():
        body += line + "<BR>"
    msg = MIMEText(body)
    if startingVersion == endingVersion:
        msg['Subject'] = f"{fwName} Not Upgraded ({reason})"
    else:
        if sessionCountInRange:
            msg['Subject'] = f"{fwName} Cleanly upgraded ({reason})"
        else:
            msg['Subject'] = f"{fwName} Upgraded ({reason}) POST UPGRADE SESSION COUNT OUT OF RANGE"
    msg['From'] = args[0].mailFrom
    msg['To'] = args[0].mailTo
    msg['Content-Type'] = 'text/html'
    sender = smtplib.SMTP(args[0].Mailserver)
    sender.send_message(msg)
    sender.quit()


def sendAttachment(fileName, fwName):
    print('cebu')


def getFirewall(firewall):
    if type(firewall) == str:
        fw_obj = pano_obj.find(firewall)
        if fw_obj == None:
            panCore.logging.exception(f"Unable to find {firewall} in Panorama Inventory. Check serial number.")
            return False, False
    elif isinstance(firewall, panos.firewall.Firewall):
        fw_obj = firewall
    else:
        panCore.logging.error("Received neither string containing serial number "
                              "nor fw_obj. Invalid input. Investigate.")
        return False, False
    try:
        sysState = fw_obj.show_system_info()
    except Exception as exceptionDetails:
        panCore.logging.warning(f"Failed to retrieve system info for {fwSerial} ({fwName}).")
        panCore.logging.warning(f"Exception details: {exceptionDetails}")
        return False, False
    else:
        return fw_obj, sysState

def checkSessionSync():
    try:
        syncState = panCore.xmlToLXML(fw_obj.op('show high-availability state-synchronization'))
        if syncState.xpath('/response/result/sync_conf')[0].text == "True":
            panCore.logging.info(f"    > {fwName} Session table is syncronized between HA nodes.")
            return True
        else:
            panCore.logging.warning(f"    > Session table for {fwName} ({fwSerial}) is not in sync with HA pair. Investigate.")
            return False
    except Exception as exceptionDetails:
        panCore.logging.warning(f"    > Failed to retrieve system info for {fwSerial} ({fwName}).")
        panCore.logging.warning(f"    > Exception details: {exceptionDetails}")
        return False


def checkUpgradabilityPassive():
    sessionsSynchronized = checkSessionSync()
    if not sessionsSynchronized:
        panCore.logging.warning(f"{fwName} session table NOT synchronized with its HA peer.")
        return False, "SessionNotSynced"
    #if fw_obj.pending_changes():
    #    panCore.logging.warning(f"    There are pending changes in the local configuration of {fwName}. Please investigate.")
    #    return False, "Pending Config Changes"
    return True, "ReadyToUpgrade"

def checkUpgradabilityStandalone():
    if not args[0].upgradeStandalone:
        panCore.logging.info(f"   > {fwName} can't be auto-upgraded as it doesn't appear to be in an HA pair.\r\n"
                             f"   > It's running {startingVersion}. To force upgrade re-run with 'upgradeStandalone = True'")
        return False, "UpgradeStandaloneNotSet"
    panCore.logging.info(f"   > {fwName} is stand alone, but script was called with 'upgradeStandalone = True'\r\n"
                         f"   > Continuing as instructed.")
    if fw_obj.pending_changes():
        panCore.logging.warning(f"    There are pending changes in the local configuration of {fwName}. Please investigate.")
        return False, "PendingConfigChanges"
    panCore.logging.info(f"    > {fwName} does not have changes pending in the local config. Continuing upgrade procedure.")
    return True, "ReadyToUpgrade"

def checkUpgradabilityActive():
    #global major, minor, maint, hotfix
    if args[0].upgradeActive == False:
        panCore.logging.info(f"    > {fwName} is Active, and script was called with 'upgradeActive = False'.\r\n)"
                             f"    > To force ugprade of active nodes set 'upgradeActive' to 'True'.")
        return False, "Upgrade Active Not Set"
    panCore.logging.info(f"    > {fwName} is Active, but script was called with 'upgradeActive = True'.\r\n"
                         f"    > Continuing as instructed.")
    sessionsSynchronized = checkSessionSync()
    if not sessionsSynchronized:
        return False, "Sessions Not Synced"
    if fw_obj.pending_changes():
        panCore.logging.warning(
            f"    There are pending changes in the local configuration of {fwName}. Please investigate.")
        return False, "Pending Config Changes"
    peerSerial = panoInventory[fwSerial]['ha.peer.serial']
    peer_obj, peerState = getFirewall(peerSerial)
    if not peer_obj:
        panCore.logging.error(f"{fwName} HA peer unavailable. Unable to continue. ")
        return False, "HA Peer Unavailable"
    peerName = peerState['system']['hostname']
    peerVersion = peerState['system']['sw-version'].split('.')
    peerMajor, peerMinor, peerMaint = peerVersion
    panCore.logging.info(f"    > {fwName}'s HA peer ({peerName} {peerSerial}) is running {peerVersion}.")
    if 'h' in peerMaint:
        peerMaint, peerHotfix = peerMaint.split('-h')
    else:
        peerMaint, peerHotfix = peerMaint, "0"
    peerMajor, peerMinor, peerMaint, peerHotfix = int(peerMajor), int(peerMinor), int(peerMaint), int(peerHotfix)
    if (
            (peerMajor < major) or
            (peerMajor == major and peerMinor < minor) or
            (peerMajor == major and peerMinor == minor and peerMaint < maint) or
            (peerMajor == major and peerMinor == minor and peerMaint == maint and peerHotfix <= hotfix)
    ):
        panCore.logging.warning(f"    > {fwName} is active, but its peer's PAN-OS version not greater than its own. Skipping upgrade until peer is upgraded.")
        return False, "Pending Passive Upgrade"
    if not args[0].enableUpgrade:
        panCore.logging.info(f"    > {fwName} is active, and script was called with 'upgradeActive == True' and Passive PAN-OS version is greater than its own. However 'enableUpgrade' flag is NOT set. Standing down...")
        return False, "Reporting Only"
    panCore.logging.info(f"    > {fwName} is active, but script was called with 'upgradeActive == True' and Passive PAN-OS version is greater than its own. Proceeding to suspend Active firewall and ugprade. ")
    preSessions = getSessionCount(fw_obj)
    fw_obj.op('request high-availability state suspend')
    time.sleep(5)
    fw_obj.op('request high-availability state functional')  # This assumes no preemption in HA config that will auto-revert active state...
    time.sleep(5)
    postSessions = getSessionCount(peer_obj)
    if postSessions not in range(int((preSessions * .7)),int((preSessions * 1.3))):
        panCore.logging.warning(f"    > {peerName} session count ({postSessions}) not within 30 percent of {fwName} pre-suspension count ({preSessions}). REVERTING SUSPENSION.")
        peer_obj.op('request high-availability state suspend')
        time.sleep(5)
        peer_obj.op('request high-availability state functional')
        return False, "Session Count Range Error"
    else:
        panCore.logging.info(f"    > {fwName} successfully suspended. Pre-suspension session count ({preSessions}) {peerName} session count ({postSessions}) within 30 percentage points ")
        return True, "ReadyToUpgrade"

def upgradeFirewall():
    if not args[0].enableUpgrade:
        panCore.logging.info(f"    > Upgrade function called, but 'reportOnly' mode is active as 'enableUpgrade' flag is not set. Skipping actual upgrade.")
        return
    try:
        fw_obj.software.upgrade_to_version(args[0].targetVersion)
    except Exception as exceptionDetails:
        panCore.logging.info(f"    > Started upgrade for {fwName} ({fwSerial})...")
        panCore.logging.info(f"    > Exception details: {exceptionDetails}")
        time.sleep(240)
        # Since 'sync_reboot' function not workable 'disconnected' error expected during reboot.
    else:
        panCore.logging.info(f"    > No Exceptions encountered. Firewall Upgrade process completed.")
        # This will only become viable if pan-os-python 'sync_reboot' functionality fixed.
        # assuming code is fixed and upgrade and reboots successful without error skip following exception handling.
        return
    doneUpgrading = False
    tryCount = 0
    while not doneUpgrading:
        if tryCount <= 20:
            try:
                #fw_obj.show_system_info()
                fw_obj.refresh_system_info()
            except Exception as exceptionDetails:
                panCore.logging.info(f"    > Still rebooting. Connection attempt #{tryCount}")
                panCore.logging.info(f"    > Exception details: {exceptionDetails}")
                time.sleep(30)
                tryCount += 1
            else:
                upgradeTime = datetime.datetime.now(datetime.timezone.utc)
                endingVersion = fw_obj.version.split('.')
                major, minor, maint = startingVersion
                if 'h' in maint:
                    maint, hotfix = maint.split('-h')
                else:
                    maint, hotfix = maint, "0"
                panCore.logging.info(f"    > {fwName} ({fwSerial}) upgraded to {endingVersion}. ({fwNum}/{fwCount}) at {upgradeTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
                doneUpgrading = True
        else:
            panCore.logging.error(
                f"    > {fwSerial} ({fwName}) is still not back online after 20x 30 second retries (10 minutes). Investigate please.")
            doneUpgrading = True
    return

def upgradeChecker():
    #global upgradeable, major, minor, maint, hotfix, sessionCountInRange
    if (
            (major > targetMajor) or
            (major == targetMajor and minor > targetMinor) or
            (major == targetMajor and minor == targetMinor and maint > targetMaint) or
            (major == targetMajor and minor == targetMinor and maint == targetMaint and hotfix >= targetHotfix)
    ):
        panCore.logging.info(f"    > {fwName} ({fwSerial}) already running PAN-OS {startingVersion} which is >= target PAN-OS {args[0].targetVersion}. Skipping")
        return False, "alreadyUpgraded"
    else:
        panCore.logging.info(f"    > {startingVersion} seems to be less than {args[0].targetVersion}. Checking if we can upgrade.")
    if haState is None:
        panCore.logging.error(f"    > {fwName} ({fwSerial}) failed to return valid HA state. Skipping.)")
        reason = 'Invalid HA'
        upgradeable = False
    elif haState[0] == 'passive':
        panCore.logging.info(f"    > {fwName} is passive. Checking Upgradability.")
        upgradeable, reason = checkUpgradabilityPassive()
    elif haState[0] == 'active':
        panCore.logging.info(f"    > {fwName} is active. Checking Upgradability.")
        upgradeable, reason = checkUpgradabilityActive()
    elif haState[0].lower() == 'active-secondary' or haState[0].lower() == 'active-primary':
        panCore.logging.info(f"    > {fwName} is active-active. Checking Upgradability as 'standalone'.")
        upgradeable, reason = checkUpgradabilityStandalone()
    else:
        panCore.logging.info(f"    > {fwName} is stand-alone. Checking Upgradability.")
        upgradeable, reason = checkUpgradabilityStandalone()
    panCore.logging.info(f"    > {fwName} finished upgrade checker. Upgradeable: {upgradeable} Reason: {reason}")
    return upgradeable, reason



def takeBackup():
    try:
        config = panCore.xmlToLXML(fw_obj.op('show config running'))
        with open(f"{fwName}_Config.xml", "w") as outFile:
            outFile.write(str(panCore.ET.tostring(config, pretty_print=True, encoding=str)))
    except Exception as exceptionDetails:
        panCore.logging.error(f"\t\t> Failed to backup firewall.")
        panCore.logging.error(f"\t\t> Exception details: {exceptionDetails}")
        return False
    else:
        panCore.logging.info(f" >    Backup of running config taken and stored as {fwName}_Config.xml")
        return True


def getSessionCount(fw):
    try:
        devData = panCore.xmlToLXML(fw.op('show session info'))
    except Exception as exceptionDetails:
        panCore.logging.error(f"    Failed to get session info.")
        panCore.logging.error(f"    Exception details: {exceptionDetails}")
    else:
        activeSessions = devData.xpath('//response/result/num-active')[0].text
        if activeSessions:
            return int(activeSessions)
        else:
            panCore.logging.error(f"    Failed to get session info.")

def getPanoInventory():
    panCore.logging.info("Gathering Panorama inventory data")
    try:
        xmlData = panCore.xmlToLXML(pano_obj.op(cmd="show devices all"))
    except Exception as exceptionDetails:
        panCore.logging.fatal(f"    Failed to get Panorama inventory because {exceptionDetails}")
        exit("Failed to get Panorama Inventory. Unable to connect to Panorama and continue.")
    else:
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
        return panCore.devData


fwCount = len(firewalls)
targetMajor, targetMinor, targetMaint = args[0].targetVersion.split('.')
if '-h' in targetMaint:
    targetMaint, targetHotfix = targetMaint.split('-h')
else:
    targetMaint, targetHotfix = targetMaint, "0"
targetMajor, targetMinor, targetMaint, targetHotfix = int(targetMajor), int(targetMinor), int(targetMaint), int(targetHotfix)


devData = {}
fwNum = 0
auditStartTime = datetime.datetime.now(datetime.timezone.utc)
panCore.logging.info(f"Starting audit at {auditStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
panoInventory = getPanoInventory()
for firewall in firewalls:
    fwStartTime = datetime.datetime.now(datetime.timezone.utc)
    fwNum += 1
    fw_obj, sysState = getFirewall(firewall)
    if not fw_obj:
        panCore.logging.error(
            f"    > Unable to retrieve fw_obj for {fwSerial} ({fwNum}/{fwCount}) at {fwStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
        continue # If getFirewall() returns "False" errors were logged. Skip invalid SN or fw_obj.
    if not fw_obj.state.connected:
        panCore.logging.error(f"    > Device Offline: {fwSerial} ({fwNum}/{fwCount}) at {fwStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
        continue
    fwName = sysState['system']['hostname']
    fwSerial = sysState['system']['serial']
    startingVersion = sysState['system']['sw-version'].split('.')
    major, minor, maint = startingVersion
    if 'h' in maint:
        maint, hotfix = maint.split('-h')
    else:
        maint, hotfix = maint, "0"
    major, minor, maint, hotfix = int(major), int(minor), int(maint), int(hotfix)
    panCore.fwLogger = panCore.logging.handlers.RotatingFileHandler(f"{fwName}.log", mode='w',  encoding='utf-8')
    panCore.fwLogger.setLevel(panCore.logging.DEBUG)
    panCore.fwLogger.setFormatter(panCore.logging.Formatter('%(message)s'))
    panCore.logger.addHandler(panCore.fwLogger)
    panCore.logging.info(f"\t Examining {fwName} ({fwSerial}) running {startingVersion}. ({fwNum}/{fwCount}) at {fwStartTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    panCore.logging.info("\t\t Trying to gather HA config.")
    try:
        haState = fw_obj.show_highavailability_state()
    except Exception as exceptionDetails:
        panCore.logging.error(f" >    Failed to get HA state to calculate upgradeability.")
        panCore.logging.error(f" >    Exception details: {exceptionDetails}")
        continue
    sessionCountInRange = upgradeable = True  # set value in outer scope so they can be modified in function
    upgradeable, reason = upgradeChecker()
    if not upgradeable:
        panCore.logging.warning(f"\t> {fwName} Not upgradable because {reason}.")
        endingVersion = startingVersion
    else:
        panCore.logging.info(f"\t>{fwName} marked upgradeable by upgradeChecker(). Checking if upgrades are enabled.")
        if args[0].enableUpgrade:
            backupTaken = takeBackup()
            if backupTaken:
                upgradeCounter = 1
                doneUpgrading = False
                while doneUpgrading == False and upgradeCounter <= args[0].maxUpgrades:
                    preUpgradesessionCount = getSessionCount(fw_obj)
                    panCore.logging.info(f"\t> Pre-upgrade ({upgradeCounter}) session count for {fwName}: {preUpgradesessionCount}")
                    upgradeFirewall()
                    time.sleep(60)
                    postUpgradeSessionCount = getSessionCount(fw_obj)
                    panCore.logging.info(f"\t> Post-upgrade ({upgradeCounter}) session count for {fwName}: {postUpgradeSessionCount}")
                    if postUpgradeSessionCount in range(int((preUpgradesessionCount *.5)),int((preUpgradesessionCount *1.5))):
                        panCore.logging.info(f"Post upgrade session count ({postUpgradeSessionCount}) within 50 percentage points of pre-upgrade session count ({preUpgradesessionCount}).")
                        sessionCountInRange = True
                    else:
                        panCore.logging.warning(f"Post upgrade session count ({postUpgradeSessionCount}) outside of expected 50 percentage point range of pre-upgrade session count ({preUpgradesessionCount}). Aborting further upgrades, if any pending.")
                        sessionCountInRange = False
                        doneUpgrading = True
                    upgradeTime = datetime.datetime.now(datetime.timezone.utc)
                    fw_obj.refresh_system_info()
                    endingVersion = fw_obj.version.split('.')
                    panCore.logging.info(f"\t {fwName} ({fwSerial}) upgrade {upgradeCounter} Done. Running {endingVersion} now. Was running {startingVersion} ({fwNum}/{fwCount}) Finished at: {upgradeTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
                    if endingVersion == args[0].targetVersion.split('.'):
                        doneUpgrading = True
                    upgradeCounter += 1
                else:
                    panCore.logging.warning(f"\t\t> Backup failure for {fwName}. Investigate")
        else:
            panCore.logging.info("Enable upgrade not set.")
            endingVersion = startingVersion
    panCore.logger.removeHandler(panCore.fwLogger)
    panCore.fwLogger.close()
    devData[fwSerial] = {
        'serial': fwSerial,
        'hostname': fwName,
        'haState': haState[0],
        'upgradeable': upgradeable,
        'details': reason,
        'startingVersion': startingVersion,
        #**({'endingVersion': endingVersion} if 'endingVersion' in locals() else {}),
        'endingVersion': endingVersion
    }
    if args[0].mailEnable:
        sendmail(f"{fwName}.log", fwName, reason, sessionCountInRange)

headers = ['serial', 'hostname', 'haState', 'upgradeable', 'details', 'startingVersion', 'endingVersion']
workbook_obj = xlsxwriter.Workbook(args[0].workbookname)
worksheet = workbook_obj.add_worksheet('Firewalls')
worksheet.write_row('A1', headers, workbook_obj.add_format(panExcelStyles.styles['rowHeader']))
row = 1
for fw in devData.keys():
    col = 0
    for header in headers:
        if header in devData[fw].keys():
            worksheet.write(row, col, str(devData[fw][header]))
        else:
            worksheet.write(row, col, "", panCore.workbook_obj.add_format((panExcelStyles.styles['blackBox'])))
        col += 1
    row +=1
workbook_obj.close()
