#from panInventory import clusterDetails
from pancore import panCore
import panos
from panos.panorama import Panorama
from panos.firewall import Firewall
from panos.network import Zone
from panos.device import SystemSettings, SyslogServer, SyslogServerProfile
from typing import Dict, List, Tuple, Union, Any
import lxml, logging, copy, re
from datetime import datetime
logger = logging.getLogger(__name__)


def strip_template_keys(data):
    """Recursively remove keys containing @ptpl or @src."""
    if isinstance(data, dict):
        return {
            key: strip_template_keys(value)
            for key, value in data.items()
            if "@ptpl" not in key and "@src" not in key
        }
    return data


def panorama_showDevicesAll(pano_obj: Panorama) -> dict:
    """
    List all firewalls connected to this panorama, return as dictionary.
    :param pano_obj: the panos.panorama.Panorama object to query.
    :return: dictionary of firewalls connected to this panorama.
    """
    logger.info("\tParsing 'Show devices all'")
    xmlData = panCore.xmlToLXML(pano_obj.op(cmd="show devices all"))
    panCore.devData = {}
    panCore.headers = []
    for firewall in xmlData.xpath('//devices/entry'):
        fwSerial = firewall.get('name')
        panCore.devData[fwSerial] = {}
        for child in firewall.getchildren():
            if len(child):
                panCore.iterator(child, fwSerial)
            else:
                panCore.devData[fwSerial][child.tag] = child.text
                if child.tag not in panCore.headers:
                    panCore.headers.extend([child.tag])
    return panCore.devData

def panorama_Templates(templates: List, tStacks: List) -> Dict:
    """
    Parses a list of panos.panorama.Template objects and returns information about them.
    :param templates: panos.panorama.Template objects to parse.
    :return: dictionary of template information.
    """
    logger.info("\tParsing pan-os-python template objects")
    templateData = {}
    for tpl_obj in templates:
        tplName = tpl_obj.about()['name']
        tplVars = tpl_obj.findall(panos.panorama.TemplateVariable)
        templateData[tplName] = tpl_obj.about()
        templateData[tplName]['variables'] = {}
        templateData[tplName]['usedInStacks'] = []
        varNum = 1
        for tplVar in tplVars:
            templateData[tplName]['variables'][varNum] = tplVar.about()
            varNum += 1
    for stk_obj in tStacks:
        for tplName in stk_obj.about()['templates']:
            templateData[tplName]['usedInStacks'].append(stk_obj.about()['name'])
    return templateData


def panorama_ParseStackData(tStacks: List) -> Dict:
    """
    Accept a list of panos.panorama.TemplateStack objects and return a dictionary of template stack information.

    :param tStacks:
    :return:
    """
    logger.info("\tParsing pan-os-python template stack objects")
    tStackData = {}
    for stk_obj in tStacks:
        stkName = stk_obj.about()['name']
        stkVars = stk_obj.findall(panos.panorama.TemplateVariable)
        tStackData[stkName] = stk_obj.about()
        tStackData[stkName]['variables'] = {}
        varNum = 1
        for stkVar in stkVars:
            tStackData[stkName]['variables'][varNum] = stkVar.about()
            varNum += 1
    return tStackData


def either_ShowSystemInfo(pan_obj: Union[panos.panorama.Panorama, panos.firewall.Firewall], fwNameSerial) -> Dict:
    """
    Take a PAN-OS-Python object (Firewall or Panorama) and return a dictionary of system information.
    Use panCore.iterator to flatten into Key:Value pairs rather than fw_obj.show_system_info() to avoid returning nested dictionaries.
    :param fw_obj:
    :return:
    """
    logger.info(f"\tParsing 'show system info for {type(pan_obj)} ({fwNameSerial})'")
    xmlData = panCore.xmlToLXML(pan_obj.op("show system info"))
    panCore.devData = {fwNameSerial: {}}  # Nested dictionary to conform to panCore.iterator expected input.
    panCore.headers = []
    for setting in xmlData.xpath("./result/system")[0].getchildren():
        panCore.iterator(setting, fwNameSerial)
    return panCore.devData[fwNameSerial]

def firewall_SystemState(fw_obj: panos.firewall.Firewall):
    logger.info(f"\tParsing 'show system state'")
    xmlData = panCore.xmlToLXML(fw_obj.op('show system state'))
    sysStateLines = (xmlData[0].text).split("\n")
    sysState = {}
    for line in sysStateLines:
        line = line.replace(", }", " }")  # Get rid of any trailing commas after the last item as it would break later conversion to dictionary object
        if len(line) < 2 or line[-1] == ':':
            # Skip line if it has nothing to import.
            #print(f"Skipping line: {line}")
            pass
        elif ":" not in line:
            sysState[oldKey] = sysState[oldKey] + line
            #print(f"Appended {line} to {sysState[oldKey]}")
            pass
        else:
            key, val = line.split(":", 1)
            oldKey = key
            sysState[key] = str(val)
    return sysState

def firewall_SystemEnvironmentals(fw_obj: panos.firewall.Firewall) -> Dict:
    """
    Accept a panos.firewall.Firewall object and return a dictionary of environmental data.
    :param fw_obj:
    :return:
    """
    logger.info(f"\tParsing 'show system environmentals'")
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

def firewall_SyslogProfiles(fw_obj: panos.firewall.Firewall) -> Dict:
    logger.info(f"\tParsing configured syslog profiles.")
    xmlData = panCore.xmlToLXML(fw_obj.xapi.get('/config/shared/log-settings/syslog'))
    if not len(xmlData[0]):
        return
    # Multi-vsys xpath?
    # /devices/entry[@name='<device_name>']/vsys/entry[@name='<vsys_name>']/log-settings/syslog/
    # why doesn't panos.device.SyslogServerProfile.refreshall(fw_obj) work in single vsys mode?? Would it work on a multi-vsys device?
    syslogProfiles = {}
    for profile in xmlData.xpath('/response/result/syslog/entry'):
        profileName = profile.get('name')
        syslogProfiles[profileName] = {'servers': {},'customFormats': {}}
        for server in profile.xpath('./server/entry'):
            serverName = server.get('name')
            panCore.headers = []
            panCore.devData = {serverName: {}}
            for child in server.getchildren():
                panCore.iterator(child, serverName)
            syslogProfiles[profileName]['servers'][serverName] = panCore.devData[serverName]
        if profile.xpath('./format'):
            for customFormat in profile.xpath('./format')[0].getchildren():
                syslogProfiles[profileName]['customFormats'][customFormat.tag] = customFormat.text
    return syslogProfiles


def firewall_DeviceLogSettings(fw_obj: panos.firewall.Firewall) ->  Dict:
    logger.info("\tGathering device log configuration...")
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
    return deviceLogConfig


def firewall_LogCollectorStatus(fw_obj: panos.firewall.Firewall) -> Dict:
    """
    Execute `show logging-status verbose yes` and return parsed-only data.
      {
        'fw_serial': <serial or None>,
        'details': {
           <entry_name>: {
              'kv':   { <iterator key>: <trimmed value | datetime> },
              'logs': { <log-tag>: {type,last_created,last_forwarded,last_seq_forwarded,last_seq_acked,total_forwarded}
                                | {type,'not_available': True}
                                | {type,'error':'unparsed'} }
           },
           ...
        },
        'summary': { <key>: <trimmed value | datetime> }
      }
    - Verbose:yes required to cause PAN-OS to minimally structure the output rather than barf unstructured strings of information that would only be human-readable if printed to string in monospaced font.
        even with verbose flag information about each log type is unstructured and must be parsed into key:value pairs for data reporting purposes
    - Single inline token loop per value converts any YYYY/MM/DD + HH:MM:SS pairs to datetime objects.
    - Classification (kv vs logs) happens after datetimes are removed from the residual text.
    """

    logger.info("\t> Gathering log collector status")

    xmlData = panCore.xmlToLXML(fw_obj.op(
            cmd="<show><logging-status><verbose>yes</verbose></logging-status></show>",
            cmd_xml=False,
        )
    )

    result: Dict = {
        'fw_serial': getattr(fw_obj, 'serial', None),
        'details': {},
        'summary': {},
    }

    # Simple patterns used inline
    regexPattern_Date = re.compile(r"^\d{4}/\d{2}/\d{2}$")
    regexPattern_Time = re.compile(r"^\d{2}:\d{2}:\d{2}$")
    regexPattern_KeyValueSplit = re.compile(r"^\s*[^:]{1,80}\s*:\s*")  # label ":" with optional spaces around it, anchored at start
    expectedLogTypes = {
        'traffic', 'threat', 'hipmatch', 'gtp', 'auth', 'iptag',
        'userid', 'sctp', 'decryption', 'config', 'system', 'globalprotect'
    }

    # --- Per-collector entries ---
    for logCollector in xmlData.xpath('//response/result/show-logging-status/Conn-Info/entry'):
        collectorName = logCollector.get('name') or ''

        # Flatten this entry with the iterator
        panCore.headers = []
        panCore.devData = {collectorName: {}}
        for child in logCollector.getchildren():
            panCore.iterator(element=child, item=collectorName, deleteEntryTag=False)
        flat_entry = strip_template_keys(panCore.devData.get(collectorName, {}))

        parsed_record = { 'kv': {'failureDetected': False}, 'logs': {} }

        for key, raw_value in flat_entry.items():
            # Normalize to string and collapse whitespace
            value = raw_value if isinstance(raw_value, str) else ("" if raw_value is None else str(raw_value))
            value = " ".join(value.strip().split())

            # Determine tag name (last path component)
            tag = key.split('.')[-1]
            tag_lower = tag.lower()

            if tag_lower in expectedLogTypes:
                # Parse as a log row using simple positional tokens
                tokens = value.split() if value else []
                # log type repeats in xml text. Not needed since xml node already tells log type.
                if tokens and tokens[0].lower() == tag_lower:
                    tokens = tokens[1:]

                # Handle log types which this firewall doesn't generate.
                #if len(tokens) >= 2 and tokens[0].lower() == 'not' and tokens[1].lower() == 'available':
                if "not available" in value.lower():
                    parsed_record['logs'][tag_lower] = {
                        'type': tag_lower,
                        'last_created': 'N/A - log type not generated',
                    }
                    continue

                # Expected tokens: ["date", "time", "date", "time", "seq", "seq", "total"]
                if len(tokens) == 7:
                    parsed_record['logs'][tag_lower] = {
                        'type': tag_lower,
                        'last_created': f"{tokens[0]} {tokens[1]}",
                        'last_forwarded': f"{tokens[2]} {tokens[3]}",
                        'last_seq_forwarded': tokens[4],
                        'last_seq_acked': tokens[5],
                        'total_forwarded': tokens[6],
                    }
                else:
                    parsed_record['logs'][tag_lower] = {'unparsedData': value}
            else:
                # Treat as KV: trim on the first colon if present; otherwise keep as-is
                if isinstance(value, str) and ":" in value:
                    left_right = value.split(":", 1)
                    trimmed = left_right[1].strip() if len(left_right) == 2 else value
                else:
                    trimmed = value

                parsed_record['kv'][key] = trimmed

                # Flip failureDetected flag if any stage/status indicates failure
                try:
                    if str(key).lower().endswith('.status') and isinstance(trimmed, str) and trimmed.strip().lower() == 'failure':
                        parsed_record['kv']['failureDetected'] = True
                except Exception:
                    pass

        result['details'][collectorName] = parsed_record

    # --- Summary (ConnStatus) parsed only ---
    status_block = xmlData.xpath('//response/result/show-logging-status/Conn-Info/ConnStatus')
    if status_block:
        status_elem = status_block[0]
        panCore.headers = []
        panCore.devData = {'ConnStatus': {}}
        for child in status_elem.getchildren():
            panCore.iterator(element=child, item='ConnStatus', deleteEntryTag=False)
        flat_status = strip_template_keys(panCore.devData.get('ConnStatus', {}))

        parsed_summary = {}
        for key, raw_value in flat_status.items():
            value = raw_value if isinstance(raw_value, str) else ("" if raw_value is None else str(raw_value))
            value = " ".join(value.strip().split())
            # Trim simple "label : value" if present
            if ":" in value:
                parts = value.split(":", 1)
                value = parts[1].strip() if len(parts) == 2 else value
            # If the remaining value is exactly one datetime, convert it
            tokens = value.split()
            if len(tokens) == 2 and regexPattern_Date.match(tokens[0]) and regexPattern_Time.match(tokens[1]):
                try:
                    parsed_summary[key] = datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
                except Exception:
                    parsed_summary[key] = value
            else:
                parsed_summary[key] = value

        result['summary'] = parsed_summary
        result['summary']['configuredCollectors'] = list(result['details'].keys())

    return result

def firewall_Interfaces(fw_obj: panos.firewall.Firewall) -> Dict[str, dict]:
    logger.info("\tGathering interface info...")
    ifData = {'logical': {}, 'hardware': {}}
    ifData['fullDetails'] = {}
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
        logger.info("\tGathering detailed interface info for {0}".format(ifName))
        try:
            ifDetails = panCore.xmlToLXML(fw_obj.op(cmd=f"<show><interface>{ifName}</interface></show>", cmd_xml=False))
        except:
            logger.warning(f"\t****> FAILED GATHERING DETAILED INTERFACE INFO FOR {ifName}")
            pass
        panCore.headers = []
        panCore.devData = {ifName: {}}
        for ifDetail in ifDetails.xpath('/response/result')[0].getchildren():
            panCore.iterator(element=ifDetail,item=ifName,deleteEntryTag=False)
        ifData['fullDetails'].update(panCore.devData)
    return ifData

def firewall_schedules(getConf: lxml.etree) -> Dict[str, dict]:
    logger.info("\t> Gathering dynamic content update schedule information...")
    # xmlData = panCore.xmlToLXML(fw_obj.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/update-schedule"))
    # Replacing separate 'get' requests with recycling cached config used below.
    panCore.devData = {'schedules': {}}
    expectedSchedules = ['anti-virus', 'app-profile', 'global-protect-clientless-vpn', 'global-protect-datafile',
                         'statistics-service', 'threats', 'url-database', 'wf-private', 'wildfire']
    foundSchedules = []
    for schedule in getConf.xpath('/response/result/config/devices/entry[@name="localhost.localdomain"]/deviceconfig/system/update-schedule')[0].getchildren():
        if len(schedule):
            panCore.iterator(schedule, "schedules")
    for schedule in panCore.devData['schedules']:
        foundSchedules.extend([schedule.split('.')[0]])
        #split "global-protect-datafile.recurring.none@src" and just select "global-protect-datafile" to record as 'found'
    for schedule in expectedSchedules:
        if schedule not in foundSchedules:
            panCore.devData['schedules'][schedule] = "Not Configured"
    return(panCore.devData['schedules'])


def firewall_ZoneData(fw_obj: panos.firewall.Firewall) -> Dict:
    logger.info("\t> Gathering zones attached to this firewall...")
    fwZones = panos.network.Zone.refreshall(fw_obj)
    zoneData = {}
    for zone_obj in fwZones:
        zoneData[zone_obj.about()['name']] = zone_obj.about()
    return zoneData


def either_LicenseInfo(object: Union[panos.firewall.Firewall, panos.panorama.Panorama]) -> Dict:
    logger.info(f"\t> Gathering license information from {object}...")
    xmlData = panCore.xmlToLXML(object.op('request license info'))
    panCore.devData = {'licenseInfo': {}}
    panCore.headers = []
    for license in xmlData.xpath('//response/result/licenses')[0].getchildren():
        panCore.iterator(license, 'licenseInfo')
    return panCore.devData['licenseInfo']

def firewall_ResourceMonitorHistory(fw_obj: panos.firewall.Firewall) -> Dict[str, dict]:
    logger.info("\t> Gathering resource monitor history...")
    xmlData = panCore.xmlToLXML(fw_obj.op('show running resource-monitor hour'))
    resourceMonitorHistory = {
        'cpuAverage': {},
        'cpuMaximum': {},
        'resourceUtilization': {}}
    for dataProcessor in xmlData.xpath('//response/result/resource-monitor/data-processors')[0].getchildren():
        for cpuCore in dataProcessor.xpath('./hour/cpu-load-average/entry'):
            resourceMonitorHistory['cpuAverage'][cpuCore.xpath('./coreid')[0].text] = cpuCore.xpath('./value')[0].text
        for cpuCore in dataProcessor.xpath('./hour/cpu-load-maximum/entry'):
            resourceMonitorHistory['cpuMaximum'][cpuCore.xpath('./coreid')[0].text] = cpuCore.xpath('./value')[0].text
        for resource in dataProcessor.xpath('./hour/resource-utilization/entry'):
            resourceMonitorHistory['resourceUtilization'][resource.xpath('./name')[0].text] = resource.xpath('./value')[0].text
    return resourceMonitorHistory

def firewall_PendingLocalChanges(fw_obj: panos.firewall.Firewall) -> dict:
    """
    Function is firewall-specific because a Panorama change journal only covers its own /config/devices/entry[@name='localhost.localdomain'] XML branch

    :param fw_obj:
    :return:
    """
    if not fw_obj.pending_changes():
        return {1: 'No Pending Changes.'}
    logger.info("\t> Listing local changes...")
    xmlData = panCore.xmlToLXML(fw_obj.op("show config list changes"))
    pendingChanges = {}
    if not len(xmlData[0]):
        logger.info("\t> Changes were reported in fw_obj.pending_changes() test but no changes reported in show config list changes...")
        # I would like to flesh this out more and chase down "pseudo changes" by going node by node through the running and candidate XML to find what triggered the pending_changes() flag
        # Would need to do a "for xmlNode in candidateXML" and then compare to runningXML to list the differences.
        return {1: 'No Journaled changes found despite fw_obj.pending_changes() flag being True.'}
    else:
        counter = 0
        for change in xmlData.xpath('/response/result/journal/entry'):
            counter += 1
            panCore.devData = {'change': {}}
            panCore.headers = []
            panCore.iterator(change, 'change')
            pendingChanges[counter] = panCore.devData['change']
        return pendingChanges


def firewall_ZoneProtectionProfiles(getConf: lxml.etree) -> Dict:
    logger.info("\t> Gathering zone protection profiles...")
    zppProfiles = {}
    for zpp in getConf.xpath('.//config/devices/entry[@name="localhost.localdomain"][not(ancestor::template)]/network/profiles/zone-protection-profile/entry'):
        profileName = zpp.attrib['name']
        zppProfiles[profileName] = {}
        for child in zpp.getchildren():
            panCore.headers = []
            panCore.devData = {child.tag: {}}
            panCore.iterator(child, child.tag)
            zppProfiles[profileName].update(panCore.devData[child.tag])
    return zppProfiles

def firewall_highAvailability(fw_obj: panos.firewall.Firewall) -> Dict:
    logger.info("\t> Gathering general HA configuration information...")

    # Use PAN-OS-Python SDK to get HA group id once
    ha_obj = panos.ha.HighAvailability()
    fw_obj.add(ha_obj)
    ha_obj.refresh()

    # Retrieve HA XML and anchor using explicit xml_* variables
    xml_document = panCore.xmlToLXML(fw_obj.op('show high-availability all'))

    # Local helpers for clean, safe XML access (no abbreviations)
    def get_first_node(xml_parent, relative_xpath: str):
        nodes = xml_parent.xpath(relative_xpath) if xml_parent is not None else []
        return nodes[0] if nodes else None

    def get_text(xml_parent, relative_xpath: str, default: str = "") -> str:
        node = get_first_node(xml_parent, relative_xpath)
        return node.text if node is not None and getattr(node, 'text', None) is not None else default


    # Top-level anchors
    xml_result = get_first_node(xml_document, './result')
    xml_highAvailability = get_first_node(xml_result, './group')
    xml_linkMonitoring = get_first_node(xml_highAvailability, './link-monitoring')
    xml_pathMonitoring = get_first_node(xml_highAvailability, './path-monitoring')

    # Root output structure (schema preserved)
    haConfig: Dict[str, Any] = {
        'enabled': get_text(xml_result, './enabled'),
        'mode': get_text(xml_highAvailability, './mode'),
        'group': (ha_obj.about() or {}).get('group_id', ''),
        'running-sync': get_text(xml_highAvailability, './running-sync'),
        'running-sync-enabled': get_text(xml_highAvailability, './running-sync-enabled'),
        'local-info': {},
        'peer-info': {},
        'link-monitoring': {
            'enabled': get_text(xml_linkMonitoring, './enabled'),
            'failureConditions': get_text(xml_linkMonitoring, './failure-condition'),
            'groups': {}
        },
        'path-monitoring': {
            'enabled': get_text(xml_pathMonitoring, './enabled'),
            'failureConditions': get_text(xml_pathMonitoring, './failure-condition'),
            'objects': {}
        }
    }

    # ----- Link Monitoring: groups and interfaces -----
    linkMonitoringGroups = haConfig['link-monitoring']['groups']
    for linkMonitoringGroupEntry in (xml_linkMonitoring.xpath('./groups/entry') if xml_linkMonitoring is not None else []):
        groupName = get_text(linkMonitoringGroupEntry, './name')
        if not groupName:
            continue
        groupRecord = linkMonitoringGroups.setdefault(groupName, {
            'name': groupName,
            'enabled': get_text(linkMonitoringGroupEntry, './enabled'),
            'failureConditions': get_text(linkMonitoringGroupEntry, './failure-condition'),
            'interfaces': {}
        })
        groupInterfaces = groupRecord['interfaces']
        for interfaceEntry in linkMonitoringGroupEntry.xpath('./interface/entry'):
            interfaceName = get_text(interfaceEntry, './name')
            if not interfaceName:
                continue
            groupInterfaces[interfaceName] = {
                'name': interfaceName,
                'link-status': get_text(interfaceEntry, './status')
            }

    # ----- Path Monitoring: monitored objects by type (e.g., virtual-router, vlan, virtual-wire) -----
    pathMonitoringObjectsByType = haConfig['path-monitoring']['objects']

    if xml_pathMonitoring is not None:
        # Iterate over each child element under path-monitoring that represents a type container
        # Examples of type containers: 'virtual-router', 'vlan', 'virtual-wire'
        for xml_TypeContainer in list(xml_pathMonitoring):
            # Skip non-group element nodes 'enabled' and 'failure-condition'
            if xml_TypeContainer.tag in ('enabled', 'failure-condition'):
                continue
            pathMonitoringType = xml_TypeContainer.tag  # capture raw XML tag as the type label

            # Create or get the per-type objects bucket only (eliminate redundant 'types' branch)
            pathMonitoringDevData = pathMonitoringObjectsByType.setdefault(pathMonitoringType, {})

            for xml_pathMonitoringEntry in xml_TypeContainer.xpath('./entry'):
                pathMonitoringName = get_text(xml_pathMonitoringEntry, './name')
                if not pathMonitoringName:
                    continue
                # Build or fetch the record for this monitored object
                pathMonitoringRecord = pathMonitoringDevData.setdefault(pathMonitoringName, {
                    'type': pathMonitoringType,
                    'name': pathMonitoringName,
                    'enabled': get_text(xml_pathMonitoringEntry, './enabled'),
                    'failure-condition': get_text(xml_pathMonitoringEntry, './failure-condition'),
                    'destination-groups': {}
                })

                destinationGroups = pathMonitoringRecord['destination-groups']
                for destinationGroupEntry in xml_pathMonitoringEntry.xpath('./destination-groups/entry'):
                    destinationGroupName = get_text(destinationGroupEntry, './name')
                    if not destinationGroupName:
                        continue
                    destinationGroupRecord = destinationGroups.setdefault(destinationGroupName, {
                        'name': destinationGroupName,
                        'enabled': get_text(destinationGroupEntry, './enabled'),
                        'failure-condition': get_text(destinationGroupEntry, './failure-condition'),
                        'dest-ip': {}
                    })
                    destinationAddresses = destinationGroupRecord['dest-ip']
                    for destinationAddressEntry in destinationGroupEntry.xpath('./dest-ip/entry'):
                        destinationAddress = get_text(destinationAddressEntry, './addr')
                        if not destinationAddress:
                            continue
                        destinationAddresses[destinationAddress] = {
                            'address': destinationAddress,
                            'status': get_text(destinationAddressEntry, './status')
                        }
                # Handle unexpected single level XML nodes like 'source-ip'; also capture other unanticipated fields
                for childObject in xml_pathMonitoringEntry.getchildren():
                    if childObject.tag in ('name', 'enabled', 'failure-condition', 'destination-groups'):
                        continue
                    if childObject.tag not in pathMonitoringRecord.keys():
                        pathMonitoringRecord[childObject.tag] = getattr(childObject, 'text', None)

    # ----- Local and Peer info (iterator catch-all) -----
    panCore.headers = []
    panCore.devData = {'local-info': {}, 'peer-info': {}}

    xml_localInfo = get_first_node(xml_highAvailability, './local-info')
    xml_peerInfo = get_first_node(xml_highAvailability, './peer-info')

    for settingElement in (list(xml_localInfo) if xml_localInfo is not None else []):
        panCore.iterator(settingElement, 'local-info')
    for settingElement in (list(xml_peerInfo) if xml_peerInfo is not None else []):
        panCore.iterator(settingElement, 'peer-info')

    haConfig['local-info'] = panCore.devData.get('local-info', {})
    haConfig['peer-info'] = panCore.devData.get('peer-info', {})
    return haConfig

def postProcessing_highAvailability(firewallDetails: dict, panoInventory: Dict) -> Dict:
    logger.info("\t> Post-processing HA data...")
    clusterDetails: Dict[str, dict] = {}
    """
    Build clusterDetails, gather raw data grouped by cluster and cluster member
    """
    for fwNameSerial, fwData in firewallDetails.items():
        ha = fwData.get('highAvailability')
        if not ha:
            logger.info(f"\t****> {fwNameSerial} HA config wasn't captured during audit phase. Skipping further cluster post processing.")
            continue
        logger.info(f"\t\t> Post-processing HA data for {fwNameSerial}...")
        localInfo = ha.get('local-info')
        fwSerial = fwData['system']['serial']
        fwName = fwData['system']['hostname']
        peerSerial = panoInventory.get('devices', {}).get(fwSerial, {}).get('ha.peer.serial')
        peerName = panoInventory.get('devices', {}).get(peerSerial, {}).get('hostname')
        peerNameSerial = peerName + " (" + peerSerial + ")"
        if not peerSerial:
            logger.warning(f"\t****> {fwNameSerial} peer info wasn't captured during audit phase. Skipping further post processing. Investigate missing peer data!!!")
            continue
        clusterGUID = "-".join(sorted((fwSerial, peerSerial)))
        # Initialize cluster container if needed
        cluster = clusterDetails.setdefault(clusterGUID, {
            "clusterGUID": clusterGUID,
            "clusterAudits": {
                "incompatibleDynamicContent": set() #Prestage as set so items can be added without fear of duplication as in list comprehension.
            },
            "members": {},
        })
        # Add member details
        cluster["members"][fwNameSerial] = {
            "memberName": fwName,
            "memberSerial": fwSerial,
            "memberModel": localInfo['platform-model'],
            "mode": ha.get('mode'),
            "group": ha.get('group'),
            "enabled": ha.get('enabled'),
            "linkMonitorEnabled": (ha.get('link-monitoring') or {}).get('enabled'),
            "pathMonitorEnabled": (ha.get('path-monitoring') or {}).get('enabled'),
            "configSyncEnabled": ha.get('running-sync-enabled'),
            "runningConfigSynchronized": ha['running-sync'],
            "haState": localInfo['state'],
            "peerNameSerial": peerNameSerial,
            "fwAudits": {"linkMonitoring_missingGroups": [],},
            "localConfig": ha['local-info'],
            "peerConfig": ha['peer-info'],
            "linkMonitoring": ha['link-monitoring'],
            "pathMonitoring": ha['path-monitoring'],
        }
        # Gather Preemption Status
        if localInfo['preemptive'].lower() == 'no':
            cluster["members"][fwNameSerial]["preemption"] = "Disabled"
        else:
            cluster["members"][fwNameSerial]["preemption"] = F"Priority: {localInfo['priority']}, HoldMinutes: {localInfo['preempt-hold']}"
    """
    Check each cluster for best practices and config matching, expand dictionary to include audits and best practice checks
    """
    for clusterGUID, cluster in clusterDetails.items():
        members = cluster["members"]
        # Cluster Check - ensure we have data from both members
        if len(members) == 2:
            cluster["clusterAudits"]["bothMembersFound"] = True
        else:
            cluster["clusterAudits"]["bothMembersFound"] = False
            logger.warning(f"\t****> {clusterGUID} does not have both members audited. Skipping further cluster checks. Investigate!!!")
            continue
        for fwNameSerial, fw in members.items():
            peerNameSerial = fw['peerNameSerial']
            peer = members[peerNameSerial]
            localConfig = fw['localConfig']
            peerConfig = members[peerNameSerial]['localConfig']
            #
            # Sanity check - ha mode and basic config elements should always match.
            #
            fwBaseConfig = {
                "mode": fw.get('mode'),
                "group": fw.get('group'),
                "enabled": fw.get('enabled'),
                "configSyncEnabled": fw.get('configSyncEnabled')}
            peerBaseConfig = {
                "mode": peer.get('mode'),
                "group": peer.get('group'),
                "enabled": peer.get('enabled'),
                "configSyncEnabled": peer.get('configSyncEnabled')}
            if fwBaseConfig == peerBaseConfig:
                cluster['clusterAudits']["haBaseConfigMatches"] = True
            else:
                logger.warning(f"\t****> {clusterGUID} ha basic config does not match. Investigate!!!")
                cluster['clusterAudits']["haBaseConfigMatches"] = False
            #
            # Best Practice Check - passive link state should match between peers
            #
            if fw["mode"].lower() == "active-active":
                cluster["clusterAudits"]["passiveLinkStateMatches"] = 'True (N/A - Active-Active)'
            else:
                fwPassiveMode = localConfig.get("active-passive.passive-link-state", "").lower()
                peerPassiveMode = peerConfig.get("active-passive.passive-link-state", "").lower()
                if fwPassiveMode == "auto" and peerPassiveMode == "auto":
                    cluster["clusterAudits"]["passiveLinkStateMatches"] = "True (Both Auto)"
                elif fwPassiveMode == "shutdown" and peerPassiveMode == "shutdown":
                    cluster["clusterAudits"]["passiveLinkStateMatches"] = "True (Both Shutdown)"
                else:
                    cluster["clusterAudits"]["passiveLinkStateMatches"] = False
            #
            # Best practice check - both firewalls believe their config to be compatible with one another
            # E.G. PAN-OS version "close enough" match that they can functionally fail over and run the same Config XML
            #
            if localConfig.get('build-compat').lower() != 'match' or peerConfig.get('build-compat').lower() != 'match':
                cluster["clusterAudits"]["configCompatibleBetweenPeers"] = False
            else:
                cluster["clusterAudits"]["configCompatibleBetweenPeers"] = True
            #
            # Best Practice Check - All dynamic content versions should be compatible between peers.
            # Report at the cluster audit level whatever dynanmic content is reported as incompatible by either peer
            #
            incompatibleDynamicContent = []
            for key, value in localConfig.items():
                if '-compat' in key and key != 'build-compat':
                    if value.lower() != 'match':
                        incompatibleDynamicContent.append(key.split('-')[0])
            if localConfig['DLP'].lower() != 'match':
                incompatibleDynamicContent.append("DLP")
            cluster["clusterAudits"]['incompatibleDynamicContent'].update(incompatibleDynamicContent)
            #
            # Best Practice Check - path monitoring config match
            #
            localPathMonitoring = fw["pathMonitoring"]
            peerPathMonitoring = peer["pathMonitoring"]
            cluster["clusterAudits"]["pathMonitoringMatchesPeer"] = (localPathMonitoring == peerPathMonitoring)

            # Path Monitoring detailed audits
            local_pm = localPathMonitoring or {}
            peer_pm = peerPathMonitoring or {}

            # Ensure fwAudits exists for this member
            fw.setdefault('fwAudits', {})

            # Member-level working buckets (do NOT attach raw containers to fwAudits; emit only *_msg strings when non-empty)
            fw_missing_types = []
            fw_missing_objects = {}
            fw_missing_groups = []
            fw_groups_without_destinations = []
            fw_objects_without_groups = []

            local_types = (local_pm.get('objects') or {}) if isinstance(local_pm, dict) else {}
            peer_types = (peer_pm.get('objects') or {}) if isinstance(peer_pm, dict) else {}

            # Missing types
            local_type_names = set(local_types.keys())
            peer_type_names = set(peer_types.keys())
            missing_on_local_types = sorted(peer_type_names - local_type_names)
            missing_on_peer_types = sorted(local_type_names - peer_type_names)
            # Record only member-local missing types; cluster-level buckets removed as ambiguous
            if missing_on_local_types:
                fw_missing_types.extend(missing_on_local_types)

            # Iterate all types present on either side
            for pathMonitoringType in sorted(local_type_names | peer_type_names):
                local_type_record = local_types.get(pathMonitoringType, {}) or {}
                peer_type_record = peer_types.get(pathMonitoringType, {}) or {}

                # With 'types' branch removed, the type record is directly the map of objects for that type
                local_objects = local_type_record if isinstance(local_type_record, dict) else {}
                peer_objects = peer_type_record if isinstance(peer_type_record, dict) else {}

                local_object_names = set(local_objects.keys())
                peer_object_names = set(peer_objects.keys())

                missing_on_local_objects = sorted(peer_object_names - local_object_names)
                missing_on_peer_objects = sorted(local_object_names - peer_object_names)
                # Record only member-local missing objects
                if missing_on_local_objects:
                    fw_missing_objects.setdefault(pathMonitoringType, []).extend(missing_on_local_objects)

                # For each local object, check object enabled, groups presence, per-group audits
                for objectName in sorted(local_object_names):
                    local_object_record = local_objects.get(objectName, {}) or {}
                    object_enabled = (local_object_record.get('enabled') or '')

                    local_groups = (local_object_record.get('destination-groups') or {}) if isinstance(local_object_record, dict) else {}

                    # If the object has no groups locally, record as a failure for this member
                    if not isinstance(local_groups, dict) or len(local_groups) == 0:
                        fw_objects_without_groups.append((pathMonitoringType, objectName))

                    # Peer group map if peer also has this object
                    peer_groups = {}
                    if objectName in peer_objects:
                        peer_object_record = peer_objects.get(objectName, {}) or {}
                        peer_groups = (peer_object_record.get('destination-groups') or {}) if isinstance(peer_object_record, dict) else {}

                    local_group_names = set(local_groups.keys())
                    peer_group_names = set(peer_groups.keys()) if isinstance(peer_groups, dict) else set()

                    groups_missing_on_local = sorted(peer_group_names - local_group_names)
                    if groups_missing_on_local:
                        fw_missing_groups.append((pathMonitoringType, objectName, groups_missing_on_local))

                    # Group-level checks locally
                    for groupName, groupRecord in (local_groups.items() if isinstance(local_groups, dict) else []):
                        group_enabled = (groupRecord.get('enabled') or '')
                        dest_map = groupRecord.get('dest-ip') or {}
                        if not isinstance(dest_map, dict) or len(dest_map) == 0:
                            fw_groups_without_destinations.append((pathMonitoringType, objectName, groupName))

            # Build FAIL: message summaries for Excel for Path Monitoring issues
            missing_objects_tuples = [(t, name) for t, names in (fw_missing_objects or {}).items() for name in names]
            if fw_missing_types:
                fw['fwAudits']['pathMonitoring_missingTypes_msg'] = f"FAIL: {sorted(fw_missing_types)}"
            if missing_objects_tuples:
                fw['fwAudits']['pathMonitoring_missingObjects_msg'] = f"FAIL: {missing_objects_tuples}"
            if fw_missing_groups:
                fw['fwAudits']['pathMonitoring_missingGroups_msg'] = f"FAIL: {fw_missing_groups}"
            if fw_objects_without_groups:
                fw['fwAudits']['pathMonitoring_objectsWithoutGroups_msg'] = f"FAIL: {fw_objects_without_groups}"
            if fw_groups_without_destinations:
                fw['fwAudits']['pathMonitoring_groupsWithoutDestinations_msg'] = f"FAIL: {fw_groups_without_destinations}"

            #
            # Best Practice Check - link monitoring config matches (Enabled, Group definitions, Interfaces included in groups, ENTIRE config matches
            #
            localLinkMonitoring = fw["linkMonitoring"]
            peerLinkMonitoring = peer["linkMonitoring"]
            # Compare LM configs while ignoring only per-interface operational state ('link-status').
            local_cmp = copy.deepcopy(localLinkMonitoring) if isinstance(localLinkMonitoring, dict) else {}
            peer_cmp  = copy.deepcopy(peerLinkMonitoring) if isinstance(peerLinkMonitoring, dict) else {}
            for lm_view in (local_cmp, peer_cmp):
                groups_map = lm_view.get('groups') if isinstance(lm_view, dict) else None
                if not isinstance(groups_map, dict):
                    continue
                for _group_name, group_data in groups_map.items():
                    if not isinstance(group_data, dict):
                        continue
                    interfaces_map = group_data.get('interfaces')
                    if not isinstance(interfaces_map, dict):
                        continue
                    for _iface_name, iface_record in interfaces_map.items():
                        if isinstance(iface_record, dict):
                            iface_record.pop('link-status', None)
            cluster["clusterAudits"]["linkMonitoringMatchesPeer"] = (local_cmp == peer_cmp)
            #
            # If link monitoring is enabled, groups should be defined on both firewalls, and be equal.
            # Calculate link monitoring groups for each, subtract from the opposite and see what's left
            # Also compute groups without interfaces as a firewall-level audit.
            #
            local_groups_dict = localLinkMonitoring.get('groups') if isinstance(localLinkMonitoring, dict) else None
            peer_groups_dict = peerLinkMonitoring.get('groups') if isinstance(peerLinkMonitoring, dict) else None
            local_groups = set(local_groups_dict.keys()) if isinstance(local_groups_dict, dict) else set()
            peer_groups = set(peer_groups_dict.keys()) if isinstance(peer_groups_dict, dict) else set()

            # Only mark FAIL for this member if it is missing groups present on the peer
            missing_on_this_member = sorted(peer_groups - local_groups)
            if missing_on_this_member:
                fw["fwAudits"]["linkMonitoring_missingGroups"] = f"FAIL: {missing_on_this_member}"

            # Identify local groups that have no interfaces defined
            groups_without_interfaces = []
            if isinstance(local_groups_dict, dict):
                for lm_group_name, lm_group_data in local_groups_dict.items():
                    interfaces_map = (lm_group_data or {}).get('interfaces')
                    if not isinstance(interfaces_map, dict) or len(interfaces_map) == 0:
                        groups_without_interfaces.append(lm_group_name)
            if groups_without_interfaces:
                fw["fwAudits"]["linkMonitoring_groupsWithoutInterfaces"] = f"FAIL: {sorted(groups_without_interfaces)}"

            #
            # Best Practice Check - HA 1 should resist split brain by having a backup.
            #
            if 'ha1-backup-ipaddr' not in fw['localConfig'].keys():
                logger.warning(f"\t****> {fw['memberName']} ({fw['memberSerial']}) does not have an HA1 backup IP configured. Investigate!!!")
                fw["fwAudits"]["ha1BackupIP"] = "FAIL: HA1 Backup IP not configured. Beware Split-brain."
            else:
                fw["fwAudits"]["ha1BackupIP"] = f"{fw['localConfig']['ha1-backup-ipaddr']} on {fw['localConfig']['ha1-backup-port']}"
            #
            # Gather flapping counts
            #
            fw["fwAudits"]["flapCounts"] = f"PreemptFlap: {fw['localConfig']['preempt-flap-cnt']}, nonFunc: {fw['localConfig']['nonfunc-flap-cnt']}, Max:{fw['localConfig']['max-flaps']}"
    return clusterDetails


def postProcessing_Zones(firewallDetails: dict) -> Tuple[Dict, Dict]:
    logger.info("\t> Post-processing zone data...")
    zoneList = {}
    for fwNameSerial, fwData in (firewallDetails or {}).items():
        fwZones = (fwData or {}).get('zones') or {}
        for zoneName, zoneData in fwZones.items():
            # Build comparable config for variant comparison: ignore per-firewall interface lists; strip template metadata to avoid false variants
            rawConfigExcludingInterfaces = {key: value for key, value in (zoneData or {}).items() if key != 'interface'}
            zoneConfig = strip_template_keys(rawConfigExcludingInterfaces)

            # zoneAggregate holds all aggregated data for this zone name:
            # - 'configs': dict of variantIndex -> { 'config': normalized dict (no 'interface'), 'firewalls': [fwNameSerial, ...] }
            # - 'firewallsWithInterfaces' / 'firewallsWithoutInterfaces': track which firewalls have any interfaces in this zone
            zoneAggregate = zoneList.setdefault(zoneName, {
                'configs': {},
                'firewallsWithInterfaces': [],
                'firewallsWithoutInterfaces': []
            })
            variantBucket = zoneAggregate['configs']

            # Try to match an existing variant; append and break on first match
            matchedExistingVariant = False
            for variantIndex, variantRecord in variantBucket.items():
                if (variantRecord or {}).get('config') == zoneConfig:
                    variantRecord.setdefault('firewalls', []).append(fwNameSerial)
                    matchedExistingVariant = True
                    break
            if not matchedExistingVariant:
                newVariantIndex = len(variantBucket)
                variantBucket[newVariantIndex] = {"config": zoneConfig, "firewalls": [fwNameSerial]}

            # Track interface presence for this firewall in this zone
            hasInterfaces = len((zoneData or {}).get('interface', [])) > 0
            if hasInterfaces:
                zoneAggregate['firewallsWithInterfaces'].append(fwNameSerial)
            else:
                zoneAggregate['firewallsWithoutInterfaces'].append(fwNameSerial)
    zoneReport = {
        'zoneList': zoneList,
        'zonesWithoutInterfaces': {},
        'zonesWithMultipleConfigs': []}
    for zoneName in zoneList.keys():
        if len(zoneList[zoneName]['configs']) > 1:
            zoneReport['zonesWithMultipleConfigs'].append(zoneName)
        if len(zoneList[zoneName]['firewallsWithInterfaces']) == 0:
            zoneReport['zonesWithoutInterfaces'][zoneName] = zoneList[zoneName]['firewallsWithoutInterfaces']
    logger.info("Finished building ZoneReport")
    return zoneReport


def postProcessing_syslogProfiles(firewallDetails: dict) -> Dict:
    logger.info("\t> Post-processing syslog profiles...")
    syslogProfiles = {}
    for fwNameSerial in firewallDetails.keys():
        fwSyslog = (firewallDetails.get(fwNameSerial, {}) or {}).get('syslogProfiles') or {}
        for syslogProfile in fwSyslog.keys():
            profileConfig = strip_template_keys(fwSyslog[syslogProfile])
            # If profile isn't in dictionary add it.
            if syslogProfile not in syslogProfiles.keys():
                syslogProfiles[syslogProfile] = {0: {"config": profileConfig, "firewalls": [fwNameSerial]}}
            else:
                # If named profile is in dictionary check if it's configured the same as the instance in the dictionary.
                # Append firewall to list of firewalls using the matched config, or create a new record if there's no matching config already in the dictionary
                matchFound = False
                for profileRecordNum in syslogProfiles[syslogProfile].keys():
                    if profileConfig == syslogProfiles[syslogProfile][profileRecordNum]['config']:
                        matchFound = True
                        syslogProfiles[syslogProfile][profileRecordNum]['firewalls'].append(fwNameSerial)
                if not matchFound:
                    profileRecordNum += 1
                    syslogProfiles[syslogProfile][profileRecordNum] = {"config": profileConfig, "firewalls": [fwNameSerial]}
    return syslogProfiles


def postProcessing_zoneProtectionProfiles(firewallDetails: dict) -> Dict:
    """Aggregate Zone Protection Profiles across firewalls, deduplicating per-profile configs.
    Returns a dictionary shaped as:
      { profileName: { variantIndex: { 'config': <config dict>, 'firewalls': [fwNameSerial, ...] }, ... }, ... }
    Template-related keys like '@ptpl' and '@src' are stripped to avoid false variants.
    """
    logger.info("\t> Post-processing zone protection profiles...")
    zppProfiles: Dict[str, Dict[int, Dict[str, Any]]] = {}
    for fwNameSerial, fwData in (firewallDetails or {}).items():
        fwZpp = (fwData or {}).get('zoneProtectionProfiles') or {}
        if not isinstance(fwZpp, dict) or not fwZpp:
            continue
        for profileName, profileConfigRaw in fwZpp.items():
            # Normalize by stripping template keys
            profileConfig = strip_template_keys(profileConfigRaw)
            if profileName not in zppProfiles:
                zppProfiles[profileName] = {0: {"config": profileConfig, "firewalls": [fwNameSerial]}}
                continue
            # Try to match an existing variant if above 'continue' doesn't end loop upon first instance of profile.
            matchFound = False
            for variantIndex in zppProfiles[profileName].keys():
                if profileConfig == zppProfiles[profileName][variantIndex]['config']:
                    zppProfiles[profileName][variantIndex]['firewalls'].append(fwNameSerial)
                    matchFound = True
                    break
            if not matchFound:
                newIndex = len(zppProfiles[profileName]) #No need to +1 since 0 index already starts 1 less than the length of the dict.
                zppProfiles[profileName][newIndex] = {"config": profileConfig, "firewalls": [fwNameSerial]}
    return zppProfiles


def postProcessing_deviceLogOutputs(firewallDetails: dict) -> Dict[str, Any]:
    """Aggregate Device Log Output rules across all firewalls by
    logType -> ruleName -> variantIndex, mirroring the simplicity of ZPP.

    Returns a dict shaped as:
      { logType: { ruleName: { idx: { 'config': <dict>, 'firewalls': [ 'FW (Serial)', ... ] }}}}
    """
    logger.info("\t> Post-processing device log outputs...")
    logOutputsByType: Dict[str, Dict[str, Dict[int, Dict[str, Any]]]] = {}

    for fwNameSerial, fwData in (firewallDetails or {}).items():
        fwLogOutputs = (fwData or {}).get('deviceLogOutputs') or {}
        if not isinstance(fwLogOutputs, dict) or not fwLogOutputs:
            continue
        for logType, rulesByName in fwLogOutputs.items():
            if not isinstance(rulesByName, dict) or not rulesByName:
                continue
            logTypeBucket = logOutputsByType.setdefault(logType, {})
            for ruleName, raw_rule_config in rulesByName.items():
                if not isinstance(raw_rule_config, dict):
                    continue
                # Normalize and remove template keys to avoid false variants based on different template sources
                normalizedRuleConfig = strip_template_keys(raw_rule_config or {}) or {}
                # Canonicalize destinations to be ordering-insensitive and consistent types
                destinations = normalizedRuleConfig.get('destinations', {})
                if isinstance(destinations, dict):
                    canonicalized_destinations: Dict[str, list] = {}
                    for actionName, raw_targets in (destinations or {}).items():
                        if isinstance(raw_targets, (list, tuple, set)):
                            targets = sorted(str(target) for target in raw_targets)
                        elif raw_targets is None:
                            targets = []
                        else:
                            targets = [str(raw_targets)]
                        canonicalized_destinations[actionName] = targets
                    normalizedRuleConfig['destinations'] = canonicalized_destinations
                else:
                    normalizedRuleConfig['destinations'] = {}
                # Normalize common text fields; trim whitespace to avoid variants based on leading or trailing spaces
                description = normalizedRuleConfig.get('ruleDescription')
                normalizedRuleConfig['ruleDescription'] = '' if description is None else str(description).strip()
                filter = normalizedRuleConfig.get('ruleFilter')
                normalizedRuleConfig['ruleFilter'] = '' if filter is None else str(filter).strip()

                # Dedupe variants per ruleName under each log type
                ruleVariants = logTypeBucket.setdefault(ruleName, {})
                matchFound = False
                for variantIndex, recordData in ruleVariants.items():
                    if recordData.get('config') == normalizedRuleConfig:
                        recordData.setdefault('firewalls', []).append(fwNameSerial)
                        matchFound = True
                        break
                if not matchFound:
                    newIndex = len(ruleVariants)
                    ruleVariants[newIndex] = {
                        'config': normalizedRuleConfig,
                        'firewalls': [fwNameSerial],
                    }
    return logOutputsByType