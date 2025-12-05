from pancore import panCore, panExcelStyles
from typing import Dict, List
import logging
import xlsxwriter
import datetime
import re

todayDate = datetime.date.today()
logger = logging.getLogger(__name__)

# Per-workbook style cache key attached to the xlsxwriter.Workbook instance
STYLE_CACHE_ATTR = "_pan_style_cache"

# Simple, shared cell normalizer for workbook writers
# Converts datetime/date objects to strings so Excel sees stable text unless you format as dates
# This avoids repeating small helpers in each writer.
def datetime_to_string(value):
    try:
        import datetime as _dt
        if isinstance(value, (_dt.datetime, _dt.date)):
            if isinstance(value, _dt.datetime):
                return value.strftime("%Y-%m-%d %H:%M:%S")
            return value.strftime("%Y-%m-%d")
    except Exception:
        pass
    return value

# Helper: decide the format key to use for audit sections based on the value
# Returns one of: 'blackBox' (for empty/None), 'alertText' (for failures), or None for normal formatting
# This helper is intentionally simple so it can be unit-tested without creating a Workbook.
def determine_audit_format_key(header_name: str, value):
    # Empty or missing
    if value == '' or value is None:
        return 'blackBox'
    # Explicit failure conditions
    if isinstance(value, bool):
        if value is False:
            return 'alertText'
        return None
    # String-based failure text
    try:
        s = str(value)
    except Exception:
        s = ''
    # Treat any occurrence of FAIL: (case-insensitive) as failure
    if 'fail:' in s.lower():
        return 'alertText'
    return None

def initXLSX(workBookName:str="nameNotSpecified.xlsx", constantMemory=False) -> xlsxwriter.Workbook:
    # Default 'constantMemory' to false as some calling functions may require multi-line writing into the XLSX file.
    # Allow caller to turn 'constant memory' flag on if advantageous to that caller's use case
    # xlsx_writer will normally hold all contents in memory. This flag flushes lines from memory when moving to the next row.
    logger.info(f"Initializing XLSX output for workbook: {workBookName}")
    workbook = xlsxwriter.Workbook(workBookName, {'constant_memory': constantMemory})
    # Build per-workbook style cache and attach it
    cache = {}
    logger.info('>Initializing XLSX output\r> Available styles: ')
    for key, spec in panExcelStyles.styles.items():
        logger.info(key)
        cache[key] = workbook.add_format(spec)
    setattr(workbook, STYLE_CACHE_ATTR, cache)
    logger.info('< XLSX output initialized. ')
    return workbook


def writeWorksheet_Templates(workbook:xlsxwriter.Workbook, templateData: Dict) -> None:
    """
    Add the template worksheet to the workbook.
    :param templateData:
    :return:
    """
    logger.info("\tWriting template worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    headers = ['name', 'description', 'devices']
    for tplName in templateData.keys():
        for header in templateData[tplName].keys():
            if header not in headers:
                headers.append(header)
    headers.remove('variables')
    maxVarNum = 0
    for tplName in templateData.keys():
        maxVarNum = max(maxVarNum, len(templateData[tplName]['variables']))
    varHeaders = []
    for i in range(1, maxVarNum):
        varHeaders.extend([f"Var{i}.name", f"Var{i}.Type", f"Var{i}.Value"])
    worksheet = workbook.add_worksheet("Templates")
    worksheet.write_row("A1", headers + varHeaders, format_rowHeader)
    row = 0
    for tplName in templateData.keys():
        row += 1
        col = 0
        for header in headers:
            if header in templateData[tplName].keys():
                worksheet.write(row, col, str(templateData[tplName][header]))
            else:
                worksheet.write(row, col, "", format_blackBox)
            col += 1
        for i in range(1, maxVarNum):
            if i in templateData[tplName]['variables'].keys():
                worksheet.write(row, col, templateData[tplName]['variables'][i]['name'])
                col += 1
                worksheet.write(row, col, templateData[tplName]['variables'][i]['variable_type'])
                col += 1
                worksheet.write(row, col, templateData[tplName]['variables'][i]['value'])
                col += 1
            else:
                worksheet.write(row, col, "", format_blackBox)
                col += 1
                worksheet.write(row, col, "", format_blackBox)
                col += 1
                worksheet.write(row, col, "", format_blackBox)
                col += 1


def writeWorksheet_TemplateStacks(workbook:xlsxwriter.Workbook, tStackData: Dict) -> None:
    logger.info("\tWriting template stack worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    headers = ['name', 'description', 'devices', 'templates']
    for stkName in tStackData.keys():
        for header in tStackData[stkName].keys():
            if header not in headers:
                headers.append(header)
    headers.remove('variables')
    maxVarNum = 0
    for stkName in tStackData.keys():
        maxVarNum = max(maxVarNum, len(tStackData[stkName]['variables']))
    varHeaders = []
    for i in range(1, maxVarNum):
        varHeaders.extend([f"Var{i}.name", f"Var{i}.Type", f"Var{i}.Value"])
    worksheet = workbook.add_worksheet("Template Stacks")
    worksheet.write_row("A1", headers + varHeaders, format_rowHeader)
    row = 1
    for stkName in tStackData.keys():
        col = 0
        for header in headers:
            if header in tStackData[stkName].keys():
                if type(tStackData[stkName][header]) is list:
                    worksheet.write(row, col, ", ".join(tStackData[stkName][header]))
                else:
                    worksheet.write(row, col, tStackData[stkName][header])
            else:
                worksheet.write(row, col, "", format_blackBox)
            col += 1
        for i in range(1, maxVarNum):
            if i in tStackData[stkName]['variables'].keys():
                worksheet.write(row, col, tStackData[stkName]['variables'][i]['name'])
                col += 1
                worksheet.write(row, col, tStackData[stkName]['variables'][i]['variable_type'])
                col += 1
                worksheet.write(row, col, tStackData[stkName]['variables'][i]['value'])
                col += 1
            else:
                worksheet.write(row, col, "", format_blackBox)
                col += 1
                worksheet.write(row, col, "", format_blackBox)
                col += 1
                worksheet.write(row, col, "", format_blackBox)
                col += 1
        row += 1

def writeWorksheet_PanoramaInventory(workbook:xlsxwriter.Workbook, panoInventory: Dict) -> None:
    logger.info("\tWriting Panorama device inventory worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_alertText = formats['alertText']
    format_blackBox = formats['blackBox']
    headers = []
    for device in panoInventory:
        for key in panoInventory[device].keys():
            if key not in headers:
                headers.append(key)
    worksheet = workbook.add_worksheet("PanoramaFirewallInventory")
    worksheet.write_row("A1", headers, format_rowHeader)
    row = 1
    for device in panoInventory:
        #logger.info(f'\tWriting Panorama Firewall Inventory {device} on row {row}')
        col = 0
        for item in headers:
            if item in panoInventory[device]:
                if all([item == 'connected', panoInventory[device]['connected'] == 'no']):
                    worksheet.write(row, col, panoInventory[device][item], format_alertText)
                else:
                    worksheet.write(row, col, panoInventory[device][item])
            else:
                #If we've hit a field this particular firewall doesn't have put a black box in the excel sheet and move on.
                worksheet.write(row, col, "", format_blackBox)
            col += 1
        row += 1

def writeWorksheet_FirewallDetails(workbook:xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    logger.info("\tWriting Firewall details worksheet:")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_alertText = formats['alertText']
    format_blackBox = formats['blackBox']
    headers = []
    for fwSerial in firewallDetails:
        for header in firewallDetails[fwSerial]['system'].keys():
            if header not in headers:
                headers.extend([header])
    worksheet = workbook.add_worksheet("Firewall Show System Info")
    worksheet.write_row("A1", headers, format_rowHeader)
    row = 1
    for fwSerial in firewallDetails:
        col = 0
        #logger.info(f'\t--> Writing system info for {device} on row {row}')
        for item in headers:
            if item in firewallDetails[fwSerial]['system']:
                if 'release-date' in item:
                    if firewallDetails[fwSerial]['system'][item] == 'unknown':
                        # Just take the 'unknown' string and write it to the excel sheet. Use Regex to recognize and datetime to parse datetime records'
                        worksheet.write(row, col, firewallDetails[fwSerial]['system'][item])
                    else:
                        rawItemDate = firewallDetails[fwSerial]['system'][item]
                        # Check if item ends with a digit, and if so parse it as time.
                        # 2nd criteria protects against numeric timezone representations
                        if (re.search(r'\d+$', rawItemDate)) and not (rawItemDate[-3] == "+"):
                            itemDate = datetime.datetime.strptime(rawItemDate, '%Y/%m/%d %H:%M:%S')
                        else:
                            # Otherwise strip the four character (text or number) timezone label, and then parse it as time.
                            itemDate = datetime.datetime.strptime(rawItemDate[:-4], '%Y/%m/%d %H:%M:%S')
                        # Check if the item date is earlier than or equal to thirty days ago.
                        # If so write it with 'alertText' style
                        if itemDate.date() <= (todayDate - datetime.timedelta(days=30)):
                            worksheet.write(row, col, firewallDetails[fwSerial]['system'][item], format_alertText)
                        else:
                            worksheet.write(row, col, firewallDetails[fwSerial]['system'][item])
                else:
                    worksheet.write(row, col, firewallDetails[fwSerial]['system'][item])
            else:
                worksheet.write(row, col, "", format_blackBox)
            col += 1
        row += 1
    logger.info("Finished Writing Firewall Details worksheet\n")


def writeWorksheet_ZoneInfo(workbook:xlsxwriter.Workbook, zoneReport: Dict) -> None:
    zoneList = zoneReport['zoneList']
    logger.info("\tWriting zone info worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_label = formats['label']
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    worksheet = workbook.add_worksheet("zoneInfo")
    zoneHeaders = []
    for zoneName, zoneData in zoneReport.get('zoneList').items():
        for configNum, configData in zoneData.get('configs').items():
            for header in configData['config'].keys():
                if header not in zoneHeaders:
                    zoneHeaders.append(header)
    logger.info("\t--> Writing 'Zones with multiple configs' report section.")
    preHeaders = ['zoneName', 'configNum', 'firewallsUsingZone']
    width = max(6, len(preHeaders + zoneHeaders))
    worksheet.merge_range(0, 0, 0, width - 1, "Zones with Multiple Configs", format_label)
    worksheet.write_row(1, 0, preHeaders + zoneHeaders, format_rowHeader)
    row = 2
    for zoneName in zoneReport['zonesWithMultipleConfigs']:
        zoneData = zoneReport['zoneList'][zoneName]
        for configNum in zoneData['configs'].keys():
            zoneConfig = zoneData['configs'][configNum]['config']
            firewallsWithConfig = zoneData['configs'][configNum]['firewalls']
            worksheet.write(row, 0, zoneName)
            worksheet.write(row, 1, configNum)
            worksheet.write(row, 2, str(firewallsWithConfig))
            col = 3
            for item in zoneHeaders:
                if item not in zoneConfig.keys():
                    worksheet.write(row, col, "", format_blackBox)
                else:
                    worksheet.write(row, col, zoneConfig[item])
                col += 1
            row += 1
    logger.info("\t--> Writing 'Zones without interfaces' report section.")
    row += 2
    worksheet.merge_range(row, 0, row, 5, "Zones without Interfaces on any firewall", format_label)
    row += 1
    worksheet.write(row, 0, "Name", format_rowHeader)
    worksheet.merge_range(row, 1, row, 5, "Firewalls", format_rowHeader)
    row += 1
    for zoneName in zoneReport['zonesWithoutInterfaces']:
        worksheet.write(row, 0, zoneName)
        worksheet.merge_range(row, 1, row, 5, str(zoneReport['zonesWithoutInterfaces'][zoneName]))
        row += 1
    row += 2
    logger.info("\t-- > Writing 'All zones' report section.")
    zoneHeaders = ['name', 'configNum', 'firewallsUsingZone']
    for zoneName in zoneList.keys():
        for config in zoneList[zoneName]['configs'].keys():
            for keyName in zoneList[zoneName]['configs'][config]['config'].keys():
                if keyName not in zoneHeaders:
                    zoneHeaders.extend([keyName])
    width = len(zoneHeaders)
    worksheet.merge_range(row, 0, row, width - 1, "All Zones", formats['label'])
    row += 1
    worksheet.write_row(row, 0, zoneHeaders, formats['rowHeader'])
    row += 1
    for zoneName in zoneList.keys():
        for configNum in zoneList[zoneName]['configs'].keys():
            col = 0
            for item in zoneHeaders:
                if item == "configNum":
                    worksheet.write(row, col, configNum)
                elif item == "firewallsUsingZone":
                    worksheet.write(row, col, str(zoneList[zoneName]['configs'][configNum]['firewalls']))
                elif item not in zoneList[zoneName]['configs'][configNum]['config'].keys():
                    worksheet.write(row, col, "", format_blackBox)
                else:
                    worksheet.write(row, col, zoneList[zoneName]['configs'][configNum]['config'][item])
                col += 1
            row += 1

def writeWorksheet_HAClusterSummary(workbook:xlsxwriter.Workbook, clusterDetails) -> None:
    logger.info("\tWriting High Availability worksheet.")
    worksheet = workbook.add_worksheet("HA_ClusterData")

        # Formats (centralized via per-workbook cache)
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_label = formats['label']
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    format_alertText = formats['alertText']
    format_warnText = formats['warnText']
    format_greyBackground = formats['greyBackground']

    # Build header buckets
    headers_cluster_details: List[str] = ['clusterGUID']
    headers_cluster_audits: List[str] = []
    headers_member_details: List[str] = []
    headers_member_audits: List[str] = []

    # Discover all possible headers from the data
    for _clusterGUID, cluster in clusterDetails.items():
        # Cluster details: all top-level keys which aren't dictionaries should be presented as data local to the cluster.
        for top_key in cluster.keys():
            if type(cluster[top_key]) is dict:
                continue
            else:
                if top_key not in headers_cluster_details:
                    headers_cluster_details.append(top_key)

        # Cluster audits
        for audit_key in cluster.get('clusterAudits', {}).keys():
            if audit_key not in headers_cluster_audits:
                headers_cluster_audits.append(audit_key)

        # Per member data
        for _memberName, memberData in cluster.get('members', {}).items():
            # Member firewall details: all top-level keys which aren't dictionaries should be presented as data local to the member.
            for key in memberData.keys():
                if not isinstance(memberData.get(key), dict) and key not in headers_member_details:
                    headers_member_details.append(key)
            # Per Member audits
            for audit_key in (memberData.get('fwAudits', {}) or {}).keys():
                if audit_key not in headers_member_audits:
                    headers_member_audits.append(audit_key)

    # Reorder member audit headers to group peer comparison audits together, after all other audits
    peerComparisonAuditSubstring = "_missing"
    sortedMemberAuditHeaders = sorted(headers_member_audits, key=str.lower)
    nonPeerComparisonAudits = []
    peerComparisonAudits = []
    for headerName in sortedMemberAuditHeaders:
        if peerComparisonAuditSubstring in (headerName or ""):
            peerComparisonAudits.append(headerName)
        else:
            nonPeerComparisonAudits.append(headerName)
    headers_member_audits = nonPeerComparisonAudits + peerComparisonAudits

    # Row 0: Group headers
    col = 0
    if headers_cluster_details:
        if len(headers_cluster_details) == 1:
            worksheet.write(0, col, "Cluster Details", format_label)
        else:
            worksheet.merge_range(0, col, 0, col + len(headers_cluster_details) - 1, "Cluster Details", format_label)
        col += len(headers_cluster_details)
    if headers_cluster_audits:
        if len(headers_cluster_audits) == 1:
            worksheet.write(0, col, "Cluster Audits", format_label)
        else:
            worksheet.merge_range(0, col, 0, col + len(headers_cluster_audits) - 1, "Cluster Audits", format_label)
        col += len(headers_cluster_audits)
    if headers_member_details:
        if len(headers_member_details) == 1:
            worksheet.write(0, col, "Member Details", format_label)
        else:
            worksheet.merge_range(0, col, 0, col + len(headers_member_details) - 1, "Member Details", format_label)
        col += len(headers_member_details)
    if headers_member_audits:
        if len(headers_member_audits) == 1:
            worksheet.write(0, col, "Member Audits", format_label)
        else:
            worksheet.merge_range(0, col, 0, col + len(headers_member_audits) - 1, "Member Audits", format_label)
        col += len(headers_member_audits)

    # Row 1: Column headers (complete order)
    headers_all = (
        headers_cluster_details
        + headers_cluster_audits
        + headers_member_details
        + headers_member_audits
    )
    worksheet.write_row(1, 0, headers_all, format_rowHeader)

    # Utility: normalize values for Excel cells
    def _cell_value(value):
        if isinstance(value, (int, float)) or isinstance(value, bool):
            return value
        if isinstance(value, (list, tuple, set)):
            try:
                return ", ".join(str(item) for item in value)
            except Exception:
                return str(list(value))
        if isinstance(value, dict):
            try:
                parts = [f"{str(key)}={str(value[key])}" for key in sorted(value.keys(), key=lambda key_name: str(key_name))]
                return ", ".join(parts)
            except Exception:
                return str(value)
        if value is None:
            return ""
        return str(value)

    # Data rows start at row 2
    row = 2

    for clusterGUID, cluster in clusterDetails.items():
        members = cluster.get('members', {})

        # Precompute cluster details/audits value maps at the cluster level, before looping over members.
        cluster_details_values = {}
        for key in headers_cluster_details:
            if key == 'clusterGUID':
                cluster_details_values[key] = clusterGUID
            else:
                cluster_details_values[key] = cluster.get(key, '')
        cluster_audit_values = cluster.get('clusterAudits', {}) or {}

        for _memberName, memberData in members.items():
            col = 0

            # Cluster Details
            for header_name in headers_cluster_details:
                value = cluster_details_values.get(header_name, '')
                worksheet.write(row, col, _cell_value(value))
                col += 1

            # Cluster Audits
            for header_name in headers_cluster_audits:
                value = cluster_audit_values.get(header_name, '')
                fmt_key = determine_audit_format_key(header_name, value)
                if fmt_key == 'blackBox':
                    worksheet.write(row, col, '', format_blackBox)
                elif fmt_key == 'alertText':
                    worksheet.write(row, col, _cell_value(value), format_alertText)
                else:
                    worksheet.write(row, col, _cell_value(value))
                col += 1

            # Member Status (base fields)
            for header_name in headers_member_details:
                value = memberData.get(header_name, '')
                if value == '' or value is None:
                    worksheet.write(row, col, '', format_blackBox)
                else:
                    # If this is an 'enabled' field explicitly set to 'no', render as a warning
                    if isinstance(value, str) and ('enabled' in header_name.lower()) and value.strip().lower() == 'no':
                        worksheet.write(row, col, _cell_value(value), format_warnText)
                    else:
                        worksheet.write(row, col, _cell_value(value))
                col += 1

            # Firewall Audits
            fw_audit_values = memberData.get('fwAudits', {}) or {}
            for header_name in headers_member_audits:
                value = fw_audit_values.get(header_name, '')
                fmt_key = determine_audit_format_key(header_name, value)
                if fmt_key == 'blackBox':
                    worksheet.write(row, col, '', format_blackBox)
                elif fmt_key == 'alertText':
                    worksheet.write(row, col, _cell_value(value), format_alertText)
                else:
                    worksheet.write(row, col, _cell_value(value))
                col += 1
            row += 1
    logger.info("\tFinished Writing High Availability worksheet\n")


def writeWorksheet_HAConfigDetails(workbook:xlsxwriter.Workbook, clusterDetails) -> None:
    logger.info("\tWriting High Availability Config Details worksheet.")
    worksheet = workbook.add_worksheet("HA_ConfigDetails")

        # Formats (centralized via per-workbook cache)
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_label = formats['label']
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    format_greyBackground = formats['greyBackground']

    # Build headers
    headers_identifiers: List[str] = ['clusterGUID', 'memberName', 'memberSerial', 'memberModel']
    headers_local_config: List[str] = []
    headers_peer_config: List[str] = []

    # Discover headers from data
    for clusterGUID, cluster in clusterDetails.items():
        for _memberName, memberData in cluster.get('members', {}).items():
            for key in (memberData.get('localConfig', {}) or {}).keys():
                if key not in headers_local_config:
                    headers_local_config.append(key)
            for key in (memberData.get('peerConfig', {}) or {}).keys():
                if key not in headers_peer_config:
                    headers_peer_config.append(key)

    # Row 0 group labels
    col = 0
    if len(headers_identifiers) == 1:
        worksheet.write(0, col, "Identifiers", format_label)
    else:
        worksheet.merge_range(0, col, 0, col + len(headers_identifiers) - 1, "Identifiers", format_label)
    col += len(headers_identifiers)
    if headers_local_config:
        if len(headers_local_config) == 1:
            worksheet.write(0, col, "Local Config", format_label)
        else:
            worksheet.merge_range(0, col, 0, col + len(headers_local_config) - 1, "Local Config", format_label)
        col += len(headers_local_config)
    if headers_peer_config:
        if len(headers_peer_config) == 1:
            worksheet.write(0, col, "Peer Config", format_label)
        else:
            worksheet.merge_range(0, col, 0, col + len(headers_peer_config) - 1, "Peer Config", format_label)
        col += len(headers_peer_config)

    # Row 1 column headers
    headers_all = headers_identifiers + headers_local_config + headers_peer_config
    worksheet.write_row(1, 0, headers_all, format_rowHeader)

    # Utility: normalize values
    def _cell_value(value):
        if isinstance(value, (int, float)) or isinstance(value, bool):
            return value
        if isinstance(value, (list, tuple, set)):
            try:
                return ", ".join(str(item) for item in value)
            except Exception:
                return str(list(value))
        if isinstance(value, dict):
            try:
                parts = [f"{str(key)}={str(value[key])}" for key in sorted(value.keys(), key=lambda key_name: str(key_name))]
                return ", ".join(parts)
            except Exception:
                return str(value)
        if value is None:
            return ""
        return str(value)

    # Data rows
    row = 2
    for clusterGUID, cluster in clusterDetails.items():
        for _memberName, memberData in cluster.get('members', {}).items():
            # Identifiers
            worksheet.write(row, 0, clusterGUID)
            worksheet.write(row, 1, memberData.get('memberName', ''))
            worksheet.write(row, 2, memberData.get('memberSerial', ''))
            worksheet.write(row, 3, memberData.get('memberModel', ''))
            # Local Config
            col = 4
            local_vals = memberData.get('localConfig', {}) or {}
            for header in headers_local_config:
                value = local_vals.get(header, '')
                if value == '' or value is None:
                    worksheet.write(row, col, '', format_blackBox)
                else:
                    worksheet.write(row, col, _cell_value(value))
                col += 1
            # Peer Config
            peer_vals = memberData.get('peerConfig', {}) or {}
            for header in headers_peer_config:
                value = peer_vals.get(header, '')
                if value == '' or value is None:
                    worksheet.write(row, col, '', format_blackBox)
                else:
                    worksheet.write(row, col, _cell_value(value), format_greyBackground)
                col += 1
            row += 1
    logger.info("\tFinished Writing High Availability Config Details worksheet\n")


def writeWorksheet_HALinkMonitoring(workbook:xlsxwriter.Workbook, clusterDetails) -> None:
    logger.info("\tWriting High Availability Monitoring worksheet.")
    worksheet = workbook.add_worksheet("HA_LinkMonitoring")

        # Formats (centralized via per-workbook cache)
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_label = formats['label']
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    format_wrappedText = formats['wrappedText']
    format_alertText = formats['alertText']
    format_normalText = formats['normalText']
    format_warnText = formats['warnText']

    # Row 0: Group labels
    worksheet.merge_range(0, 0, 0, 3, "Firewall Info", format_label)
    worksheet.merge_range(0, 4, 0, 5, "Firewall LM Config", format_label)
    worksheet.merge_range(0, 6, 0, 9, "Health Audits", format_label)  # extended by one column
    worksheet.merge_range(0, 10, 0, 14, "Link Monitoring Groups", format_label)

    # Row 1: Column headers
    preambleHeaders = [
        'clusterGUID', 'memberName', 'memberSerial', 'memberModel',
        'linkMonitorEnabled', 'linkMonitorFailCond',
        'BothFirewallsPresent', 'MatchesPeer', 'MissingGroups',
        'GroupsWithoutInterfaces'  # new audit column
    ]
    groupHeaders = ['GroupName', 'groupEnabled', 'groupFailCond', 'Interfaces', 'InterfaceState']
    allHeaders = preambleHeaders + groupHeaders
    worksheet.write_row(1, 0, allHeaders, format_rowHeader)

    # Data rows start after two header rows
    row = 2
    for clusterGUID, cluster in clusterDetails.items():
        for fwNameSerial, member in (cluster.get('members', {}) or {}).items():
            panCore.logging.info(f"\t\tWriting High Availability Monitoring worksheet for {fwNameSerial}")
            lm = member.get('linkMonitoring') or {}
            # Decide warn styling for enabled when explicitly 'no'
            lm_enabled_val = lm.get('enabled')
            lm_enabled_fmt = format_warnText if (isinstance(lm_enabled_val, str) and lm_enabled_val.strip().lower() == 'no') else format_normalText
            rowData = [
                (clusterGUID, format_normalText),
                (member.get('memberName'), format_normalText),
                (member.get('memberSerial'), format_normalText),
                (member.get('memberModel'), format_normalText),
                (lm_enabled_val, lm_enabled_fmt),
                (lm.get('failureConditions'), format_normalText)
            ]
            bothMembersFound = cluster.get('clusterAudits', {}).get('bothMembersFound')
            if bothMembersFound:
                rowData.append((bothMembersFound, format_normalText))
                peerMatch = cluster['clusterAudits']['linkMonitoringMatchesPeer']
                rowData.append((peerMatch, format_normalText if peerMatch else format_alertText))
                missingGroups = member.get('fwAudits', {}).get('linkMonitoring_missingGroups', '')
                rowData.append((missingGroups, format_alertText if missingGroups else format_normalText))
                groupsWithoutIf = member.get('fwAudits', {}).get('linkMonitoring_groupsWithoutInterfaces', '')
                rowData.append((groupsWithoutIf, format_alertText if groupsWithoutIf else format_normalText))
            else:
                rowData.append((bothMembersFound, format_alertText))
                # Fill remaining preamble fields with black boxes when peer missing
                rowData.extend([('', format_blackBox)] * max(0, (len(preambleHeaders) - len(rowData))))

            groups = lm.get('groups')
            if not groups or not isinstance(groups, dict) or len(groups) == 0:
                # No groups: write one row with alert in GroupName and black-box the rest
                row_vals = list(rowData)  # copy
                row_vals.append(('No groups configured', format_alertText))
                row_vals.extend([('', format_blackBox)] * max(0, (len(groupHeaders) - 1)))
                col = 0
                for cellData, cellFormat in row_vals:
                    worksheet.write(row, col, str(cellData), cellFormat)
                    col += 1
                row += 1
            else:
                for groupName, groupData in groups.items():
                    col = 0
                    for cellData, cellFormat in rowData:
                        worksheet.write(row, col, str(cellData), cellFormat)
                        col += 1
                    worksheet.write(row, col, groupName, format_normalText)
                    # Warn when group is explicitly disabled
                    group_enabled_val = groupData.get('enabled')
                    if isinstance(group_enabled_val, str) and group_enabled_val.strip().lower() == 'no':
                        worksheet.write(row, col+1, group_enabled_val, format_warnText)
                    else:
                        worksheet.write(row, col+1, group_enabled_val, format_normalText)
                    worksheet.write(row, col+2, groupData.get('failureConditions'), format_normalText)
                    if len(groupData.get('interfaces') or {}) > 0:
                        interfaces, interfaceStates = [], []
                        for interfaceName, interfaceData in (groupData.get('interfaces') or {}).items():
                            interfaces.append(interfaceData.get('name'))
                            interfaceStates.append(interfaceData.get('link-status'))
                        any_down = any(str(state).strip().lower() == 'down' for state in interfaceStates if state is not None)
                        group_cell_format = format_warnText if any_down else format_wrappedText
                        worksheet.write(row, col + 3, "\n".join(interfaces), format_wrappedText)
                        worksheet.write(row, col + 4, "\n".join(interfaceStates), group_cell_format)
                    else:
                        worksheet.write(row, col+3, "No Interfaces", format_alertText)
                        worksheet.write(row, col+4, "", format_blackBox)
                    row += 1
    logger.info("\tFinished Writing High Availability Monitoring worksheet\n")


def writeWorksheet_HAPathMonitoring(workbook:xlsxwriter.Workbook, clusterDetails) -> None:
    logger.info("\tWriting High Availability Path Monitoring worksheet.")
    worksheet = workbook.add_worksheet("HA_PathMonitoring")

    # Formats (centralized via per-workbook cache)
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_label = formats['label']
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    format_wrappedText = formats['wrappedText']
    format_alertText = formats['alertText']
    format_warnText = formats['warnText']

    # 1) Define core, canonical columns
    headers_fw_info = ['clusterGUID', 'memberName', 'memberSerial', 'memberModel']
    headers_pm_top = ['pmEnabled', 'pmFailureConditions']
    headers_object_identity = ['pmType', 'pmObject', 'pmObjectEnabled', 'pmObjectFailureCondition']
    headers_group = ['pmGroup', 'pmGroupEnabled', 'pmGroupFailureCondition']
    headers_address = ['pmDestAddress', 'pmDestStatus']

    # 2) Discover dynamic object-level fields across data
    discovered_object_fields: List[str] = []
    for _clusterGUID, cluster in (clusterDetails or {}).items():
        for _memberKey, memberData in (cluster.get('members', {}) or {}).items():
            pm_root = memberData.get('pathMonitoring') or {}
            objects_by_type = (pm_root.get('objects') or {}) if isinstance(pm_root, dict) else {}
            for _pm_type, objects_map in (objects_by_type or {}).items():
                for _object_name, object_record in (objects_map or {}).items():
                    if isinstance(object_record, dict):
                        for key_name in object_record.keys():
                            if key_name in ('type', 'name', 'enabled', 'failure-condition', 'destination-groups'):
                                continue
                            if key_name not in discovered_object_fields:
                                discovered_object_fields.append(key_name)
    headers_object_dynamic = discovered_object_fields

    # 3) Path Monitoring audit message columns (FAIL:-prefixed strings)
    headers_pm_audits = [
        'pathMonitoring_missingTypes_msg',
        'pathMonitoring_missingObjects_msg',
        'pathMonitoring_missingGroups_msg',
        'pathMonitoring_objectsWithoutGroups_msg',
        'pathMonitoring_groupsWithoutDestinations_msg',
    ]

    # 4) Row 0: Group labels
    col = 0
    worksheet.merge_range(0, col, 0, col + len(headers_fw_info) - 1, "Firewall Info", format_label)
    col += len(headers_fw_info)
    worksheet.merge_range(0, col, 0, col + len(headers_pm_top) - 1, "Path Monitoring Settings", format_label)
    col += len(headers_pm_top)
    worksheet.merge_range(0, col, 0, col + len(headers_object_identity) - 1, "Path Monitoring Object", format_label)
    col += len(headers_object_identity)
    if headers_object_dynamic:
        worksheet.merge_range(0, col, 0, col + len(headers_object_dynamic) - 1, "Object Extra Fields", format_label)
        col += len(headers_object_dynamic)
    worksheet.merge_range(0, col, 0, col + len(headers_group) - 1, "Destination Group", format_label)
    col += len(headers_group)
    worksheet.merge_range(0, col, 0, col + len(headers_address) - 1, "Destination Address", format_label)
    col += len(headers_address)
    worksheet.merge_range(0, col, 0, col + len(headers_pm_audits) - 1, "Path Monitoring Audits", format_label)

    # 5) Row 1: Column headers
    headers_all = (
        headers_fw_info
        + headers_pm_top
        + headers_object_identity
        + headers_object_dynamic
        + headers_group
        + headers_address
        + headers_pm_audits
    )
    worksheet.write_row(1, 0, headers_all, format_rowHeader)

    # 6) Data rows
    row = 2

    def write_cell(value, col_idx):
        if value in (None, ''):
            worksheet.write(row, col_idx, '', format_blackBox)
        else:
            worksheet.write(row, col_idx, value)

    def write_enabled_cell(value, col_idx):
        # Render 'no' as a warning to indicate disabled state without raising an alert
        if value in (None, ''):
            worksheet.write(row, col_idx, '', format_blackBox)
        elif isinstance(value, str) and value.strip().lower() == 'no':
            worksheet.write(row, col_idx, value, format_warnText)
        else:
            worksheet.write(row, col_idx, value)

    for clusterGUID, cluster in (clusterDetails or {}).items():
        for _memberKey, memberData in (cluster.get('members', {}) or {}).items():
            fw_info_vals = [
                clusterGUID,
                memberData.get('memberName', ''),
                memberData.get('memberSerial', ''),
                memberData.get('memberModel', ''),
            ]
            pm_root = memberData.get('pathMonitoring') or {}
            pm_enabled = pm_root.get('enabled', '')
            pm_failure = pm_root.get('failureConditions', '')
            objects_by_type = (pm_root.get('objects') or {}) if isinstance(pm_root, dict) else {}

            # Helper to write audit columns
            def write_pm_audit_columns(start_col):
                pm_audits_vals = [memberData.get('fwAudits', {}).get(h, '') for h in headers_pm_audits]
                c = start_col
                for val in pm_audits_vals:
                    if val:
                        worksheet.write(row, c, val, format_alertText if isinstance(val, str) and val.startswith('FAIL:') else None)
                    else:
                        worksheet.write(row, c, '', format_blackBox)
                    c += 1

            if not objects_by_type:
                col_idx = 0
                for v in fw_info_vals: worksheet.write(row, col_idx, v); col_idx += 1
                write_enabled_cell(pm_enabled, col_idx); col_idx += 1
                write_cell(pm_failure, col_idx); col_idx += 1
                # Object identity + dynamic + group + address as black boxes
                for _ in range(len(headers_object_identity) + len(headers_object_dynamic) + len(headers_group) + len(headers_address)):
                    worksheet.write(row, col_idx, '', format_blackBox); col_idx += 1
                write_pm_audit_columns(col_idx)
                row += 1
                continue

            for pm_type, objects_map in objects_by_type.items():
                if not isinstance(objects_map, dict):
                    continue
                for object_name, object_record in (objects_map or {}).items():
                    object_record = object_record or {}
                    groups_map = object_record.get('destination-groups') or {}

                    if not groups_map:
                        col_idx = 0
                        for v in fw_info_vals: worksheet.write(row, col_idx, v); col_idx += 1
                        write_enabled_cell(pm_enabled, col_idx); col_idx += 1
                        write_cell(pm_failure, col_idx); col_idx += 1
                        write_cell(pm_type, col_idx); col_idx += 1
                        write_cell(object_name, col_idx); col_idx += 1
                        write_enabled_cell(object_record.get('enabled', ''), col_idx); col_idx += 1
                        write_cell(object_record.get('failure-condition', ''), col_idx); col_idx += 1
                        for key_name in headers_object_dynamic:
                            write_cell(object_record.get(key_name, ''), col_idx); col_idx += 1
                        for _ in range(len(headers_group) + len(headers_address)):
                            worksheet.write(row, col_idx, '', format_blackBox); col_idx += 1
                        write_pm_audit_columns(col_idx)
                        row += 1
                        continue

                    for group_name, group_record in groups_map.items():
                        group_record = group_record or {}
                        dest_map = group_record.get('dest-ip') or {}

                        if not dest_map:
                            col_idx = 0
                            for v in fw_info_vals: worksheet.write(row, col_idx, v); col_idx += 1
                            write_enabled_cell(pm_enabled, col_idx); col_idx += 1
                            write_cell(pm_failure, col_idx); col_idx += 1
                            write_cell(pm_type, col_idx); col_idx += 1
                            write_cell(object_name, col_idx); col_idx += 1
                            write_enabled_cell(object_record.get('enabled', ''), col_idx); col_idx += 1
                            write_cell(object_record.get('failure-condition', ''), col_idx); col_idx += 1
                            for key_name in headers_object_dynamic:
                                write_cell(object_record.get(key_name, ''), col_idx); col_idx += 1
                            write_cell(group_name, col_idx); col_idx += 1
                            write_enabled_cell(group_record.get('enabled', ''), col_idx); col_idx += 1
                            write_cell(group_record.get('failure-condition', ''), col_idx); col_idx += 1
                            for _ in range(len(headers_address)):
                                worksheet.write(row, col_idx, '', format_blackBox); col_idx += 1
                            write_pm_audit_columns(col_idx)
                            row += 1
                            continue

                        for _dest_key, dest_data in dest_map.items():
                            dest_data = dest_data or {}
                            col_idx = 0
                            for v in fw_info_vals: worksheet.write(row, col_idx, v); col_idx += 1
                            write_enabled_cell(pm_enabled, col_idx); col_idx += 1
                            write_cell(pm_failure, col_idx); col_idx += 1
                            write_cell(pm_type, col_idx); col_idx += 1
                            write_cell(object_name, col_idx); col_idx += 1
                            write_enabled_cell(object_record.get('enabled', ''), col_idx); col_idx += 1
                            write_cell(object_record.get('failure-condition', ''), col_idx); col_idx += 1
                            for key_name in headers_object_dynamic:
                                write_cell(object_record.get(key_name, ''), col_idx); col_idx += 1
                            write_cell(group_name, col_idx); col_idx += 1
                            write_enabled_cell(group_record.get('enabled', ''), col_idx); col_idx += 1
                            write_cell(group_record.get('failure-condition', ''), col_idx); col_idx += 1
                            write_cell(dest_data.get('address', ''), col_idx); col_idx += 1
                            write_cell(dest_data.get('status', ''), col_idx); col_idx += 1
                            write_pm_audit_columns(col_idx)
                            row += 1

    logger.info("\tFinished Writing High Availability Path Monitoring worksheet\n")


def writeWorksheet_DynamicUpdateSchedule(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    logger.info("\tWriting Dynamic Content Update Schedule worksheet:")
    # Formats via per-workbook cache
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    # Collect headers from schedules across devices
    headers = []
    for device in firewallDetails:
        schedules = firewallDetails[device].get('schedules', {}) or {}
        for header in schedules.keys():
            # Ignore metadata/attribute keys ending with '@ptpl' or '@src'
            if header.endswith('@ptpl') or header.endswith('@src'):
                continue
            if header not in headers:
                headers.append(header)

    worksheet = workbook.add_worksheet("Update Schedules")
    # Column headers
    worksheet.write(0, 0, "Serial #", format_rowHeader)
    worksheet.write(0, 1, "Hostname", format_rowHeader)
    worksheet.write_row(0, 2, sorted(headers), format_rowHeader)

    row = 1
    for device in firewallDetails:
        fw_hostname = firewallDetails[device].get('system', {}).get('hostname', '')
        fw_serial = firewallDetails[device].get('system', {}).get('serial', '')
        logger.info(f"\t--> Writing Dynamic Content Schedule for {device} on row {row}")
        worksheet.write(row, 0, fw_serial)
        worksheet.write(row, 1, fw_hostname)
        col = 2
        schedules = firewallDetails[device].get('schedules', {}) or {}
        for item in sorted(headers):
            if item in schedules:
                worksheet.write(row, col, schedules[item])
            else:
                worksheet.write(row, col, '', format_blackBox)
            col += 1
        row += 1
    logger.info("\tFinished Writing Dynamic Content Update Schedule worksheet\n")


def writeWorksheet_ResourceMonitorHistory(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    logger.info("\tWriting Resource Monitor History worksheet...")
    worksheet = workbook.add_worksheet("ResourceMonitorHistory")

    # Formats via per-workbook cache
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    row_header = formats['rowHeader']
    alert_fmt = formats['alertText']
    black_box = formats['blackBox']

    # First pass: gather all possible core IDs and resource names across all firewalls
    # and determine the maximum number of time points
    all_core_ids = set()
    all_resource_names = set()
    max_time_points = 0

    for device in firewallDetails:
        if 'resourceMonitorHistory' in firewallDetails[device]:
            resource_data = firewallDetails[device]['resourceMonitorHistory']

            # Collect all core IDs
            all_core_ids.update(resource_data.get('cpuAverage', {}).keys())
            all_core_ids.update(resource_data.get('cpuMaximum', {}).keys())

            # Collect all resource names
            all_resource_names.update(resource_data.get('resourceUtilization', {}).keys())

            # Determine max number of time points by checking comma-separated values
            for core_id, series in resource_data.get('cpuAverage', {}).items():
                time_points = len(series.split(',')) if isinstance(series, str) else 0
                max_time_points = max(max_time_points, time_points)

            for core_id, series in resource_data.get('cpuMaximum', {}).items():
                time_points = len(series.split(',')) if isinstance(series, str) else 0
                max_time_points = max(max_time_points, time_points)

            for resource, series in resource_data.get('resourceUtilization', {}).items():
                time_points = len(series.split(',')) if isinstance(series, str) else 0
                max_time_points = max(max_time_points, time_points)

    # Sort the sets for consistent column ordering
    all_core_ids = sorted(all_core_ids)
    all_resource_names = sorted(all_resource_names)

    # Calculate column positions
    col_positions = {
        'start': 1,  # Start after Firewall Name column
        'resources': {},
        'cpu_avg': {},
        'cpu_max': {}
    }

    current_col = col_positions['start']

    # Resource Utilization columns first
    for resource_name in all_resource_names:
        col_positions['resources'][resource_name] = current_col
        current_col += max_time_points

    # CPU Average columns
    for core_id in all_core_ids:
        col_positions['cpu_avg'][core_id] = current_col
        current_col += max_time_points

    # CPU Maximum columns
    for core_id in all_core_ids:
        col_positions['cpu_max'][core_id] = current_col
        current_col += max_time_points

    # Header row 0: merged group headers
    worksheet.write(0, 0, "Firewall Name", row_header)

    # Resource Utilization headers
    for resource_name in all_resource_names:
        start_col = col_positions['resources'][resource_name]
        end_col = start_col + max_time_points - 1
        header_text = f"{resource_name} Util (%)"
        if max_time_points == 1:
            worksheet.write(0, start_col, header_text, row_header)
        else:
            worksheet.merge_range(0, start_col, 0, end_col, header_text, row_header)

    # CPU Average headers
    for core_id in all_core_ids:
        start_col = col_positions['cpu_avg'][core_id]
        end_col = start_col + max_time_points - 1
        header_text = f"CPU Avg Core {core_id} (%)"
        if max_time_points == 1:
            worksheet.write(0, start_col, header_text, row_header)
        else:
            worksheet.merge_range(0, start_col, 0, end_col, header_text, row_header)

    # CPU Maximum headers
    for core_id in all_core_ids:
        start_col = col_positions['cpu_max'][core_id]
        end_col = start_col + max_time_points - 1
        header_text = f"CPU Max Core {core_id} (%)"
        if max_time_points == 1:
            worksheet.write(0, start_col, header_text, row_header)
        else:
            worksheet.merge_range(0, start_col, 0, end_col, header_text, row_header)

    # Header row 1: time point labels
    worksheet.write(1, 0, "", row_header)

    time_labels = [f"t-{max_time_points - i - 1}" for i in range(max_time_points)] if max_time_points else []

    # Time labels for resources
    for resource_name in all_resource_names:
        start_col = col_positions['resources'][resource_name]
        for i, label in enumerate(time_labels):
            worksheet.write(1, start_col + i, label, row_header)

    # Time labels for CPU Avg
    for core_id in all_core_ids:
        start_col = col_positions['cpu_avg'][core_id]
        for i, label in enumerate(time_labels):
            worksheet.write(1, start_col + i, label, row_header)

    # Time labels for CPU Max
    for core_id in all_core_ids:
        start_col = col_positions['cpu_max'][core_id]
        for i, label in enumerate(time_labels):
            worksheet.write(1, start_col + i, label, row_header)

    # Data rows
    row = 2
    for device in firewallDetails:
        fwName = firewallDetails[device].get('system', {}).get('hostname', device)
        logger.info(f"\t\tWriting resource monitor data for {fwName} on row {row}")

        worksheet.write(row, 0, fwName)

        if 'resourceMonitorHistory' in firewallDetails[device]:
            resource_data = firewallDetails[device]['resourceMonitorHistory']

            # Resource Utilization values
            for resource_name in all_resource_names:
                start_col = col_positions['resources'][resource_name]
                if resource_name in resource_data.get('resourceUtilization', {}):
                    values = resource_data['resourceUtilization'][resource_name].split(',')
                    values = values + [''] * (max_time_points - len(values))
                    for i, value in enumerate(values):
                        if value:
                            try:
                                val = float(value)
                                worksheet.write(row, start_col + i, val)
                                worksheet.conditional_format(row, start_col + i, row, start_col + i, {
                                    'type': 'cell', 'criteria': '>=', 'value': 80, 'format': alert_fmt
                                })
                            except ValueError:
                                worksheet.write(row, start_col + i, value)
                        else:
                            worksheet.write(row, start_col + i, '', black_box)
                else:
                    for i in range(max_time_points):
                        worksheet.write(row, start_col + i, '', black_box)

            # CPU Average values
            for core_id in all_core_ids:
                start_col = col_positions['cpu_avg'][core_id]
                if core_id in resource_data.get('cpuAverage', {}):
                    values = resource_data['cpuAverage'][core_id].split(',')
                    values = values + [''] * (max_time_points - len(values))
                    for i, value in enumerate(values):
                        if value:
                            try:
                                val = float(value)
                                worksheet.write(row, start_col + i, val)
                                worksheet.conditional_format(row, start_col + i, row, start_col + i, {
                                    'type': 'cell', 'criteria': '>=', 'value': 80, 'format': alert_fmt
                                })
                            except ValueError:
                                worksheet.write(row, start_col + i, value)
                        else:
                            worksheet.write(row, start_col + i, '', black_box)
                else:
                    for i in range(max_time_points):
                        worksheet.write(row, start_col + i, '', black_box)

            # CPU Maximum values
            for core_id in all_core_ids:
                start_col = col_positions['cpu_max'][core_id]
                if core_id in resource_data.get('cpuMaximum', {}):
                    values = resource_data['cpuMaximum'][core_id].split(',')
                    values = values + [''] * (max_time_points - len(values))
                    for i, value in enumerate(values):
                        if value:
                            try:
                                val = float(value)
                                worksheet.write(row, start_col + i, val)
                                worksheet.conditional_format(row, start_col + i, row, start_col + i, {
                                    'type': 'cell', 'criteria': '>=', 'value': 80, 'format': alert_fmt
                                })
                            except ValueError:
                                worksheet.write(row, start_col + i, value)
                        else:
                            worksheet.write(row, start_col + i, '', black_box)
                else:
                    for i in range(max_time_points):
                        worksheet.write(row, start_col + i, '', black_box)
        else:
            # No resource monitor data; fill with black boxes across all groups
            for resource_name in all_resource_names:
                start_col = col_positions['resources'][resource_name]
                for i in range(max_time_points):
                    worksheet.write(row, start_col + i, '', black_box)
            for core_id in all_core_ids:
                start_col = col_positions['cpu_avg'][core_id]
                for i in range(max_time_points):
                    worksheet.write(row, start_col + i, '', black_box)
            for core_id in all_core_ids:
                start_col = col_positions['cpu_max'][core_id]
                for i in range(max_time_points):
                    worksheet.write(row, start_col + i, '', black_box)

        row += 1

    # Column widths and freeze panes
    worksheet.set_column('A:A', 25)
    for col in range(1, current_col):
        worksheet.set_column(col, col, 8)
    worksheet.freeze_panes(2, 1)
    logger.info("\tFinished writing Resource Monitor History worksheet\n")



def writeWorksheet_Licensing(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    """Write licensing worksheet using per-workbook formats cache.
    Columns: Hostname, Serial, then one column per key found under firewallDetails[device]['licensing'] across all devices.
    Cells for missing values are black boxed. Any column ending with '.expired' is highlighted with alertText when value is 'yes'/'true' (case-insensitive).
    """
    logger.info("\tWriting Licensing worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    worksheet = workbook.add_worksheet("Licensing")
    # Discover headers from all devices' licensing dictionaries
    headers: List[str] = []
    for device in firewallDetails:
        licensing = (firewallDetails[device].get('licensing') or {})
        for header in licensing.keys():
            if header not in headers:
                headers.append(header)
    # Write header row
    worksheet.write_row("A1", ["Hostname", "Serial"] + headers, formats['rowHeader'])
    # Data rows
    row = 1
    for device in firewallDetails:
        hostname = firewallDetails[device].get('system', {}).get('hostname', '')
        serial = firewallDetails[device].get('system', {}).get('serial', '')
        worksheet.write(row, 0, hostname)
        worksheet.write(row, 1, serial)
        col = 2
        licensing = firewallDetails[device].get('licensing', {}) or {}
        for header in headers:
            if header in licensing:
                value = licensing[header]
                if isinstance(value, str):
                    v_lower = value.lower()
                else:
                    try:
                        v_lower = str(value).lower()
                    except Exception:
                        v_lower = ''
                if header.endswith('.expired') and (v_lower == 'yes' or v_lower == 'true'):
                    worksheet.write(row, col, value, formats['alertText'])
                else:
                    worksheet.write(row, col, value)
            else:
                worksheet.write(row, col, '', formats['blackBox'])
            col += 1
        row += 1
    logger.info("\tFinished Writing Licensing worksheet\n")


def writeWorksheet_NetworkInterfacesLogical(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    """Write logical interfaces to worksheet using per-workbook formats."""
    logger.info("\tWriting firewall interface (Logical) worksheet")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    headers: List[str] = ['fwName']
    # Discover headers across all devices
    for device in firewallDetails:
        logical = firewallDetails[device].get('interfaces', {}).get('logical', {}) or {}
        for iface in logical:
            for key in logical[iface].keys():
                if key not in headers:
                    headers.append(key)
    worksheet = workbook.add_worksheet("NetworkInterfaces-Logical")
    worksheet.write_row(0, 0, headers, format_rowHeader)
    
    row = 1
    for device in firewallDetails:
        fwName = firewallDetails[device].get('system', {}).get('hostname', device)
        logical = firewallDetails[device].get('interfaces', {}).get('logical', {}) or {}
        for iface in logical:
            col = 0
            for hdr in headers:
                if hdr == 'fwName':
                    worksheet.write(row, col, fwName)
                elif hdr in logical[iface]:
                    worksheet.write(row, col, logical[iface][hdr])
                else:
                    worksheet.write(row, col, '', format_blackBox)
                col += 1
            row += 1
    logger.info("\tFinished writing interface (Logical) worksheet")


def writeWorksheet_NetworkInterfacesHardware(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    """Write hardware interfaces to worksheet using per-workbook formats."""
    logger.info("\tWriting firewall interface (Hardware) worksheet")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    headers: List[str] = ['fwName']
    for device in firewallDetails:
        hw = firewallDetails[device].get('interfaces', {}).get('hardware', {}) or {}
        for iface in hw:
            for key in hw[iface].keys():
                if key not in headers:
                    headers.append(key)

    worksheet = workbook.add_worksheet("NetworkInterfaces-Hardware")
    worksheet.write_row(0, 0, headers, format_rowHeader)

    row = 1
    for device in firewallDetails:
        fwName = firewallDetails[device].get('system', {}).get('hostname', device)
        hw = firewallDetails[device].get('interfaces', {}).get('hardware', {}) or {}
        for iface in hw:
            col = 0
            for hdr in headers:
                if hdr == 'fwName':
                    worksheet.write(row, col, fwName)
                elif hdr in hw[iface]:
                    worksheet.write(row, col, hw[iface][hdr])
                else:
                    worksheet.write(row, col, '', format_blackBox)
                col += 1
            row += 1
    logger.info("\tFinished writing interface (Hardware) worksheet")




def writeWorksheet_NetworkInterfacesDetails(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    """Write full interface details to worksheet using per-workbook formats."""
    logger.info("\tWriting firewall interface (Details) worksheet")
    essential_detail_headers = ['fwName', 'ifnet.name', 'ifnet.zone', 'ifnet.mode']
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    headers: List[str] = list(essential_detail_headers)
    for device in firewallDetails:
        details = firewallDetails[device].get('interfaces', {}).get('fullDetails', {}) or {}
        for iface in details:
            for key in details[iface].keys():
                if key not in headers:
                    headers.append(key)

    worksheet = workbook.add_worksheet("NetworkInterfaces-fullDetails")
    worksheet.write_row(0, 0, headers, format_rowHeader)

    row = 1
    for device in firewallDetails:
        fwName = firewallDetails[device].get('system', {}).get('hostname', device)
        details = firewallDetails[device].get('interfaces', {}).get('fullDetails', {}) or {}
        for iface in details:
            col = 0
            for hdr in headers:
                if hdr == 'fwName':
                    worksheet.write(row, col, fwName)
                elif hdr in details[iface]:
                    worksheet.write(row, col, details[iface][hdr])
                else:
                    worksheet.write(row, col, '', format_blackBox)
                col += 1
            row += 1
    logger.info("\tFinished writing interface (Full Details) worksheet")



def writeWorksheet_EnvironmentalDetails(workbook: xlsxwriter.Workbook, firewallDetails: Dict, firewallDetailsByModel: Dict) -> None:
    """Write firewall Environmental Details worksheet.
    - Groups rows by firewall model using the provided firewallDetailsByModel mapping.
    - Each model section has its own headers derived from its environmentals keys (excluding ".description").
    - Inserts 5 blank rows between different models.
    - Uses alertText for any field whose header contains ".alarm" and value is string "True".
    - Missing values are rendered with the blackBox format.
    """
    logger.info("\tWriting firewall Environmental Details worksheet")
    worksheet = workbook.add_worksheet("SystemEnvironmentals")

    # Formats (centralized via per-workbook cache; initXLSX must be called first)
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    format_alertText = formats['alertText']

    # Build headers per model
    headers_by_model: Dict[str, List[str]] = {}
    for fwModel in firewallDetailsByModel.keys():
        # Start with standard identifiers
        headers = ['fwName', 'fwModel']
        for device in firewallDetailsByModel[fwModel].keys():
            env = firewallDetailsByModel[fwModel][device].get('environmentals', {}) or {}
            for header in env.keys():
                if (header not in headers) and ('.description' not in header):
                    headers.append(header)
        headers_by_model[fwModel] = headers

    # Write sections per model
    row = 0
    for fwModel in headers_by_model.keys():
        # Section header (row headers)
        worksheet.write_row(row, 0, headers_by_model[fwModel], format_rowHeader)
        row += 1
        # Rows per device for this model
        for device in firewallDetailsByModel[fwModel].keys():
            fwName = firewallDetails.get(device, {}).get('system', {}).get('hostname', device)
            fwModel_name = firewallDetails.get(device, {}).get('system', {}).get('model', fwModel)
            col = 0
            env = firewallDetailsByModel[fwModel][device].get('environmentals', {}) or {}
            for item in headers_by_model[fwModel]:
                if item == 'fwName':
                    worksheet.write(row, col, fwName)
                elif item == 'fwModel':
                    worksheet.write(row, col, fwModel_name)
                elif item not in env.keys():
                    worksheet.write(row, col, '', format_blackBox)
                elif ('.alarm' in item) and (env.get(item) == 'True'):
                    worksheet.write(row, col, env.get(item), format_alertText)
                else:
                    worksheet.write(row, col, env.get(item))
                col += 1
            row += 1
        # Skip 5 rows between different models
        row += 5
    logger.info("\tFinished writing firewall Environmental Details worksheet")


def writeWorksheet_SystemState(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    """Write firewall system state worksheet using per-workbook formats cache.
    Sheet name: "System State Details".
    Columns: 'FW Name' followed by all keys found under firewallDetails[device]['systemState'] across devices.
    Missing values are rendered with the blackBox format.
    """
    logger.info("\tWriting firewall system state worksheet.")
    worksheet = workbook.add_worksheet("System State Details")

    # Formats via per-workbook cache (initXLSX must be called before any worksheet writers)
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    # Build headers
    headers: List[str] = ['FW Name']
    for device in firewallDetails:
        sys_state = firewallDetails[device].get('systemState', {}) or {}
        for key in sys_state.keys():
            if key not in headers:
                headers.append(key)

    # Header row
    worksheet.write_row(0, 0, headers, format_rowHeader)

    # Data rows
    row = 1
    for device in firewallDetails:
        fwName = firewallDetails[device].get('system', {}).get('hostname', device)
        worksheet.write(row, 0, fwName)
        col = 1
        sys_state = firewallDetails[device].get('systemState', {}) or {}
        for key in headers[1:]:  # skip 'FW Name'
            if key in sys_state:
                worksheet.write(row, col, sys_state.get(key))
            else:
                worksheet.write(row, col, '', format_blackBox)
            col += 1
        row += 1
    logger.info("\tFinished writing firewall system state worksheet")


def writeWorksheet_SyslogProfiles(workbook: xlsxwriter.Workbook, syslogProfiles: Dict) -> None:
    logger.info("\tWriting Syslog Profiles worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']
    format_centeredText = formats['centeredText']

    # Discover all server attribute headers across all profiles/configs
    serverHeaders: List[str] = []
    for profileName, configs in (syslogProfiles or {}).items():
        for configNum, configData in (configs or {}).items():
            servers = ((configData.get('config') or {}).get('servers')) or {}
            for _serverName, serverConfig in servers.items():
                if isinstance(serverConfig, dict):
                    for attr in serverConfig.keys():
                        if attr not in serverHeaders:
                            serverHeaders.append(attr)

    worksheet = workbook.add_worksheet("Syslog Profiles")
    headers = ['profileName', 'configNum', 'serverName'] + serverHeaders + ['firewallsUsingProfile', 'customFormats']

    worksheet.write_row(0, 0, headers, format_rowHeader)
    row = 1
    for profileName in syslogProfiles:
        for configNum in syslogProfiles[profileName]:
            # Add one to the zero indexed configNum and show the total count of configs for this profile
            configLabel = f"{configNum+1}/{len(syslogProfiles[profileName])}"
            servers = syslogProfiles[profileName][configNum]['config']['servers']
            customFormats = syslogProfiles[profileName][configNum]['config']['customFormats']
            fwList = syslogProfiles[profileName][configNum]['firewalls']
            height = len(servers)
            
            # Write profileName and configNum (merge only if height > 1)
            if height > 1:
                worksheet.merge_range(row, 0, row+height-1, 0, profileName, format_centeredText)
                worksheet.merge_range(row, 1, row+height-1, 1, configLabel, format_centeredText)
            else:
                worksheet.write(row, 0, profileName)
                worksheet.write(row, 1, configLabel)
            
            serverRow = row
            for serverName, serverConfig in servers.items():
                worksheet.write(serverRow, 2, serverName)
                for header in serverHeaders:
                    if header in serverConfig.keys():
                        # Zero index, so move to next column and add the index.
                        worksheet.write(serverRow, 3+serverHeaders.index(header), serverConfig[header])
                    else:
                        worksheet.write(serverRow, 3+serverHeaders.index(header), '', format_blackBox)
                serverRow += 1
            
            # Write firewalls using profile column (merge only if height > 1)
            if height > 1:
                if len(fwList) > 0:
                    #Absolute length, so do NOT advance column number before adding length.
                    worksheet.merge_range(row, 3+len(serverHeaders), row+height-1, 3+len(serverHeaders), ", ".join(fwList))
                else:
                    worksheet.merge_range(row, 3+len(serverHeaders), row+height-1, 3+len(serverHeaders), '', format_blackBox)
            else:
                if len(fwList) > 0:
                    worksheet.write(row, 3+len(serverHeaders), ", ".join(fwList))
                else:
                    worksheet.write(row, 3+len(serverHeaders), '', format_blackBox)
            
            # Write custom formats column (merge only if height > 1)
            if isinstance(customFormats, dict) and customFormats:
                # Render custom format's key: value dict to line-separated string
                customFormatLines = []
                for logType in customFormats.keys():
                    customFormat = customFormats.get(logType)
                    customFormatLines.append(f"{logType}: {customFormat}")
                if height > 1:
                    worksheet.merge_range(row, 4+len(serverHeaders), row + height-1, 4 + len(serverHeaders), ", ".join(customFormatLines))
                else:
                    worksheet.write(row, 4+len(serverHeaders), ", ".join(customFormatLines))
            else:
                if height > 1:
                    worksheet.merge_range(row, 4+len(serverHeaders), row + height-1, 4 + len(serverHeaders), '', format_blackBox)
                else:
                    worksheet.write(row, 4+len(serverHeaders), '', format_blackBox)
            row += height
    logger.info("\tFinished Writing Syslog Profiles worksheet\n")


def writeWorksheet_ZoneProtectionProfile(workbook: xlsxwriter.Workbook, zoneProtectionProfiles_or_profileData: Dict) -> None:
    """Write Zone Protection Profiles worksheet.
    Accepts either:
    - a dict that already looks like profileData['zoneProtectionProfiles']
    - or a dict shaped like {'zoneProtectionProfiles': <that dict>}
    The sheet name is "zoneProtectionProfiles".
    Columns: 'ProfileName', 'ConfigNumber', 'FirewallsUsingConfig', '' separator, then all discovered config keys.
    Missing values are rendered with the blackBox format.
    """
    logger.info("\tWriting Zone Protection Profiles worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    # Normalize input to the inner mapping: { zppName: { configIndex: { 'config': {...}, 'firewalls': [...] }, ... } }
    if 'zoneProtectionProfiles' in (zoneProtectionProfiles_or_profileData or {}):
        zppData = zoneProtectionProfiles_or_profileData.get('zoneProtectionProfiles') or {}
    else:
        zppData = zoneProtectionProfiles_or_profileData or {}

    worksheet = workbook.add_worksheet("zoneProtectionProfiles")

    # Discover all config keys across all profiles/configs
    headers: List[str] = []
    for zppName, configs in (zppData or {}).items():
        for configNum, configEntry in (configs or {}).items():
            config = (configEntry or {}).get('config') or {}
            for key in config.keys():
                if key not in headers:
                    headers.append(key)

    # Write header row
    preHeaders = ['ProfileName', 'ConfigNumber', 'FirewallsUsingConfig', '']
    worksheet.write_row(0, 0, preHeaders + headers, format_rowHeader)

    # Write data rows
    row = 1
    for zppName, configs in (zppData or {}).items():
        total = len(configs)
        for idx, configNum in enumerate(configs.keys()):
            # Some callers may use integer or 0-based keys; render "x/y" using 1-based position when possible
            position = idx + 1
            label = f"{position}/{total}" if total else "1/1"
            entry = configs.get(configNum) or {}
            fwList = entry.get('firewalls', [])
            config = entry.get('config', {}) or {}

            worksheet.write(row, 0, zppName)
            worksheet.write(row, 1, label)
            worksheet.write(row, 2, ", ".join(fwList) if isinstance(fwList, (list, tuple, set)) else str(fwList))
            worksheet.write(row, 3, "", format_blackBox)

            col = 4
            for header in headers:
                if header in config:
                    worksheet.write(row, col, config.get(header))
                else:
                    worksheet.write(row, col, '', format_blackBox)
                col += 1
            row += 1

    logger.info("\tFinished Writing Zone Protection Profiles worksheet\n")


def writeWorksheet_DeviceLogOutputSummary(workbook: xlsxwriter.Workbook, logOutputs_by_type: Dict) -> None:
    """Write aggregated Device Log Outputs summary.

    Expects post-processed data shaped as:
      { logType: { ruleName: { idx: { 'config': <dict>, 'firewalls': [ ... ] }}}}

    Columns:
      'OutputName', 'Number', 'LogType', 'Description', 'Filter',
      'Panorama', 'SNMP', 'E-mail', 'Syslog', 'HTTP',
      'Firewall Count', 'Firewal List'
    """
    logger.info("\tWriting Device log output summary worksheet (aggregated)")

    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    worksheet = workbook.add_worksheet("LogOutputs_Summary")

    headers: List[str] = [
        'OutputName', 'Number', 'LogType', 'Description', 'Filter',
        'Panorama', 'SNMP', 'E-mail', 'Syslog', 'HTTP',
        'Firewall Count', 'Firewal List',
    ]
    worksheet.write_row("A1", headers, format_rowHeader)

    if not isinstance(logOutputs_by_type, dict):
        logger.warning("logOutputs_by_type not a dict; nothing to write")
        return

    row = 1
    # Sort for stable output
    for logType in sorted(logOutputs_by_type.keys()):
        rules_by_name = logOutputs_by_type.get(logType) or {}
        for ruleName in sorted(rules_by_name.keys()):
            variants = rules_by_name.get(ruleName) or {}
            total_variants = len(variants) or 1
            # iterate by numeric index order when possible
            for idx in sorted(variants.keys()):
                entry = variants.get(idx) or {}
                cfg = (entry.get('config') or {})
                firewalls = entry.get('firewalls') or []

                number_label = f"{(idx if isinstance(idx, int) else 0) + 1}/{total_variants}"

                description = cfg.get('ruleDescription', '')
                rule_filter = cfg.get('ruleFilter', '')

                dests = cfg.get('destinations') or {}
                panorama_val = "True" if isinstance(dests, dict) and ('send-to-panorama' in dests.keys()) else "False"

                # Helper to write destination columns or black box if absent
                def write_or_blackbox(col_index: int, key: str) -> None:
                    if isinstance(dests, dict) and key in dests:
                        worksheet.write(row, col_index, str(dests.get(key)))
                    else:
                        worksheet.write(row, col_index, '', format_blackBox)

                firewall_count = len(firewalls)
                firewall_list = ", ".join(firewalls)

                worksheet.write(row, 0, ruleName)
                worksheet.write(row, 1, number_label)
                worksheet.write(row, 2, logType)
                worksheet.write(row, 3, description)
                worksheet.write(row, 4, rule_filter)
                worksheet.write(row, 5, panorama_val)
                write_or_blackbox(6, 'send-snmptrap')
                write_or_blackbox(7, 'send-email')
                write_or_blackbox(8, 'send-syslog')
                write_or_blackbox(9, 'send-http')
                worksheet.write(row, 10, firewall_count)
                worksheet.write(row, 11, firewall_list)

                row += 1

    logger.info("\tFinished writing Device log output summary worksheet\n")


def writeWorksheet_Overrides(workbook: xlsxwriter.Workbook, overridesRows: Dict[str, List[List[str]]]) -> None:
    """
    Creates three worksheets: ActiveOverrides, PassiveOverrides, PseudoOverrides.
    overridesRows expects keys: 'active', 'passive', 'pseudo' with each value being a list of row lists.
    Each row list should match the headers below.
    """
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']

    # Active overrides
    headers_active = ['Hostname', 'xpath', 'localText', 'panoText', 'localAttrib', 'panoAttrib']
    ws_active = workbook.add_worksheet("ActiveOverrides")
    ws_active.write_row("A1", headers_active, format_rowHeader)
    row_index = 1
    for row in overridesRows.get('active', []):
        ws_active.write_row(row_index, 0, row)
        row_index += 1

    # Passive overrides
    headers = ['Hostname', 'xpath', 'text', 'attrib']
    ws_passive = workbook.add_worksheet("PassiveOverrides")
    ws_passive.write_row("A1", headers, format_rowHeader)
    row_index = 1
    for row in overridesRows.get('passive', []):
        ws_passive.write_row(row_index, 0, row)
        row_index += 1

    # Pseudo overrides
    ws_pseudo = workbook.add_worksheet("PseudoOverrides")
    ws_pseudo.write_row("A1", headers, format_rowHeader)
    row_index = 1
    for row in overridesRows.get('pseudo', []):
        ws_pseudo.write_row(row_index, 0, row)
        row_index += 1


def writeWorksheet_OverrideTemplateStacks(workbook: xlsxwriter.Workbook, allTemplates: Dict, stackData: Dict) -> None:
    """
    Reproduces the TemplateStacks layout used by panOverrides: for each stack, write a header row and then rows for
    each member template with values pulled from allTemplates[template] for the stack's computed headers.
    """
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    ws = workbook.add_worksheet("TemplateStacks")
    row = 0
    for stack, details in stackData.items():
        headers = ['stackName', 'TemplateName'] + details.get('headers', [])
        ws.write_row(row, 0, headers, format_rowHeader)
        row += 1
        for template in details.get('members', []):
            ws.write(row, 0, stack)
            ws.write(row, 1, template)
            col = 2
            for header in details.get('headers', []):
                if header in allTemplates.get(template, {}):
                    ws.write(row, col, allTemplates[template][header])
                else:
                    ws.write(row, col, "", format_blackBox)
                col += 1
            row += 1


def writeWorksheet_LogCollectorStatusDetails(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    """Write verbose logging-status details per collector/connector.

    Sheet name: "LoggingStatus-Details".
    Rows: one per entry (collector/connector) per firewall.
    Columns:
      - FW Name
      - EntryName
      - All discovered KV keys from details[entry]['kv'] (kept as-is)
      - For each log tag discovered under details[entry]['logs']:
          tag.last_created, tag.last_forwarded,
          tag.last_seq_forwarded, tag.last_seq_acked, tag.total_forwarded
    Any missing values are written with blackBox format.
    Datetime objects are rendered as ISO-like strings.
    """
    logger.info("\tWriting LoggingStatus-Details worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    # Discover union of kv keys and log tags across all devices/entries
    connectivityHeaders: List[str] = []
    logtypeHeaders: List[str] = []

    for device in (firewallDetails or {}):
        loggingStatus = (firewallDetails[device] or {}).get('logCollectorStatus') or {}
        details = loggingStatus.get('details') or {}
        for logCollector, logCollectorItems in details.items():
            connectivityData = (logCollectorItems or {}).get('kv') or {}
            for connectivityHeader in connectivityData.keys():
                if connectivityHeader not in connectivityHeaders:
                    connectivityHeaders.append(connectivityHeader)
            logTypeData = (logCollectorItems or {}).get('logs') or {}
            for logType in logTypeData.keys():
                if logType not in logtypeHeaders:
                    logtypeHeaders.append(logType)

    # Build dynamic log field headers per log type based on discovered keys
    # Map: logType -> [field1, field2, ...] (excluding the 'type' label key)
    log_fields_by_type: Dict[str, List[str]] = {}
    for device in (firewallDetails or {}):
        loggingStatus = (firewallDetails[device] or {}).get('logCollectorStatus') or {}
        details = loggingStatus.get('details') or {}
        for _entry, items in (details or {}).items():
            logs_map = (items or {}).get('logs') or {}
            for logType, parsed in (logs_map or {}).items():
                if logType not in log_fields_by_type:
                    log_fields_by_type[logType] = []
                if isinstance(parsed, dict):
                    for fld in parsed.keys():
                        if fld == 'type':
                            continue
                        if fld not in log_fields_by_type[logType]:
                            log_fields_by_type[logType].append(fld)

    # Compose flattened log headers like "<logType>.<field>"
    log_headers: List[str] = []
    for logType in logtypeHeaders:
        for fld in log_fields_by_type.get(logType, []):
            log_headers.append(f"{logType}.{fld}")

    worksheet = workbook.add_worksheet("LogCollectorStatus-Details")
    headers: List[str] = ['FW Name', 'FW Serial', 'EntryName'] + connectivityHeaders + log_headers
    worksheet.write_row(0, 0, headers, format_rowHeader)

    # Write rows
    row = 1
    for device in (firewallDetails or {}):
        sys_info = (firewallDetails[device] or {}).get('system', {}) or {}
        fwName = sys_info.get('hostname', device)
        # Derive fwSerial: prefer system.serial, fallback to loggingStatus.fw_serial or parse from device key
        loggingStatus = (firewallDetails[device] or {}).get('logCollectorStatus') or {}
        fwSerial = sys_info.get('serial') or loggingStatus.get('fw_serial')
        if not fwSerial and isinstance(device, str) and '(' in device and device.endswith(')'):
            try:
                fwSerial = device.rsplit('(', 1)[1][:-1]
            except Exception:
                fwSerial = None
        details = loggingStatus.get('details') or {}
        for logCollector, logCollectorItems in details.items():
            col = 0
            worksheet.write(row, col, fwName); col += 1
            worksheet.write(row, col, fwSerial); col += 1
            worksheet.write(row, col, logCollector); col += 1

            connectivityData = (logCollectorItems or {}).get('kv') or {}
            # Write KV columns
            for connectivityHeader in connectivityHeaders:
                if connectivityHeader in connectivityData:
                    worksheet.write(row, col, datetime_to_string(connectivityData.get(connectivityHeader)))
                else:
                    worksheet.write(row, col, '', format_blackBox)
                col += 1

            # Write LOG columns
            logTypeData = (logCollectorItems or {}).get('logs') or {}
            for logType in logtypeHeaders:
                parsed = logTypeData.get(logType) or {}
                # Use dynamic fields for each logType
                for fld in log_fields_by_type.get(logType, []):
                    if fld in parsed:
                        worksheet.write(row, col, datetime_to_string(parsed.get(fld)))
                    else:
                        worksheet.write(row, col, '', format_blackBox)
                    col += 1
            row += 1
    logger.info("\tFinished Writing LoggingStatus-Details worksheet\n")



def writeWorksheet_LogCollectorStatusSummary(workbook: xlsxwriter.Workbook, firewallDetails: Dict) -> None:
    """Write verbose logging-status connection summary per firewall.

    Sheet name: "LoggingStatus-Summary".
    Rows: one per firewall device in firewallDetails.
    Columns: 'FW Name' followed by union of keys from logCollectorStatus['summary'].
    Datetime objects are rendered as ISO-like strings.
    """
    logger.info("\tWriting LoggingStatus-Summary worksheet.")
    formats = getattr(workbook, STYLE_CACHE_ATTR)
    format_rowHeader = formats['rowHeader']
    format_blackBox = formats['blackBox']

    # Discover union of summary keys
    sum_headers: List[str] = []
    for device in (firewallDetails or {}):
        ls = (firewallDetails[device] or {}).get('logCollectorStatus') or {}
        summary = ls.get('summary') or {}
        for k in summary.keys():
            if k not in sum_headers:
                sum_headers.append(k)

    worksheet = workbook.add_worksheet("LogCollectorStatus-Summary")
    headers = ['FW Name', 'FW Serial'] + sum_headers
    worksheet.write_row(0, 0, headers, format_rowHeader)

    row = 1
    for device in (firewallDetails or {}):
        sys_info = (firewallDetails[device] or {}).get('system', {}) or {}
        fwName = sys_info.get('hostname', device)
        ls = (firewallDetails[device] or {}).get('logCollectorStatus') or {}
        fwSerial = sys_info.get('serial') or ls.get('fw_serial')
        if not fwSerial and isinstance(device, str) and '(' in device and device.endswith(')'):
            try:
                fwSerial = device.rsplit('(', 1)[1][:-1]
            except Exception:
                fwSerial = None
        summary = ls.get('summary') or {}
        worksheet.write(row, 0, fwName)
        worksheet.write(row, 1, fwSerial)
        col = 2
        for k in sum_headers:
            if k in summary:
                value = datetime_to_string(summary.get(k))
                # Coerce non-scalar structures to readable strings to avoid xlsxwriter TypeError
                try:
                    if isinstance(value, (list, tuple, set)):
                        value = ", ".join(str(item) for item in value)
                    elif isinstance(value, dict):
                        # Stable, compact representation: key: value pairs
                        value = ", ".join(f"{str(key)}: {str(val)}" for key, val in value.items())
                except Exception:
                    # Fallback to str() for anything unexpected
                    try:
                        value = str(value)
                    except Exception:
                        value = ''
                worksheet.write(row, col, value)
            else:
                worksheet.write(row, col, '', format_blackBox)
            col += 1
        row += 1

    logger.info("\tFinished Writing LoggingStatus-Summary worksheet\n")
