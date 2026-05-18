from pancore import panCore, panExcelStyles
import panos, sys, argparse, xlsxwriter


CERT_TAGS = [
    'subject-hash', 'issuer-hash', 'not-valid-before', 'issuer',
    'not-valid-after', 'common-name', 'expiry-epoch', 'ca',
    'subject', 'public-key', 'algorithm', 'common-name-int', 'subject-int'
]


def extract_certificate_entries(xml_parent, entry_xpath):
    """Return list of dicts for certificate entries under xml_parent using entry_xpath.

    Each dict contains keys from CERT_TAGS plus 'name'. Missing nodes are empty strings.
    """
    if xml_parent is None:
        return []
    cert_list = []
    for cert_node in xml_parent.xpath(entry_xpath):
        cert_name = cert_node.attrib.get('name', '')
        cert_record = {'name': cert_name}
        for tag in CERT_TAGS:
            node = cert_node.find(f'./{tag}')
            cert_record[tag] = (node.text.strip() if node is not None and node.text is not None else '')
        cert_list.append(cert_record)
    return cert_list


if __name__ == "__main__":
    # Initialize CLI, logging, config, and Panorama connection
    parser = argparse.ArgumentParser(
        prog="inventoryCertificates",
        description="Inventory certificates from Panorama templates and export to Excel.")
    parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
    parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='panInventory.log')
    parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
    parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='CertificateDetails.xlsx')
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

    # Data structure:
    # cert_data[template_name]['shared'] = [list of cert dicts]
    # cert_data[template_name]['vsys'][vsys_name] = [list of cert dicts]
    cert_data = {}

    for tpl_obj in templates:
        template_name = tpl_obj.name
        base_xpath = tpl_obj.xpath()
        cert_data[template_name] = {'shared': [], 'vsys': {}}
        panCore.logging.info(f"Gathering certificates for template: {template_name}")

        # Shared certificates for this template
        try:
            xpath_shared = base_xpath + "/config/shared/certificate"
            xml_shared = panCore.xmlToLXML(pano_obj.xapi.get(xpath_shared))
            shared_list = extract_certificate_entries(xml_shared, '///response/result/certificate/entry')
            cert_data[template_name]['shared'] = shared_list
            panCore.logging.info(f"\tShared certificates found: {len(shared_list)}")
        except Exception as exc:
            panCore.logging.warning(f"\tFailed to parse shared certificates for template '{template_name}': {exc}")

        # Per-VSYS certificates under localhost.localdomain for this template
        try:
            xpath_vsys = base_xpath + "/config/devices/entry[@name='localhost.localdomain']/vsys"
            xml_vsys = panCore.xmlToLXML(pano_obj.xapi.get(xpath_vsys))
            for vsys_entry in xml_vsys.xpath('///response/result/vsys/entry'):
                vsys_name = vsys_entry.attrib.get('name', 'unknown')
                entry_list = extract_certificate_entries(vsys_entry, './certificate/entry')
                cert_data[template_name]['vsys'][vsys_name] = entry_list
                panCore.logging.info(f"\tVSYS '{vsys_name}' certificates found: {len(entry_list)}")
        except Exception as exc:
            panCore.logging.warning(f"\tFailed to parse vsys certificates for template '{template_name}': {exc}")

    # --------------------
    # Build Excel workbook
    # --------------------
    try:
        workbook = xlsxwriter.Workbook(args.workbookname)
        fmt_header = workbook.add_format(panExcelStyles.styles['rowHeader'])
        fmt_black = workbook.add_format(panExcelStyles.styles['blackBox'])
        fmt_normal = workbook.add_format(panExcelStyles.styles['normalText'])

        # Sheet 1: Shared certificates per template
        ws_shared = workbook.add_worksheet('Shared Certificates')
        shared_headers = ['template_name', 'cert_name'] + CERT_TAGS
        ws_shared.write_row('A1', shared_headers, fmt_header)
        row_idx = 1
        for template_name, data in cert_data.items():
            for record in data['shared']:
                ws_shared.write(row_idx, 0, template_name, fmt_normal)
                ws_shared.write(row_idx, 1, record.get('name', ''), fmt_normal)
                for col_offset, tag in enumerate(CERT_TAGS, start=2):
                    value = record.get(tag, '')
                    if value == '':
                        ws_shared.write(row_idx, col_offset, '', fmt_black)
                    else:
                        ws_shared.write(row_idx, col_offset, value, fmt_normal)
                row_idx += 1

        # Sheet 2: VSYS certificates per template
        ws_vsys = workbook.add_worksheet('VSYS Certificates')
        vsys_headers = ['template_name', 'vsys_name', 'cert_name'] + CERT_TAGS
        ws_vsys.write_row('A1', vsys_headers, fmt_header)
        row_idx = 1
        for template_name, data in cert_data.items():
            for vsys_name, records in data['vsys'].items():
                for record in records:
                    ws_vsys.write(row_idx, 0, template_name, fmt_normal)
                    ws_vsys.write(row_idx, 1, vsys_name, fmt_normal)
                    ws_vsys.write(row_idx, 2, record.get('name', ''), fmt_normal)
                    for col_offset, tag in enumerate(CERT_TAGS, start=3):
                        value = record.get(tag, '')
                        if value == '':
                            ws_vsys.write(row_idx, col_offset, '', fmt_black)
                        else:
                            ws_vsys.write(row_idx, col_offset, value, fmt_normal)
                    row_idx += 1

        workbook.close()
        panCore.logging.info(f"Certificate workbook written: {args.workbookname}")
    except Exception as exc:
        panCore.logging.error(f"Failed to write workbook '{args.workbookname}': {exc}")
        try:
            # Attempt to close if created
            workbook.close()
        except Exception:
            pass
