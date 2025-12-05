#!/usr/bin/env python
"""
setGroupMappingUserFormat.py

Purpose:
- Iterate Panorama Templates and locate group-mapping configurations across all VSYS under each Template.
- Optionally modify per-group-mapping fields:
  - domain: delete (default) or set to a user-provided value.
  - username order: set user-name/member and alternate-user-name-1/member to either
    UPN-first or sAMAccountName-first, based on a user flag.

Notes:
- This script operates on the Panorama candidate configuration. It does not commit.
- Uses panCore to bootstrap Panorama connectivity and logging, consistent with the project style.
"""
from __future__ import annotations

import argparse
import logging
import sys
from typing import Dict, Any

from pancore import panCore
from pancore import panWorkbookFunctions


def build_args():
    parser = argparse.ArgumentParser(
        prog="setGroupMappingUserFormat",
        description=(
            "Adjust Template group-mapping username format and domain field. "
            "By default, will delete the <domain> field. Optionally set a standard domain value "
            "and enforce a username order (UPN first or sAMAccountName first)."
        ),
    )
    parser.add_argument('-L', '--logfile', default='setGroupMappingUserFormat.log', help='Log file to write log output to')
    parser.add_argument('-c', '--conffile', default='panCoreConfig.json', help='panCore config file (JSON)')
    parser.add_argument('-w', '--workbookname', default='GroupMappingByTemplate.xlsx', help='Output Excel workbook name')
    parser.add_argument('--headless', default=False, help='Run without user interaction. Will not prompt for credential or connectivity info if config file not found.')
    parser.add_argument('-E', '--enable', action='store_true', default=False, help='Apply changes to Panorama candidate config (otherwise report-only)')

    # Domain handling
    parser.add_argument('--domain-action', choices=['delete', 'set', 'none'], default='delete', help="What to do with the <domain> element under each group-mapping: delete (default), set, or none")
    parser.add_argument('--domain-value', default=None, help="Domain value to set when --domain-action=set (e.g., example.com)")

    # Username order handling (boolean: default UPN-first; override to prefer sAMAccountName)
    parser.add_argument('--prefer-sam', dest='prefer_sam', action='store_true', default=False, help='Prefer sAMAccountName first (user-name=sAMAccountName, alternate-user-name-1=userPrincipalName). Default is UPN first.')
    return parser.parse_known_args()


def get_template_group_mappings(pano_obj, template_name: str) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Return mapping of vsys_name -> { groupMappingName -> details } across all vsys under the template.
    details include: { 'MappingName', optional 'domain', 'user-name', 'alternate-user-name-1', 'vsys' }
    """
    base_path = f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{template_name}']/config/devices/entry[@name='localhost.localdomain']/vsys"
    xml_data = panCore.xmlToLXML(pano_obj.xapi.get(base_path))
    result: Dict[str, Dict[str, Dict[str, Any]]] = {}
    # Iterate all vsys entries
    for vsys_entry in xml_data.xpath('//response/result/vsys/entry') or []:
        vsys_name = vsys_entry.get('name') or 'vsys1'
        gm_parent = vsys_entry.find('group-mapping')
        if gm_parent is None:
            continue
        gm_dict: Dict[str, Dict[str, Any]] = {}
        for entry in gm_parent.findall('entry'):
            gm_name = entry.get('name')
            if not gm_name:
                continue
            item: Dict[str, Any] = {'MappingName': gm_name, 'vsys': vsys_name}
            dom = entry.find('domain')
            if dom is not None and dom.text:
                item['domain'] = dom.text
            un = entry.find('user-name/member')
            if un is not None and un.text:
                item['user-name'] = un.text
            alt1 = entry.find('alternate-user-name-1/member')
            if alt1 is not None and alt1.text:
                item['alternate-user-name-1'] = alt1.text
            gm_dict[gm_name] = item
        if gm_dict:
            result[vsys_name] = gm_dict
    return result


def apply_domain_change(pano_obj, template_name: str, vsys_name: str, gm_name: str, action: str, value: str | None) -> None:
    base = (
        f"/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='{template_name}']"
        f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys_name}']"
        f"/group-mapping/entry[@name='{gm_name}']/domain"
    )
    if action == 'delete':
        try:
            pano_obj.xapi.delete(base)
        except Exception:
            # If already absent, ignore
            pass
    elif action == 'set':
        if not value:
            raise ValueError("--domain-action=set requires --domain-value")
        # Use set to create or replace the domain element
        pano_obj.xapi.set(base.rsplit('/domain', 1)[0], f"<domain>{value}</domain>")
    else:
        # none: do nothing
        return


def apply_username_order(pano_obj, template_name: str, vsys_name: str, gm_name: str, order: str) -> None:
    # Define desired values
    if order == 'upn-first':
        primary = 'userPrincipalName'
        alternate = 'sAMAccountName'
    else:  # 'sam-first'
        primary = 'sAMAccountName'
        alternate = 'userPrincipalName'

    base = (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/template/entry[@name='{template_name}']"
        f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys_name}']"
        f"/group-mapping/entry[@name='{gm_name}']"
    )
    # Replace (not append): remove existing username nodes before setting one member each
    u_path = base + "/user-name"
    alt_path = base + "/alternate-user-name-1"
    try:
        pano_obj.xapi.delete(u_path)
    except Exception:
        # Ignore if absent
        pass
    try:
        pano_obj.xapi.delete(alt_path)
    except Exception:
        # Ignore if absent
        pass
    # Now set single-member subtrees
    pano_obj.xapi.set(base, f"<user-name><member>{primary}</member></user-name>")
    pano_obj.xapi.set(base, f"<alternate-user-name-1><member>{alternate}</member></alternate-user-name-1>")



def main():
    args, _ = build_args()
    logger = panCore.startLogging(args.logfile)

    # Sanity for domain args
    if args.domain_action == 'set' and not args.domain_value:
        logger.error("--domain-action=set requires --domain-value")
        sys.exit(2)

    username_order = 'sam-first' if getattr(args, 'prefer_sam', False) else 'upn-first'

    # Bootstrap Panorama session
    try:
        panCore.configStart(headless=args.headless, configStorage=args.conffile)
    except Exception as e:
        logging.exception("Failed to initialize panCore configuration")
        sys.exit(1)

    if hasattr(panCore, 'panUser'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
    elif hasattr(panCore, 'panKey'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
    else:
        logging.critical("Found neither username/password nor API key. Exiting.")
        sys.exit(1)

    # Iterate templates and their group mappings
    total_targets = 0
    total_actions = 0
    # Collect rows for Excel output regardless of --enable
    excel_rows = []  # list of tuples: (TemplateName, VSYS, MappingName, domain, user-name, alternate-user-name-1)

    for tpl_obj in templates:
        tpl_name = getattr(tpl_obj, 'name', None)
        if not tpl_name:
            continue
        groupMappingMap = get_template_group_mappings(pano_obj, tpl_name)
        if not groupMappingMap:
            continue
        for vsys_name, groupMappingDict in groupMappingMap.items():
            for gm_name, record in groupMappingDict.items():
                total_targets += 1
                # Always capture current state row for Excel
                excel_rows.append(
                    (
                        tpl_name,
                        vsys_name,
                        gm_name,
                        record.get('domain'),
                        record.get('user-name'),
                        record.get('alternate-user-name-1'),
                    )
                )
                # Plan description
                planned = []
                if args.domain_action == 'delete':
                    if 'domain' in record:
                        planned.append("delete domain")
                elif args.domain_action == 'set':
                    if record.get('domain') != args.domain_value:
                        planned.append(f"set domain='{args.domain_value}'")
                # Username order (always evaluate; we default to UPN-first unless --prefer-sam)
                desired_primary = 'userPrincipalName' if username_order == 'upn-first' else 'sAMAccountName'
                desired_alt = 'sAMAccountName' if username_order == 'upn-first' else 'userPrincipalName'
                curr_primary = record.get('user-name')
                curr_alt = record.get('alternate-user-name-1')
                if curr_primary != desired_primary or curr_alt != desired_alt:
                    planned.append(f"set usernames primary={desired_primary}, alt={desired_alt}")
                if not planned:
                    logging.info(f"Template '{tpl_name}' VSYS '{vsys_name}' GM '{gm_name}': no change")
                    continue

                logging.info(f"Template '{tpl_name}' VSYS '{vsys_name}' GM '{gm_name}': planned -> {', '.join(planned)}")

                if args.enable:
                    # Apply changes
                    try:
                        apply_domain_change(pano_obj, tpl_name, vsys_name, gm_name, args.domain_action, args.domain_value)
                        apply_username_order(pano_obj, tpl_name, vsys_name, gm_name, username_order)
                        total_actions += 1
                    except Exception as e:
                        logging.exception(f"Failed to update Template '{tpl_name}' VSYS '{vsys_name}' GroupMapping '{gm_name}'")
                        logging.exception(e)

    # Write Excel report of the current state (captured before any changes were applied)
    try:
        workbook = panWorkbookFunctions.initXLSX(args.workbookname)
        worksheet = workbook.add_worksheet('Template_GroupMappings')
        # Access cached formats built by initXLSX
        formats = getattr(workbook, "_pan_style_cache", {})
        fmt_header = formats.get('rowHeader')
        fmt_black = formats.get('blackBox')
        headers = ['TemplateName', 'VSYS', 'MappingName', 'domain', 'user-name', 'alternate-user-name-1']
        worksheet.write_row(0, 0, headers, fmt_header)
        row_idx = 1
        for tpl_name, vsys_name, gm_name, domain, user_name, alt1 in excel_rows:
            worksheet.write(row_idx, 0, tpl_name)
            worksheet.write(row_idx, 1, vsys_name)
            worksheet.write(row_idx, 2, gm_name)
            # domain
            if domain:
                worksheet.write(row_idx, 3, domain)
            else:
                worksheet.write(row_idx, 3, '', fmt_black)
            # user-name
            if user_name:
                worksheet.write(row_idx, 4, user_name)
            else:
                worksheet.write(row_idx, 4, '', fmt_black)
            # alternate-user-name-1
            if alt1:
                worksheet.write(row_idx, 5, alt1)
            else:
                worksheet.write(row_idx, 5, '', fmt_black)
            row_idx += 1
        # Widths for readability
        worksheet.set_column(0, 0, 26)
        worksheet.set_column(1, 1, 10)
        worksheet.set_column(2, 2, 28)
        worksheet.set_column(3, 5, 32)
        workbook.close()
        logging.info(f"Excel report written to {args.workbookname} with {len(excel_rows)} rows")
    except Exception as e:
        logging.exception("Failed to write Excel report")
        logging.exception(e)

    if args.enable:
        logging.info("Changes have been placed in the Panorama candidate configuration. Review and commit in the Panorama GUI.")
    logging.info(f"Targets examined: {total_targets}; Entries updated: {total_actions}")


if __name__ == '__main__':
    main()
