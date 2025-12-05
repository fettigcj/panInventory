#!/usr/bin/env python

"""
setPanoCIE.py

Report and optionally set the Cloud Identity Engine (CIE) configuration under:
- Panorama Device Groups: /config/devices/entry[@name='localhost.localdomain']/device-group/entry/.../user-group-source
- Panorama Template Stacks: /config/devices/entry[@name='localhost.localdomain']/template-stack/entry/.../user-group-source

Safety:
- Report-only by default. No commit functionality is provided. Review candidate
  configuration and commit via the Panorama GUI.

Behavior:
- For Device Groups (DGs), by default only set CIE when the DG has no <master-device>.
  Use --force-dg to override and set regardless of master-device presence.
- For Template Stacks (TSs), simply ensure the CIE value matches the requested name.

Optimization:
- This script retrieves only the required config subtrees via a path-parameterized
  getter rather than downloading the entire running config.

Examples:
- Report only, DGs and TSs (default):
    python setPanoCIE.py -c panCoreConfig.json
- Apply to both DGs (without overwriting existing master-device) and TSs:
    python setPanoCIE.py -c panCoreConfig.json --enable --cie CIE_InstanceName
- Force DG update despite master-device presence (applies to all DGs):
    python setPanoCIE.py --enable --force-dg
"""

from __future__ import annotations
from typing import List, Tuple, Optional
import argparse
import logging
import sys
import lxml.etree as ET
from pancore import panCore
from panos import panorama

logger = logging.getLogger(__name__)

DG_BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']/device-group"
TS_BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']/template-stack"

def get_config_subtree_lxml(pano_obj: panorama.Panorama, path: str) -> ET._Element:
    """Retrieve only the specified config subtree and return it as an lxml element."""
    xml = pano_obj.xapi.get(path)
    return panCore.xmlToLXML(xml)

# Set new config API setters

def set_dg_cie(pano_obj: panorama.Panorama, dg: str, cie_value: str) -> None:
    cie_xpath = (f"{DG_BASE_XPATH}/entry[@name='{dg}']/user-group-source/cloud-identity-engine")
    element_xml = f"<member>{cie_value}</member>"
    logger.info(f"Setting DG '{dg}' CIE → {cie_value}")
    pano_obj.xapi.set(cie_xpath, element_xml)


def set_ts_cie(pano_obj: panorama.Panorama, ts: str, cie_value: str) -> None:
    cie_xpath = (
        f"{TS_BASE_XPATH}/entry[@name='{ts}']/user-group-source/cloud-identity-engine"
    )
    element_xml = f"<member>{cie_value}</member>"
    logger.info(f"Setting Template Stack '{ts}' CIE → {cie_value}")
    pano_obj.xapi.set(cie_xpath, element_xml)


# Consolidated API getters: one GET per DG/TS user-group-source subtree

def getDeviceGroupUID(pano_obj: panorama.Panorama, dg: str) -> dict:
    """
    Fetch the DG's user-group-source subtree once and return a dict describing
    the User-ID source configuration.

    Return format:
      - If CIE present: {'type': 'CIE', 'name': <CIE instance name>}
      - Elif master-device present: {'type': 'master_device', 'name': <serial number>}
      - Else: {'type': 'NotConfigured', 'name': None}
    """
    try:
        xml = pano_obj.xapi.get(f"{DG_BASE_XPATH}/entry[@name='{dg}']/user-group-source")
        doc = panCore.xmlToLXML(xml)
        nodes = doc.xpath("//user-group-source")
        if not nodes:
            return {'type': 'NotConfigured', 'name': None}
        userGroupSource = nodes[0]
        # Check for CIE first
        cie_nodes = userGroupSource.xpath("cloud-identity-engine/member")
        if cie_nodes and cie_nodes[0] is not None and (cie_nodes[0].text is not None):
            return {'type': 'CIE', 'name': cie_nodes[0].text}
        # Check for master-device serial
        md_list = userGroupSource.xpath("master-device/device/text()")
        if md_list:
            return {'type': 'master_device', 'name': md_list[0]}
        # Neither configured
        return {'type': 'NotConfigured', 'name': None}
    except Exception:
        return {'type': 'NotConfigured', 'name': None}


def getTemplateStackUID(pano_obj: panorama.Panorama, ts: str) -> dict:
    """
    Fetch the TS’s user-group-source subtree once and return a dict describing
    the User-ID source configuration.

    Returns one of:
      - {'type': 'CIE', 'name': <CIE instance name>}
      - {'type': 'legacy', 'name': <best-effort legacy source name or 'N/A'>}
      - {'type': 'NotConfigured', 'name': None}
    """
    try:
        xml = pano_obj.xapi.get(f"{TS_BASE_XPATH}/entry[@name='{ts}']/user-group-source")
        doc = panCore.xmlToLXML(xml)
        nodes = doc.xpath("//user-group-source")
        if not nodes:
            return {'type': 'NotConfigured', 'name': None}
        userGroupSource = nodes[0]

        # Test if CIE is present: test for child existence and extract its text
        cie_texts = userGroupSource.xpath("cloud-identity-engine/member/text()")
        if cie_texts:
            return {'type': 'CIE', 'name': cie_texts[0]}

        masterDevice = userGroupSource.xpath("master-device/device/text()")[0]
        return {'type': 'legacy', 'name': masterDevice}
    except Exception:
        return {'type': 'NotConfigured', 'name': None}


# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(
        prog="setPanoCIE",
        description=(
            "Report and optionally set the Cloud Identity Engine configuration "
            "for Panorama Device Groups and/or Template Stacks, and export an Excel report."
        ),
    )

    #parser.add_argument('-I', '--headless', action='store_true', default=False, help='Disable interactions; requires creds in config')
    parser.add_argument('-L', '--logfile', default='setPanoCIE.log', help='Log file path')
    parser.add_argument('-c', '--conffile', default='panCoreConfig.json', help='Config JSON for Panorama access')
    parser.add_argument('-w', '--workbookname', default='setPanoCIE.xlsx', help='Output Excel workbook name')
    parser.add_argument('-E', '--enable', action='store_true', default=False, help='Apply changes (otherwise report-only)')
    parser.add_argument('--cie', default='CIE_Instance', help='Cloud Identity Engine instance name to set')
    parser.add_argument('--scope', choices=['dg', 'ts', 'both'], default='both', help='Target scope: device groups, template stacks, or both')
    parser.add_argument('--force-dg', dest='force_dg', action='store_true', default=False, help='Set DG CIE even if <master-device> is present')
    args, unknown = parser.parse_known_args()
    logger = panCore.startLogging(args.logfile)

    # Bootstrap Panorama session via panCore
    panCore.configStart(headless=False, configStorage=args.conffile)
    if hasattr(panCore, 'panUser'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(
            panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
    elif hasattr(panCore, 'panKey'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(
            panAddress=panCore.panAddress, panKey=panCore.panKey)
    else:
        logger.critical("Found neither username/password nor API key. Exiting.")
        sys.exit(1)

    # Build targets directly from panCore-provided objects instead of parsing subtrees
    target_dgs: List[str] = []
    target_tss: List[str] = []

    if args.scope in ('dg', 'both'):
        try:
            target_dgs = [dg_obj.name for dg_obj in deviceGroups if getattr(dg_obj, 'name', None)]
        except Exception as e:
            logger.exception("Failed to build device group list from panCore.deviceGroups")
            logger.exception(e)
            target_dgs = []

    if args.scope in ('ts', 'both'):
        try:
            target_tss = [ts_obj.name for ts_obj in tStacks if getattr(ts_obj, 'name', None)]
        except Exception as e:
            logger.exception("Failed to build template stack list from panCore.tStacks")
            logger.exception(e)
            target_tss = []

    logger.info("Inspecting Panorama configuration for CIE settings…")

    # Collection phase: only gather current UID source type & name for Excel
    dg_rows = []  # [{ name, source_type, source_name }]
    ts_rows = []  # [{ name, source_type, source_name }]

    dg_uid_map = {}  # { dg_name: {type, name} }
    for dg in target_dgs:
        uid = getDeviceGroupUID(pano_obj, dg)
        dg_uid_map[dg] = uid
        if uid['type'] == 'CIE':
            source_type, source_name = 'CIE', uid['name']
        elif uid['type'] == 'master_device':
            source_type, source_name = 'legacy', uid['name']  # serial number
        elif uid['type'] == 'legacy':
            source_type, source_name = 'legacy', uid['name']
        else:
            source_type, source_name = 'NotConfigured', None
        dg_rows.append({'name': dg, 'source_type': source_type, 'source_name': source_name})
        logger.info(f"DG='{dg}': uid_type={uid['type']}; name={uid['name']}")

    ts_uid_map = {}  # { ts_name: {type, name} }
    for ts in target_tss:
        uid = getTemplateStackUID(pano_obj, ts)
        ts_uid_map[ts] = uid
        if uid['type'] == 'CIE':
            source_type, source_name = 'CIE', uid['name']
        elif uid['type'] == 'legacy':
            source_type, source_name = 'legacy', uid['name']
        else:
            source_type, source_name = 'NotConfigured', None
        ts_rows.append({'name': ts, 'source_type': source_type, 'source_name': source_name})
        logger.info(f"TS='{ts}': uid_type={uid['type']}; name={uid['name']}")

    # Always write Excel report
    try:
        from pancore import panWorkbookFunctions
        workbook = panWorkbookFunctions.initXLSX(args.workbookname)
        # Write Template Stacks sheet
        ws_ts = workbook.add_worksheet('TemplateStacks-UserID')
        header = ['Template Stack', 'Source Type', 'Source Name']
        for col, h in enumerate(header):
            ws_ts.write(0, col, h)
        for row_idx, row in enumerate(ts_rows, start=1):
            ws_ts.write(row_idx, 0, row['name'])
            ws_ts.write(row_idx, 1, row['source_type'])
            ws_ts.write(row_idx, 2, row['source_name'])
        # Write Device Groups sheet
        ws_dg = workbook.add_worksheet('DeviceGroups-UserID')
        header_dg = ['Device Group', 'Source Type', 'Source Name']
        for col, h in enumerate(header_dg):
            ws_dg.write(0, col, h)
        for row_idx, row in enumerate(dg_rows, start=1):
            ws_dg.write(row_idx, 0, row['name'])
            ws_dg.write(row_idx, 1, row['source_type'])
            ws_dg.write(row_idx, 2, row['source_name'])
        workbook.close()
        logger.info(f"Excel report written to {args.workbookname}")
    except Exception as e:
        logger.exception("Failed to write Excel report")
        logger.exception(e)

    # Update phase: decide and apply only when --enable
    if args.enable:
        dgs_to_update: List[str] = []
        for dg, uid in dg_uid_map.items():
            if uid['type'] == 'master_device' and not args.force_dg:
                continue
            needs_change = not (uid['type'] == 'CIE' and uid['name'] == args.cie)
            if needs_change:
                dgs_to_update.append(dg)

        tss_to_update: List[str] = []
        for ts, uid in ts_uid_map.items():
            needs_change = not (uid['type'] == 'CIE' and uid['name'] == args.cie)
            if needs_change:
                tss_to_update.append(ts)

        if not dgs_to_update and not tss_to_update:
            logger.info("No updates required.")
        else:
            logger.info(
                f"Pending updates → DGs: {dgs_to_update if dgs_to_update else 'None'}, "
                f"Template Stacks: {tss_to_update if tss_to_update else 'None'}"
            )
            for dg in dgs_to_update:
                try:
                    set_dg_cie(pano_obj, dg, args.cie)
                except Exception as e:
                    logger.exception(f"Failed to set DG '{dg}' CIE")
                    logger.exception(e)
            for ts in tss_to_update:
                try:
                    set_ts_cie(pano_obj, ts, args.cie)
                except Exception as e:
                    logger.exception(f"Failed to set Template Stack '{ts}' CIE")
                    logger.exception(e)
            logger.info("Changes placed in Panorama candidate configuration. Review and commit via the Panorama GUI.")


if __name__ == '__main__':
    main()
