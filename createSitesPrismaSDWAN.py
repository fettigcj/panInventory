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
2024-07-25: Start test file.



"""

from pancore import panCore, panExcelStyles
import panGroupsAndProfiles
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse, re, time, panos, requests, json, threading, copy
from threading import Thread

def getKey():
    global headers, tokenExpiryTime
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    return headers, tokenExpiryTime

def getThingListFromSCM(thingType, folder, headers, limit=200, offset=0):
    params = {'folder': folder,
              'limit': limit,
              'offset': offset}
    return requests.request("GET", f"{panCore.scmConfURL}/{thingType}", headers=headers, data={}, params=params)

def getThingFromSCM_byID(thingType, id, headers):
    return requests.request("GET", f"{panCore.scmConfURL}/{thingType}/{id}", headers=headers, data={})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="CopyToSCM",
        description="Copy Panorama config to Strata Cloud Manager.")
        #epilog="Text")
    parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
    parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='SCM-Migration.log')
    parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="_scmOnlypanCoreConfig.json")
    parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='SCM-NewSites.xlsx')
    parser.add_argument('-S', '--noShared', help='Disable importing Shared objects', default=False, action='store_true')
    parser.add_argument('-F', '--sharedFolder', help='Destination folder for Panorama "shared" scope objects', default='All')
    parser.add_argument('-T', '--limitThreads', help="Limit number of threads to prevent overwhelming API destination", default=100)
    parser.add_argument('-W', '--Wait', help="Seconds to wait before starting next batch of threads in multi-threaded operations.", default=2)
    # NOTE: SCM uses folder "All" to describe config scope of "Global" folder.
    # to write to "Global" as shown in GUI use "All"
    # to write to "Prisma Access" config scope use "Shared"
    parser.add_argument('-d', '--deviceGroups', help='CSV of device group:folder pairings', default="GlobalProtect_Azure:Shared,GP_Americas:Shared")
    parser.add_argument('-z', '--zoneMap', help='Replace zone names for SCM compatibility', default='TRUST:trust,Trust:trust,INTERNET:untrust,GLOBALPROTECT:trust')
    args = parser.parse_known_args()

    panCore.startLogging(args[0].logfile)
    panCore.configStart(headless=args[0].headless, configStorage=args[0].conffile)
    """
    if hasattr(panCore, 'panUser') and panCore.panUser is not None:
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
    elif hasattr(panCore, 'panKey') and panCore.panKey is not None:
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
    else:
        panCore.logging.critical("Found neither username/password nor API key. Exiting.")
        sys.exit()
    """

    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    panCore.scmConfURL = "https://api.sase.paloaltonetworks.com/sdwan/v2.5/api/appdefs/"
    appDefs = requests.request("GET", panCore.scmConfURL, headers=headers, data={})



    