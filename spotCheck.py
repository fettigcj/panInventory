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
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='spotCheck.log')
parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='spotCheck.xlsx')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
args = parser.parse_known_args()

