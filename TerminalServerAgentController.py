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
2024-01-19 - Started the thing.


Goals:
Make the thing.
"""

import panos, argparse,datetime

parser = argparse.ArgumentParser(
    prog="TerminalServerAgentController",
    description="Dynamically add and remove TS Agents from target firewall configuration")

parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='panInventory.log')
parser.add_argument('-f', '--firewall', help="IP address of firewall to connect to.", default='172.31.255.254')
parser.add_argument('-u', '--username', help="username to connect with.", default='tsaController')
parser.add_argument('-p', '--password', help="password to connect with.", default='Change!This@Immediately1')

args = parser.parse_known_args()

todayDate = datetime.date.today()


