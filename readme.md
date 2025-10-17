# Palo Alto Networks Inventory, Reporting, and Control Tools

## Global conventions
 argparse is utilized to provide basic help and CLI switches. Access help for guidance of CLI options by invoking the python file with the --help argument.

## UpgradeFirewalls.py
Created to facilitate the mass upgrades required to avoid 
device certificate expiration issues when PAN-OS device certs expired at the end of 2023.

The script can generate upgrade readiness reports as well as upgrade firewalls. Readiness report will detail 
serial number, hostname, ha State, upgradeable status, and a 'details' column showing rationale for the 'upgradeable' column as well as starting and ending version columns.  

Examples below, [Workflow diagram](https://lucid.app/publicSegments/view/264469e4-0d7f-4d20-8403-c968b8e861f5/image.png)

### EXTREMELY dangerous. Use with CAUTION.

Used incorrectly this script WILL create network outages as firewalls WILL be rebooted as part of the upgrade process.

### Help output:
options:  
  -h, --help            show this help message and exit  
  -l, --headless        Operate in headless mode, without user input (Will disable panCore's ability to prompt for
                        credentials)  
  -L LOGFILE, --logfile LOGFILE Log file to store log output to.  
  -c CONFFILE, --conffile CONFFILE Specify the config file to read options from. Default 'panCoreConfig.json'.  
  -w WORKBOOKNAME, --workbookname WORKBOOKNAME Name of Excel workbook to be generated  
  -V TARGETVERSION, --targetVersion TARGETVERSION What version to upgrade to  
  -A, --upgradeActive   Suspend & upgrade active IF passive already upgraded.  
  -U, --enableUpgrade   Enable upgrading of firewalls. Otherwise report only  
  -S, --upgradeStandalone Upgrade & Reboot non-HA firewalls. WILL CAUSE OUTAGE DURING REBOOT.  
  -E, --mailEnable      Enable SMTP e-mail reporting.  
  -F MAILFROM, --mailFrom MAILFROM SMTP source address  
  -T MAILTO, --mailTo MAILTO SMTP destination address  
  -M MAILSERVER, --Mailserver MAILSERVER SMTP server address  
  -f FILENAME, --filename FILENAME file containing line break separated serial number list to limit scope.  

### Examples:

#### Default behaviors:
* Utilize default config file (panCoreConfig.json)
* Connect to Panorama and iterate through all connected firewalls.
* Output report to default Excel workbook (upgradeFirewalls.xlsx)
* do NOT upgrade 'active' HA members
* do NOT upgrade stand alone (active-active clusters are treated as stand-alone)
* do NOT upgrade (Report only)

py .\upgradeFirewalls.py
##### Upgrade 'passive' firewalls connected to Panorama specified in 'prodPano.json'

py .\upgradeFirewalls.py -c 'prodPano.json' -U

##### Upgrade active AND passive firewalls, e-mail per-FW log details 
(Must be run at least twice)

py .\upgradeFirewalls.py -UAE -F 'sourceAddress' -T 'recipientAddress' -M 'sendingServer' 

1. Upgrades any passive firewalls encountered.
2. Checks session count on active (FW01) node
3. Suspends (for 5 seconds) active (FW01) node _*if passive FW PAN-OS version higher*_
NOTE: During initial run FW01 would be skipped as FW02 PAN-OS version was 'lesser or equal' - hence requiring 2nd pass 
4. If newly-active (FW02) node session count not within 30% of prior-active (FW01) node suspends FW02 (restoring FW01 to active state), logs error and skips pair
5. Upgrades newly passive node

#### Upgrade Active, Passive, AND standalone firewalls connected to panorama specified in "pano2.json whose serial number is in "upgradelist.txt"
  
py .\upgradeFirewalls.py -c 'pano2.json' -UAS -f 'upgradelist.txt'
