#!/usr/bin/env python

################################################################################
# script:   PanCore
# by:       Christopher Fettig, Palo Alto Networks
#
# © 2020 Palo Alto Networks, Inc.  All rights reserved.
#  Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc.
#  https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf
#
################################################################################

"""
Changelog
2023-01-25 - Corrected typo 'config['localFile']['key'] should have been 'panKey' when updating JSON for local config storage.
2023-01-04 - Adjusted log output, made timezone more consistent & included hour in filename exported in getTSF()
2023-02-27 - Typos in memo/comment fields of configStart()
2023-12-26 - Incorporate Strata Cloud Manager auth token generation
2023-12-29 - Update configStart() to standardize keys and changed to programmatic for (_varName in varList exec()) method of building variables.
2024-01-04 - Eliminated regression bug in configStart where passwords were not being decoded when retrieved from environment variables
2024-01-29 - Address unboundLocalError where SCMCreds not defined (User picked "N" for connecting to SCM but 'if scm' test encountered bug/error)

Goals
1.  Re-implement "headless" support. Vestigial elements from prior 'headless mode' exist in this code base but the
    function was de-implemented as part of support for multi option config allowing database or environment variable
    storage of credentials.

"""

#Import custom library modules
from pancore import panExcelStyles

#Import stock/public library modules
import os, platform, sys  # To Ping prior to connecting (Error avoidance) and for sys.exit() access
import requests # For interacting with SCM (Strata Cloud Manager) API
import lxml.etree as ET  # So we can handle XML and apply the cool .xpath and .xlst modules
import xml.etree.ElementTree as ET2  # Because pan-os-python doesn't use LXML with all the cool features
import xlsxwriter  # Because CSV's lack formatting capabilities.
import re, panos, datetime, time, json, getpass
from panos import ha, panorama, base, firewall
import logging, logging.handlers
# Handler to encode passwords. NOT ENCRYPTION. ONLY OBFUSCATION.
import zlib
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
logger = logging.getLogger(__name__)

def encodePass(data: bytes) -> bytes:
    return b64e(zlib.compress(data, 9))

def decodePass(obscured: bytes) -> bytes:
    return zlib.decompress(b64d(obscured))

def scmCredPrompt():
    #'scmAuth': 'https://auth.apps.paloaltonetworks.com/oauth2/access_token',
    #'scmBase': 'https://api.sase.paloaltonetworks.com/sse/config/v1',
    scmCreds = {'scmUser': input("Please paste your assigned username for SCM (Strata Cloud Manager):"),
                'scmPass': input("Please paste your API key assigned by SCM (Strata Cloud Manager):"),
                'scmTSG': input("Please paste the TSG ID of the SCM (Strata Cloud Manager) environment:")}
    responses = ['yes', 'y', 'no', 'n']
    prompt = "Is the above information correct?\n\r     (Enter yes (y) or no (n):"
    while True:
        for key in scmCreds.keys():
            print("{:<15} {:<25}".format(key + ":", scmCreds[key]))
        userInput = input(prompt).lower()
        if userInput not in responses:
            pass
        else:
            if userInput in ['yes', 'y']:
                break
            else:
                scmCreds = scmCredPrompt()
                break
    return scmCreds

def getSCM_Token(scmUser, scmPass, scmTSG):
    global scmToken, tokenExpiryTime
    # Store token & expiry time in pancore's memory space to support
    # multi-threading efforts in calling scripts.
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Accept': 'application/json'}
    data = {
        'grant_type': 'client_credentials',
        'scope': f'profile tsg_id:{scmTSG} email'}
    response = requests.post(url=scmAuthURL, headers=headers, data=data, auth=(scmUser,scmPass))
    if response.status_code == 200:
        logging.info("Refreshed oAuth token.")
        scmToken = response.json()['access_token']
        headers = {'Content-Type': 'application/json',
                   'Authorization': f'Bearer {scmToken}'}
        tokenExpiryTime = time.time() + (60 * 13)
        return headers, tokenExpiryTime
    else:
        logging.error("Did not receive proper SCM token.")
        tokenExpiryTime = time.time()
        return response, tokenExpiryTime #Return HTTP response and current time as 'expiry' time to force re-key.

def panoCredPrompt():
    panCreds = {}
    panCreds['panAddress'] = input("Please enter the FQDN or IP address of the Panorama you wish to connect to: ")
    responses = ['yes', 'y', 'no', 'n']
    prompt = "Do you have an API key to provide? If not we can store a username and password.\n\r" \
             "          (Enter yes/y or no/n):"
    while True:
        userInput = input(prompt).lower()
        if userInput not in responses:
            pass
        else:
            if userInput in ['yes', 'y']:
                panCreds['panAuthType'] = "key"
                panCreds['panKey'] = input("Please paste the API key now: ")
                break
            else:
                panCreds['panAuthType'] = "password"
                panCreds['panUser'] = input("Please enter the username we should use to connect to Panorama: ")
                panCreds['panPass'] = getpass.getpass(f"Please enter the password for {panCreds['panUser']}: ")
                break
    while True:
        print("\n\r***\n\r")
        for key in panCreds.keys():
            if key == 'panPass':
                print("{:<15} {:<25}".format(key + ":", "***HIDDEN***"))
            else:
                print("{:<15} {:<25}".format(key + ":", panCreds[key]))
        userInput = input("Is the above correct? (yes or y to continue)")
        if userInput not in responses:
            pass
        else:
            if userInput in ['yes', 'y']:
                break
            else:
                panCreds = panoCredPrompt()
                break
    return panCreds


def dbCredPrompt():
    dbCreds = {'dbHost': input("Please enter the SQL server address: "),
               'dbUser': input("Please enter the username for the SQL server: "),
               'dbPass': input("Please enter the password for the SQL server: ")}
    responses = ['yes', 'y', 'no', 'n']
    prompt = "Do you require read write access to the active panorama?\n" \
             "(Or will read only to the passive panorama suffice?)\n" \
             "Enter 'yes' or 'y' to interact with the ACTIVE panorama or 'no' / 'n' to interact with the PASSIVE panorama:"
    while True:
        userInput = input(prompt)
        if userInput not in responses:
            pass
        else:
            if userInput.lower() in ['yes', 'y']:
                dbCreds['haMember'] = 'active'
            else:
                dbCreds['haMember'] = 'passive'
            break
    while True:
        print("\n\r***\n\r")
        for key in dbCreds.keys():
            print("{:<15} {:<25}".format(key + ":", dbCreds[key]))
        userInput = input("Is the above correct? (yes or y to continue)")
        if userInput not in responses:
            pass
        else:
            if userInput in ['yes', 'y']:
                break
            else:
                dbCreds = dbCredPrompt()
                break
    return dbCreds


def configStart(headless=False, configStorage='panCoreConfig.json'):
    """
    Get credentials for Panorama and/or Strata Cloud Manager. Default config storage is a JSON file.
    Alternatively, a database or environment variables may be used, though this introduces additional dependencies.
    """
    if not bool(logging.getLogger()):
        startLogging('loggingNotStarted.log')
        logger.warning('Calling script ran panCore.configStart() before panCore.startLogging. Initiating logging with default log file name.')
    if os.path.exists(configStorage):
        logger.info("Getting config/credentials from file.")
        try:
            config = json.load((open(configStorage)))
        except Exception as e:
            logger.error(f"Exception: {e} was encountered when trying to open config file.")
            if headless == True:
                logger.critical('Unable to read config in silent mode. Unable to prompt for user input. EXITING')
                sys.exit('Unable to read credentials in silent mode. Unable to prompt for user input. EXITING')
    else:
        logger.info("Config INI file doesn't exist. Creating empty construct and prompting user for input.")
        config = {
            "method": "localFile",
            "scmConfURL": "https://api.sase.paloaltonetworks.com/sse/config/v1",
            "scmAuthURL": "https://auth.apps.paloaltonetworks.com/oauth2/access_token",
            "localFile": {
                "panAddress": "null",
                "panUser": "null",
                "panPass": "null",
                "panKey": "null",
                "panAuthType": "null",
                "scmUser": "null",
                "scmPass": "null",
                "scmTSG": "null"
            },
            "panScan": {
                "MessageToUser": "set haMember to 'active' if scripts calling this config file will need to edit config elements.",
                "haMember": "passive",
                "dbHost": "null",
                "dbUser": "null",
                "dbPass": "null"},
            "environmentVariables": {
                "MessageToUser": "THESE ARE NOT TO STORE LOGON INFO. THESE ARE TO STORE WHERE TO GET THAT LOGON INFO",
                "panAddress": "panAddress",  # Find the Panorama address in the 'panAddress' environment variable
                "panKey": "panKey",  # find the Panorama API key in the 'panKey' environment variable
                "panUser": "panUser",
                "panPass": "panPass",
                "panAuthType": "panAuthType",  # whether to use Username/Password or API key to authenticate w/ Panorama
                "scmUser": "scmUser",
                "scmPass": "scmPass",
                "scmTSG": "scmTSG"}
        }
        print("There are three options for storing how to access Panorama. Locally in an JSON file is the simplest, "
              "but also the least secure. Environment variables are next simplest, but may not scale well. If your "
              "environment has a panscan database that this system can access those credentials may be retrieved as a "
              "third option."
              "")
        responses = ['1', '2', '3']
        prompt = """
        Please enter a number to choose which config method to employ:
        1 for local file (Supports both Panorama & SCM)
        2 for environment variable (Supports both Panorama & SCM)
        3 for retrieving a Panorama API key from panscan's database (No SCM support)
        """
        while True:
            userInput = input(prompt)
            if userInput not in responses:
                pass
            else:
                if userInput == '3':
                    logger.info("  User chose to retrieve credentials from panscan database.")
                    config['method'] = 'panScan'
                    logger.info("getting information to connect to panscan database")
                    dbCreds = dbCredPrompt()
                    config['panScan']['dbHost'] = dbCreds['dbHost']
                    config['panScan']['dbUser'] = dbCreds['dbUser']
                    config['panScan']['dbPass'] = (encodePass(bytes(dbCreds['dbPass'], 'ascii'))).decode('ascii')
                    config['panScan']['haMember'] = dbCreds['haMember']
                    break
                elif userInput == '2':
                    config['method'] = 'variables'
                    logger.info("  User chose to store credentials in environment variables")
                    innerResponses = ['yes', 'y', 'no', 'n']
                    while True:
                        innerInput = input("Do you wish to connect to Panorama? (yes or y) / (no or n):").lower()
                        if innerInput not in innerResponses:
                            pass
                        else:
                            if innerInput in ['yes', 'y']:
                                panCreds = panoCredPrompt()
                                break
                            else:
                                break
                    while True:
                        innerInput = input(
                            "Do you wish to connect to SCM (Strata Cloud Manager)? (yes or y) / (no or n):").lower()
                        if innerInput not in innerResponses:
                            pass
                        else:
                            if innerInput in ['yes', 'y']:
                                scmCreds = scmCredPrompt()
                                break
                            else:
                                break
                    if (platform.system()).lower() == "windows":
                        scriptText = f"echo off\n"
                        scriptText += f"echo Setting environment variables for future PanCore use.\n"
                        scriptText += f"echo NOTE: If you cannot use the default environment variable names change them\n"
                        scriptText += f"echo       here AND in the {configStorage} INI file. We can use any environment\n"
                        scriptText += f"echo       variable name, but must write and read from the same variable.\necho.\n"
                        if 'panCreds' in locals():
                            scriptText += "echo Setting Panorama connectivity:\n"
                            scriptText += f"setx {config['environmentVariables']['panAddress']} {panCreds['panAddress']}\necho.\n"
                            scriptText += f"setx {config['environmentVariables']['panAuthType']} {panCreds['panAuthType']}\necho.\n"
                            if panCreds['panAuthType'] == 'key':
                                scriptText += f"setx {config['environmentVariables']['panKey']} {panCreds['panKey']}\n"
                            else:
                                scriptText += f"setx {config['environmentVariables']['panUser']} {panCreds['panUser']}\n"
                                scriptText += f"setx {config['environmentVariables']['panPass']} '{(encodePass(bytes(panCreds['panPass'], 'ascii'))).decode('ascii')}\n"
                        if 'scmCreds' in locals():
                            scriptText += "echo Setting SCM connectivity: \n"
                            scriptText += f"setx {config['environmentVariables']['scmUser']} {scmCreds['scmUser']}\n"
                            scriptText += f"setx {config['environmentVariables']['scmPass']} {(encodePass(bytes(scmCreds['scmPass'], 'ascii'))).decode('ascii')}\n"
                            scriptText += f"setx {config['environmentVariables']['scmTSG']} {scmCreds['scmTSG']}\n"
                        scriptText += f"echo.\n"
                        scriptText += f"echo NOTE: setx configures environment variables for FUTURE shells. Exit and re-open\n"
                        scriptText += f"echo       this shell for the changes to take effect\n"
                        scriptText += f"echo on\npause"
                        with open('setVariables.bat', 'w') as f:
                            f.write(scriptText)
                    elif (platform.system()).lower() == "linux":
                        import stat
                        scriptText = f"# Run this shell script to append the below to your bash profile's environment variables\n" \
                                     f"# for future panCore use.\n" \
                                     f"# If you want to use different environment variable keys be sure to change this\n" \
                                     f"# script AND the {configStorage} config JSON file. Any environment variable may be used,\n" \
                                     f"# but we need to be consistent with storing and retrieving from the same place.\n"
                        if panCreds:
                            scriptText += f"echo 'export panAddress={panCreds['panAddress']}' >> ~/.bash_profile\n" \
                                          f"echo 'export panAuthType={panCreds['panAuthType']}' >> ~/.bash_profile\n"
                            if panCreds['panAuthType'] == 'key':
                                scriptText += f"echo 'export panKey={panCreds['panKey']}' >> ~/.bash_profile\n"
                            else:
                                scriptText += f"echo 'export panUser={panCreds['panUser']}' >> ~/.bash_profile\n"
                                scriptText += f"echo 'export panPass={(encodePass(bytes(panCreds['panPass'], 'ascii'))).decode('ascii')}' >> ~/.bash_profile\n"
                        if scmCreds:
                            scriptText += f"echo 'export scmUser={scmCreds['scmUser']}' >> ~/.bash_profile\n"
                            scriptText += f"echo 'export scmPass={(encodePass(bytes(scmCreds['scmPass'], 'ascii'))).decode('ascii')}' >> ~/.bash_profile\n"
                            scriptText += f"echo 'export scmTSG={scmCreds['scmTSG']}' >> ~/.bash_profile\n"
                        scriptText += f"# Remember ~/.bash_profile is read on logon." \
                                      f"Log off and back in after running this for it to take effect."
                        with open('setVariables.sh', 'w') as f:
                            f.write(scriptText)
                        st = os.stat('setVariables.sh')
                        os.chmod('setVariables.sh', st.st_mode | stat.S_IEXEC)
                    break
                elif userInput == '1':
                    config['method'] = 'localFile'
                    logger.info("  User chose to store credentials in config file")
                    innerResponses = ['yes', 'y', 'no', 'n']
                    while True:
                        innerInput = input("Do you wish to connect to Panorama? (yes or y) / (no or n):").lower()
                        if innerInput not in innerResponses:
                            pass
                        else:
                            if innerInput in ['yes', 'y']:
                                panCreds = panoCredPrompt()
                                break
                            else:
                                break
                    while True:
                        innerInput = input(
                            "Do you wish to connect to SCM (Strata Cloud Manager)? (yes or y) / (no or n):").lower()
                        if innerInput not in innerResponses:
                            pass
                        else:
                            if innerInput in ['yes', 'y']:
                                scmCreds = scmCredPrompt()
                                break
                            else:
                                break
                    if 'panCreds' in locals():
                        config['localFile']['panAddress'] = panCreds['panAddress']
                        config['localFile']['panAuthType'] = panCreds['panAuthType']
                        if panCreds['panAuthType'] == 'key':
                            config['localFile']['panKey'] = panCreds['panKey']
                        else:
                            config['localFile']['panUser'] = panCreds['panUser']
                            config['localFile']['panPass'] = (encodePass(bytes(panCreds['panPass'], 'ascii'))).decode(
                                'ascii')
                    if 'scmCreds' in locals():
                        config['localFile']['scmUser'] = scmCreds['scmUser']
                        config['localFile']['scmPass'] = (encodePass(bytes(scmCreds['scmPass'], 'ascii'))).decode(
                            'ascii')
                        config['localFile']['scmTSG'] = scmCreds['scmTSG']
                    break
        with open(configStorage, 'w') as configFile:
            configFile.write(json.dumps(config, indent=4))
    # Config has either been read from config file or generated and written to config file.
    # Time to wrap up the config start function and return an authentication mechanism
    global panAddress, panUser, panPass, panKey, scmUser, scmPass, scmTSG, scmAuthURL, scmConfURL
    scmAuthURL = config['scmAuthURL']
    scmConfURL = config['scmConfURL']
    if config['method'] == 'localFile':
        logger.info("Got credentials, stored in local file")
        panAddress = config['localFile']['panAddress']
        if config['localFile']['panAuthType'] == 'key':
            panKey = config['localFile']['panKey']
        else:
            panUser = config['localFile']['panUser']
            panPass = (decodePass(config['localFile']['panPass'])).decode()
        if config['localFile']['scmUser'] != "null":
            scmUser = config['localFile']['scmUser']
            scmPass = (decodePass(config['localFile']['scmPass']))
            scmTSG = config['localFile']['scmTSG']
    elif config['method'] == 'panScan':
        logger.info("Getting config/credentials from panscan database")
        # import mysql.connector as database
        import mysql.connector
        connection = mysql.connector.connect(
            user=config['panScan']['dbUser'],
            password=(decodePass(config['panScan']['dbPass'])).decode(),
            host=config['panScan']['dbHost'],
            database='panscan')
        cursor = connection.cursor()
        sqlQuery = f"SELECT name, ip, api_key from panorama where ha_primary='{config['panScan']['haMember'].lower()}'"
        try:
            cursor.execute(sqlQuery)
            resp = cursor.fetchone()
            panAddress = resp[1]
            panKey = resp[2]
        except Exception as e:
            logger.error(f"Error encountered while accessing PanScan database: {e}")
            sys.exit("Quitting due to above SQL error preventing retrieval of credentials.")
    elif config['method'] == 'variables':
        logger.info("Getting config/credentials from environment variables:")
        varList = ['panAddress', 'panKey', 'panUser', 'panPass', 'scmUser', 'scmPass', 'scmTSG']
        for _varName in varList:
            # Variables will be created as "None" type if environment variable doesn't exist.
            # Delete them if that occurs to avoid breaking other tests (e.g. connect w/ API key
            # if username doesn't exist.)
            if _varName.endswith('Pass'):
                exec(f"global panPass, scmPass\n"
                     f"temp = os.environ.get('{config['environmentVariables'][_varName]}')\n"
                     f"if temp is not None:\n"
                     f"\t{_varName} = str(decodePass(temp), encoding='utf-8')")
            else:
                exec(f"global panAddress, panUser, panKey, scmUser, scmTSG\n"
                     f"{_varName} = os.environ.get('{config['environmentVariables'][_varName]}')\n"
                     f"if {_varName} == None:\n"
                     f"\tdel {_varName}\n"
                     f"else:\n"
                     f"\tlogger.info('\t{_varName} retrieved.')")
        logger.info('Done getting environmentVariables.')
        #print(panAddress)
        #if not panAddress and not scmUser:
        #    logger.critical(f"Failed to retrieve Panorama address or SCM User from environment variables. Exiting\n"
        #                    f"If you've just built the setVariables.bat file go run it to create the necessary environment variables\n"
        #                    f"and then re-run this script. (Re-launch your IDE if necessary as IDE environment is generated at runtime.).")


def startLogging(logFileName: str) -> logging.Logger:
    """
    Initialize the root logger and create the main log file handler.

    Args:
        logFileName: Path to the log file

    Returns:
        logging.Logger: Root logger instance
    """
    # Configure the root logger
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    # Create and configure handlers
    fileFormat = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    consoleFormat = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fileHandler = logging.handlers.TimedRotatingFileHandler(filename=f"{logFileName}", when='midnight', backupCount=5, encoding='utf-8')
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(fileFormat)
    screenLogger = logging.StreamHandler()
    screenLogger.setLevel(logging.INFO)
    screenLogger.setFormatter(consoleFormat)
    # Add handlers to root logger
    logger.addHandler(fileHandler)
    logger.addHandler(screenLogger)
    return logger

def listLoggers() -> None:
    """
    Get all currently instantiated loggers and their levels.

    Returns:
        dict: Dictionary of logger names and their effective levels
    """
    loggers = {}
    # Get the manager that holds all logger instances
    manager = logging.Logger.manager
    # Iterate through all loggers
    for logger_name in manager.loggerDict:
        logger = logging.getLogger(logger_name)
        loggers[logger_name] = {
            'level': logging.getLevelName(logger.getEffectiveLevel()),
            'handlers': [type(h).__name__ for h in logger.handlers],
            'propagate': logger.propagate
        }
    print("\nCurrent Loggers:")
    print("-" * 80)
    print(f"{'Logger Name':<30} {'Level':<10} {'Handlers':<20} {'Propagate'}")
    print("-" * 80)
    for name, info in loggers.items():
        handlers = ','.join(info['handlers']) if info['handlers'] else 'None'
        print(f"{name:<30} {info['level']:<10} {handlers:<20} {info['propagate']}")


def stringifyLXML(lxmlBlock):
    return ET.tostring(lxmlBlock)

def exportLXML(lxml, filename):
    output = ET.ElementTree(lxml)
    output.write(filename, pretty_print=True, encoding='utf-8', xml_declaration=True)

def xmlToLXML(xmldata):
    # pan-os-python utilizes 'xml.etree.ElementTree' which lacks the ability to access XML xpath nodes
    # and other search/find features found in lxml imported above. This function converts to the lxml object role
    return ET.fromstring(ET2.tostring(xmldata))


def expandPanObject(panObject):
    for childType in panObject.CHILDTYPES:
        try:
            logger.info(f"attempting to refresh {childType} on {panObject}")
            parent, child = childType.split('.')
            parentModule = getattr(panos, parent)
            childModule = getattr(parentModule, child)
            childModule.refreshall(panObject)
        except Exception as e:
            logger.warning(f"failed to refresh {childType}: {e}")



def pingit(host):
    # Determine if remote firewall is accessible before attempting to retrieve its inventory
    if platform.system() == "Windows":
        response = os.system("ping -n 1 " + host)
    else:
        response = os.system("ping -c 1 " + host)
    if response == 0:
        return True
    else:
        return False


def uniquelabel(candidatelabel, data, counter=int(2)):
    # Since label already exists in dictionary append a suffix to make a unique label
    # We only call unique label if the label already exists, so start with 2 and add from there.
    unique = False
    while unique is False:
        newlabel = candidatelabel + "_" + str(counter)
        if newlabel in data:
            counter += 1
        else:
            unique = 'true'
    return newlabel


def identifyEmptyXMLText(stringData):
    regexPattern = re.compile("\n *")
    if regexPattern.fullmatch(stringData):
        return True
    else:
        return False


def iterator(element, item, label="", deleteEntryTag=True, ignoreTemplateKeys=False):
    global headers, devData
    # Iterate through XML sub-elements and identify a unique key name into which the
    # respective value can be stored in the devData dict's "item" dict
    # Will likely be redundant in future PAN-OS JSON API capability
    if ((element.tag == 'entry') and (deleteEntryTag)):
        temp = element.get('name')
        if not temp:
            try:
                temp = element.find('name').text
            except:
                try:
                    temp = element.find('description').text
                except:
                    temp = '.'
    else:
        temp = element.tag
    if label != "":
        newlabel = label + "." + temp
    else:
        newlabel = temp
    if newlabel in devData[item]:
        newlabel = uniquelabel(newlabel, devData[item])
    if element.text:
        if identifyEmptyXMLText(element.text) == False:
            devData[item][newlabel] = element.text
        if newlabel not in headers:
            headers.extend([newlabel])
            # print(f"... panCore is adding {newlabel} to headers list")
    # Check if element has XML attributes other than the "name" attribute incorporated into label earlier.
    # If so parse each attribute and incorporate it into the dictionary.
    if ((len(element.attrib.keys()) > 0) and (element.attrib.keys() != ['name'])):
        for key in element.attrib.keys():
            if ignoreTemplateKeys and key.lower() in ['ptpl', 'src']:
                continue
            else:
                sublabel = newlabel + "@" + key
                # print(f"... panCore is adding {sublabel} to headers list")
                headers.extend([sublabel])
                devData[item][sublabel] = element.get(key)
    if len(element):
        for subelement in element.getchildren():
            iterator(subelement, item, newlabel, deleteEntryTag, ignoreTemplateKeys)


def buildPano_obj(panAddress, panUser='optional', panPass='optional', panKey='optional'):
    if not bool(logging.getLogger()):
        startLogging('loggingNotStarted.log')
        logger.warning('Calling script ran panCore.buildPano_obj() before panCore.startLogging. Initiating logging with default log file name.')
    #######################################################################################
    ################## Fetch Firewall Inventory from Panorama #############################
    #######################################################################################
    if not pingit(panAddress):
        logger.error('\t******** Unable to Ping Panorama, Aborting further processes')
        return ("error")
    logger.info('\t******** Successfully pinged Panorama. Creating PAN-OS-Python objects.')
    # Theoretically there's no scenario where we would have both an API key and a username, but if both are present
    # prefer API key over username by attempting that first.
    if panKey != 'optional':
        pano_obj = panos.panorama.Panorama(hostname=panAddress, api_key=panKey)
    elif panUser != 'optional':
        pano_obj = panos.panorama.Panorama(panAddress, panUser, panPass)
    else:
        logger.error('Error. No API key or username given.')
        sys.exit("No API or username provided. Exiting.")
    pano_obj.refresh_devices(add=True, include_device_groups=True, expand_vsys=False)
    panos.panorama.Template.refreshall(pano_obj)
    panos.panorama.TemplateStack.refreshall(pano_obj)
    deviceGroups = pano_obj.findall(panos.panorama.DeviceGroup)
    firewalls = pano_obj.findall(panos.firewall.Firewall)
    templates = pano_obj.findall(panos.panorama.Template)
    tStacks = pano_obj.findall(panos.panorama.TemplateStack)
    return (pano_obj, deviceGroups, firewalls, templates, tStacks)


def buildFirewall_obj(panAddress, panUser='optional', panPass='optional', panKey='optional'):
    if not bool(logging.getLogger()):
        startLogging('loggingNotStarted.log')
        logger.warning('Calling script ran panCore.buildFirewall_obj() before panCore.startLogging. Initiating logging with default log file name.')
    #######################################################################################
    ############## Build an individual firewall object ####################################
    ## Useful for commands which cannot be relayed through Panorama (SCP/TFTP exports) ####
    if not pingit(panAddress):
        logger.error('\n****\nUnable to Ping Panorama, Aborting further processes\n****\n')
        exit()
    logger.info('\n****\nSuccessfully pinged firewall {0}. Creating PAN-OS-Python object.'.format(panAddress))
    if panKey != 'optional':
        fwDirect_obj = panos.firewall.Firewall(hostname=panAddress, api_key=panKey)
    elif panUser != 'optional':
        fwDirect_obj = panos.firewall.Firewall(panAddress, panUser, panPass)


def getTSF(pan_obj, prefix=''):
    # using 'pan_obj' nomenclature as this function should be viable for fw_ or pano_ objects.
    sysInfo = pan_obj.show_system_info()
    hostname = sysInfo['system']['hostname']
    startTime = datetime.datetime.now(datetime.timezone.utc)
    logging.info(f"Requesting tech support job for {hostname} at {startTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    resp = xmlToLXML(pan_obj.xapi.export(category='tech-support'))
    job = resp.find('.//job').text
    time.sleep(30)
    resp = xmlToLXML(pan_obj.xapi.export(category='tech-support', extra_qs=f'action=status&job-id={job}'))
    jobState = resp.find('.//status').text
    waitCount = 1
    jobTime = datetime.datetime.now(datetime.timezone.utc)
    logging.info("    Tech support job for {0} scheduled in job {1} at {2}".format(hostname, job, jobTime.strftime("%Y/%m/%d, %H:%M:%S - %Z")))
    time.sleep(600)
    while jobState == 'ACT':
        resp = xmlToLXML(pan_obj.xapi.export(category='tech-support', extra_qs=f'action=status&job-id={job}'))
        jobState = resp.find('.//status').text
        jobProgress = resp.find('.//progress').text
        logging.info(f"    > Job {job} for {hostname} not done after wait #{waitCount}. Current Progress: {jobProgress} Waiting another 3 minutes.")
        time.sleep(180)
        waitCount += 1
    finTime = datetime.datetime.now(datetime.timezone.utc)
    logging.info(f"Job {job} for {hostname} is no longer active at {finTime.strftime('%Y/%m/%d, %H:%M:%S - %Z')}")
    if jobState != "FIN":
        logging.error("Job state did not return 'FIN' Something to figure out. Writing raw XML response to file. jobState returned: {0}".format(jobState))
        with open(f"tsGeneratorError_{hostname}.XML", 'wb') as fd:
            fd.write(ET.tostring(resp, pretty_print=True,encoding='utf-8',xml_declaration=True))
            logging.error(f"Wrote tsGeneratorError_{hostname}.XML. Please consult error file for exact problem that prevented TSF generation.")
    else:
        pan_obj.xapi.export(category='tech-support', extra_qs=f'action=get&job-id={job}')
        with open(f"{prefix}tsDump_{hostname}_{finTime.strftime('%Y-%m-%d-%H_%Z')}.tgz", "wb") as fd:
            fd.write(pan_obj.xapi.export_result['content'])
            logging.info(f"Wrote TS file, finished with {hostname}.")