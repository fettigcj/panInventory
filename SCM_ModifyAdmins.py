#!/usr/bin/env python

################################################################################
# script:	PanInventory.py
# by:		Christopher Fettig, Palo Alto Networks
#
################################################################################
"""
Changelog

2024-03-15 Begin file.

"""


from pancore import panCore, panExcelStyles
import panGroupsAndProfiles
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse, re, time, panos, requests, json, threading, copy


def postThing(submission):
    devData = submission['devData']
    thingName = submission['thingName']
    thingPath = submission['thingPath']
    headers = submission['headers']
    endpoint = submission['endpoint']
    params = submission['params']
    headers['Authorization'] = f"Bearer {panCore.scmToken}"
    panCore.postThingResults[endpoint]['objectDetails'][thingPath] = {}
    if hasattr(panCore, 'tokenExpiryTime'):
        #currentTime = time.localtime(time.time())
        #expiryTime = time.localtime(panCore.tokenExpiryTime)
        #print(f"Current time        : {currentTime.tm_year}/{currentTime.tm_mon}/{currentTime.tm_mday} {currentTime.tm_hour}:{currentTime.tm_min}.{currentTime.tm_sec}")
        #print(f"Token Expires At    : {expiryTime.tm_year}/{expiryTime.tm_mon}/{expiryTime.tm_mday} {expiryTime.tm_hour}:{expiryTime.tm_min}.{expiryTime.tm_sec}")
        if time.time() >= panCore.tokenExpiryTime:
            if not hasattr(panCore, 'refreshingToken'):
                # Minimize number of threads simultaneously refreshing scmToken
                panCore.refreshingToken = True
                panCore.logging.error(f"oAuth token expired. Refreshing")
                resp, nullOut = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
                del panCore.refreshingToken
            else:
                i = 1
                while panCore.refreshingToken:
                    # Wait (For up to 5 seconds) for another thread to finish refreshing panCore.scmToken
                    if i == 5:
                        break
                    time.sleep(1)
                    i += 1
            if time.time() >= panCore.tokenExpiryTime:
                panCore.logging.error(f"\t\t\tReceived expired oAuth token. Investigate below HTTP response:\n"
                                      f"\t\t\t{resp}")
            else:
                headers['Authorization'] = f"Bearer {panCore.scmToken}"
    response = requests.request("POST", panCore.scmConfURL + endpoint, headers=headers, data=json.dumps(devData), params=params)
    panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Name'] = thingName
    panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Destination'] = params['folder']
    panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Config'] = devData
    if response.status_code == 201:
        panCore.logging.info(f"\t\t\tSCM created {thingName} in SCM folder {params['folder']} from {thingPath}.")
        panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'CreatedSuccessfully'
        panCore.postThingResults[endpoint]['summaries']['createdSuccessfully'][thingPath] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
    elif response.status_code == 400:
        panCore.logging.warning(f"\t\t\tHTTP 400 encountered trying to create {thingName}.")
        if '_errors' in response.json().keys():
            if type(response.json()['_errors']) == list:
                errorCount = len(response.json()['_errors'])
                if 'details' in response.json()['_errors'][0].keys():
                    if type(response.json()['_errors'][0]['details']) == list:
                        panCore.logging.warning(f"\t\t\tFailed to create {thingName} due to {response.json()['_errors'][0]['details']}")
                        panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'otherError'
                        panCore.postThingResults[endpoint]['objectDetails'][thingPath]['errMessage'] = response.json()['_errors'][0]['details']
                        panCore.postThingResults[endpoint]['summaries']['otherError'] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
                    elif 'errorType' in response.json()['_errors'][0]['details'].keys():
                        if response.json()['_errors'][0]['details']['errorType'] == 'Object Already Exists':
                            panCore.logging.warning(f"\t\t\tFailed to create {thingName} as it already exists.")
                            panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'AlreadyExists'
                            panCore.postThingResults[endpoint]['objectDetails'][thingPath]['errMessage'] = response.json()['_errors'][0]['details']
                            panCore.postThingResults[endpoint]['summaries']['alreadyExists'][thingPath] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
                        elif response.json()['_errors'][0]['details']['errorType'] == 'Invalid Object':
                            if 'is not a valid reference>' in response.json()['_errors'][0]['details']['message'][0]:
                                invalidReference = response.json()['_errors'][0]['details']['message'][0].split("'")[1]
                                panCore.logging.warning(f"\t\t\tFailed to create {thingName} as SCM believes it contains an invalid reference: {invalidReference}.")
                                panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'invalidReference'
                                panCore.postThingResults[endpoint]['objectDetails'][thingPath]['errMessage'] = response.json()['_errors'][0]['details']
                                panCore.postThingResults[endpoint]['summaries']['invalidReference'][thingPath] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
                            else:
                                panCore.logging.warning(f"\t\t\tFailed to create {thingName} as SCM believes it's invalid. (Message Details Below):")
                                panCore.logging.warning("\t\t\t".join(response.json()['_errors'][0]['details']['message']))
                                panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'invalidObject'
                                panCore.postThingResults[endpoint]['objectDetails'][thingPath]['errMessage'] = response.json()['_errors'][0]['details']
                                panCore.postThingResults[endpoint]['summaries']['invalidObject'][thingPath] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
                        else:
                            panCore.logging.warning(f"\t\t\tFailed to create {thingName} but no anticipated error was given. See details below:")
                            panCore.logging.warning("\t\t\t".join(response.json()['_errors'][0]['details']['message']))
                            panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'UnexpectedError'
                            panCore.postThingResults[endpoint]['objectDetails'][thingPath]['errMessage'] = response.json()['_errors'][0]['details']
                            panCore.postThingResults[endpoint]['summaries']['unexpectedError'][thingPath] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
        else:
            panCore.logging.warning(f"\t\t\tHTTP 400 received without _errors populated.")
            panCore.logging.warning(f"\t\t\t".join(response.text))
            panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'nonErrorFailure'
            panCore.postThingResults[endpoint]['objectDetails'][thingPath]['httpReponse'] = response.text
            panCore.postThingResults[endpoint]['summaries']['nonErrorResponse'][thingName] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
    else:
        panCore.logging.error("\t\t\tUnexpected HTTP status code encountered. HTTP status and message text to follow:")
        panCore.postThingResults[endpoint]['objectDetails'][thingPath]['Results'] = 'UnexpectedHTTP_Code'
        panCore.postThingResults[endpoint]['objectDetails'][thingPath]['httpCode'] = response.status_code
        panCore.postThingResults[endpoint]['objectDetails'][thingPath]['httpReponse'] = response.text
        panCore.postThingResults[endpoint]['summaries']['unexepectedHTTP_Code'] = panCore.postThingResults[endpoint]['objectDetails'][thingPath]
        panCore.logging.error(response.status_code)
        panCore.logging.error(response.text)


def getThingListFromSCM(thingType, folder, headers, limit=200, offset=0):
    params = {'folder': folder,
              'limit': limit,
              'offset': offset}


def getAccessPolicies():
    payload = {}
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {panCore.scmToken}'}
    return requests.request("GET", "https://api.sase.paloaltonetworks.com/iam/v1/access_policies", headers=headers, data=payload)

def checkUserExists(userMail):
    params = f'email: {userMail}'
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {panCore.scmToken}'}
    return requests.request("GET", "https://api.sase.paloaltonetworks.com/iam/v1/sso_users", headers=headers, params=params)


def createUser(userMail, fName, lName):
    payload = json.dumps({'email': userMail,
                          'firstname': fName,
                          'lastname': lName})
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {panCore.scmToken}'}
    return requests.request("POST", "https://api.sase.paloaltonetworks.com/iam/v1/sso_users", headers=headers, data=payload)


def assignPolicy(userMail, resource, role):
    payload = json.dumps({
        "principal": userMail,
        "resource": resource,
        "role": role})
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {panCore.scmToken}'}
    return requests.request("POST", "https://api.sase.paloaltonetworks.com/iam/v1/access_policies", headers=headers,data=payload)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="CopyToSCM",
        description="Copy Panorama config to Strata Cloud Manager.")
        #epilog="Text")
    parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
    parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='SCM-Migration.log')
    parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
    parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='SCM-Migration.xlsx')
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
    if hasattr(panCore, 'panUser') and panCore.panUser is not None:
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
    elif hasattr(panCore, 'panKey') and panCore.panKey is not None:
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
    else:
        panCore.logging.critical("Found neither username/password nor API key. Exiting.")
        sys.exit()


panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)





roles = []
accessLists = {}
accessLists = (getAccessPolicies()).json()
print(accessLists['items'][0].keys())
for aclIdent in accessLists['items']:
    if aclIdent['principal'] == 'soumik.biswas@global.ntt':
        print(aclIdent.values())

print(accessLists['items'][0].keys())
for aclIdent in accessLists['items']:
    if 'z05391a' in aclIdent['principal']:
        print(aclIdent.values())



newUserList = {
    'kannan.krishnan@global.ntt':
        {'fname': 'kannan',
         'lname': 'krishnan'},
    'maninder-singh@global.ntt':
        {'fname': 'maninder',
         'lname': 'singh'},
    'soumik.biswas@global.ntt':
        {'fname': 'soumik',
         'lname': 'biswas'},
    'subrat11.dash@global.ntt':
        {'fname': 'subrat11',
         'lname': 'dash'},
    'keshav.kapoor@global.ntt':
        {'fname': 'keshav',
         'lname': 'kapoor'},
    'prasanjeet.bhattacharya@global.ntt':
        {'fname': 'prasanjeet',
         'lname': 'bhattacharya'},
    'neetish.kumar@global.ntt':
        {'fname': 'neetish',
         'lname': 'kumar'},
    'rajini.p@global.ntt':
        {'fname': 'rajini',
         'lname': 'p'},
    'vishal.goswami@global.ntt':
        {'fname': 'vishal',
         'lname': 'goswami'},
    'jai.deep@global.ntt':
        {'fname': 'jai',
         'lname': 'deep'},
    'ajay.anantha@global.ntt':
        {'fname': 'ajay',
         'lname': 'anantha'},
    'dileep.anisetti@global.ntt':
        {'fname': 'dileep',
         'lname': 'anisetti'},
    'gaurav.ku@global.ntt':
        {'fname': 'gaurav',
         'lname': 'ku'},
    'muneebnisar.reshi@global.ntt':
        {'fname': 'muneebnisar',
         'lname': 'reshi'},
    'naren.srinivasan@global.ntt':
        {'fname': 'naren',
         'lname': 'srinivasan'},
    'phani.reddy@global.ntt':
        {'fname': 'phani',
         'lname': 'reddy'},
    'ruchi16.sharma@global.ntt':
        {'fname': 'ruchi1',
         'lname': 'sharma',
         'ACL': 'prismaaccess|network_admin,cgx|network_admin'},
    'saicharan.ramesh@global.ntt':
        {'fname': 'saicharan',
         'lname': 'ramesh'},
    'sheby.nathan@global.ntt':
        {'fname': 'sheby',
         'lname': 'nathan'},
    'vikrant11.sharma@global.ntt':
        {'fname': 'vikrant11',
         'lname': 'sharma'}
        }


resp, nullOut = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
for user in newUserList:
    print(f"Creating: {newUserList[user]['fname']} {newUserList[user]['lname']} ({user})")
    userCreation = createUser(user, newUserList[user]['fname'], newUserList[user]['lname'])
    print(f"IAM returned status code: {userCreation.status_code}")
    print(f"IAM returned text: {userCreation.text}")

acls = 'prismaaccess|network_admin,cgx|network_admin'
for acl in acls.split(','):
    resource = acl.split('|')[0]
    role = acl.split('|')[1]

userCreation = createUser('muneebnisar.reshi@global.ntt', 'Muneebnisar', 'Reshi')
checkUser = checkUserExists('cfettig@coca-cola.com')


roles = ['ntt_noc:1731304033', 'browser', 'network_admin', 'security_admin', 'browser', 'mt_monitor_user', 'superreaders:1731304033', 'soc_analyst', 'tier_2_support']
readRoles = ['browser', 'mt_monitor_user', 'soc_analyst', 'view_only_admin']
writeRoles = []

tsgIdent = '1731304033'

response = assignPolicy('fetticj@fettiglab.com', f"prn:{tsgIdent}::::", 'ntt_noc:1731304033')

user = 'fettigcj@fettiglab.com'
resource = "prn:1731304033::::"
resource = 'prn:1731304033:prisma_access:::'
resource = 'prn:1731304033:cgx:::'

adminList = ['ajay.anantha@global.ntt', 'dileep.anisetti@global.ntt', 'gaurav.ku@global.ntt', 'muneebnisar.reshi@global.ntt ', 'naren.srinivasan@global.ntt', 'phani.reddy@global.ntt', 'ruchi16.sharma@global.ntt', 'saicharan.ramesh@global.ntt', 'sheby.nathan@global.ntt', 'vikrant11.sharma@global.ntt']

user = 'jai.deep@global.ntt'
for user in adminList:
    for role in readRoles:
        response = assignPolicy(user, resource, role)
        print(f"Assigned role {role} to {user} and received HTTP response: {response.status_code}")
        print(response.text)



panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)