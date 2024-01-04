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
2023-12-26:
    Tag copying functional and color-to-color-number mapping finished
    Incorporated panCore functionality for SCM interactions
    added ability to parse multiple device groups to destination folders

2023-12-27:
    Address group functionality added.

2023-12-29:
    Base functionality established & tested.
    Tags, Address Objects, Address Groups, Regions, Application Objects (Basic, SCM API rejects signature details),
    App Groups, App filters, Service objects, Service Groups, Custom URL categories, Dynamic User Groups, EDL's,
    Schedules, and Security rules are all created successfully.

2024-01-03:
    Added -F --sharedFolder to args. Replaced (pano_obj, 'All') with (pano_obj, args[0].sharedFolder) to facilitate
    variable destination folder when writing objects from Panorama's "Shared" context.
    Replaced "postSecurityPolicies(" with "processRulebasePolicies(" since pan-os-python co-mingles all policy types.



Future Goals:
    panCore.getSCM_Token() will return HTTP response in the event of a fault, along with a token 'expiry' time of the current time.
    Need to write error handling to either log-and-exit or otherwise handle faults.
    Suspect that returning CURRENT time as expiry time will create a loop since this script will re-try key generation upon reaching expiry time.

    Currently nested groups will error out on first run, but be created properly in a subsequent run.
    Would like to create a way to detect missing members and force groups which contain groups to be created last.

    Create a method to update an object when it already exists rather than simply reporting "Object Already Exists"

    Create postData() function for other functions to call to relegate decoding HTTP 201 / 400 / 401 etc codes to
    shared code instead of copy-paste stuff that needs to be separately maintained.

    Add while errors() loop to eliminate objects w/ errors (Address groups w/ missing nested members get rejected until nested member created)

Functionality Notes / Warnings:
    pan-os-python presents application objects w/ a list "tunnel_applications" but SCM expects that field to be
    "Boolean" and thus rejects the 'list' object. Doesn't seem impactful since there's no apparent way to create a
    custom app-id object with that data populated so the list is always empty...

    Neither API seems to interact with the boolean "Continue scanning for other Applications" field of a custom App-ID
"""
#Import custom library modules
from pancore import panCore, panExcelStyles
import panGroupsAndProfiles
#Import stock/public library modules
import sys, datetime, xlsxwriter, argparse, re, time, panos, requests, json

def postTags(source, destination): # pan-os-python object to copy from and SCM folder to post to
    panCore.logging.info(f"    Retrieving tag data from source: {source}")
    tags = panos.objects.Tag.refreshall(source)
    tagCount = len(tags)
    panCore.logging.info(f"      Retrieved {tagCount} tags.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    tagNum = 1
    for tag_obj in tags:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': tag_obj.about()['name']}
        if tag_obj.about()['color']:
            devData['color'] = colorCodes[tag_obj.about()['color']]
        if tag_obj.about()['comments']:
            devData['comments'] = tag_obj.about()['comments']
        panCore.logging.info(
            F"got tag info for tag {tag_obj.about()['name']}. Posting to SCM... (Tag {tagNum}/{tagCount}")
        response = requests.request("POST", panCore.scmConfURL + "/tags", headers=headers, data=json.dumps(devData),params=params)
        if response.status_code == 201:
            panCore.logging.info("     SCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("HTTP 400 encountered.")
            try:
                panCore.logging.warning(f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("    response does not contain anticipated error data.")
        else:
            panCore.logging.error("Unexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        tagNum += 1


def postAddresses(source, destination):
    panCore.logging.info(f"    Retrieving Address data from source: {source}")
    addresses = panos.objects.AddressObject().refreshall(source)
    addressCount = len(addresses)
    panCore.logging.info(f"      Retrieved {addressCount} addresses.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    addressNum = 1
    for addr_obj in addresses:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': addr_obj.about()['name'],
                   addr_obj.about()['type'].replace('-', '_'): addr_obj.about()['value'],
                   **({'description': addr_obj.about()['description']} if addr_obj.about()['description'] is not None else {}),
                   **({'tag': addr_obj.about()['tag']} if addr_obj.about()['tag'] is not None else {})
                   }
        panCore.logging.info(f"got info for address object {addr_obj.about()['name']}. Posting to SCM... (Address {addressNum}/{addressCount}")
        response = requests.request("POST", panCore.scmConfURL + "/addresses", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("     SCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("HTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("    response does not contain anticipated error data.")
        else:
            panCore.logging.error("Unexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        addressNum += 1

def postAddressGroups(source, destination):
    panCore.logging.info(f"Retrieving Address data from source: {source}")
    addresses = panos.objects.AddressGroup().refreshall(source)
    addressCount = len(addresses)
    panCore.logging.info(f"\tRetrieved {addressCount} address groups.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    errorObjects = {'alreadyExists': [],
                    'invalidObject': {},
                    'invalidReference': {},
                    'otherError': {},
                    'nonErrorResponse': {}}
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    addressNum = 1
    for addr_obj in addresses:
        if addr_obj.dynamic_value is not None:
            panCore.logging.info(f"{addr_obj.name} is a dynamic object.")
        devData = {'name': addr_obj.name,
                   **({'dynamic': {'filter': addr_obj.dynamic_value}} if addr_obj.dynamic_value is not None else {}),
                   **({'static': addr_obj.static_value} if addr_obj.static_value is not None else {}),
                   **({'description': addr_obj.description} if addr_obj.description is not None else {}),
                   **({'tag': addr_obj.tag} if addr_obj.tag is not None else {}),
                   }
        panCore.logging.info(
            f"\tGot info for address group {addr_obj.about()['name']}. Posting to SCM... (Group {addressNum}/{addressCount}")
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        response = requests.request("POST", panCore.scmConfURL + "/address-groups", headers=headers,
                                    data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("\t\tHTTP 400 encountered.")
            if '_errors' in response.json().keys():
                if type(response.json()['_errors']) == list:
                    errorCount = len(response.json()['_errors'])
                    if 'details' in response.json()['_errors'][0].keys():
                        if type(response.json()['_errors'][0]['details']) == list:
                            panCore.logging.warning(f"Failed to create {addr_obj.name} due to {response.json()['_errors'][0]['details']}")
                            errorObjects['otherError'][addr_obj.name] = {'errorType': 'weird list response',
                                                                         'message': response.json()['_errors'][0]['details']}
                        elif 'errorType' in response.json()['_errors'][0]['details'].keys():
                            if response.json()['_errors'][0]['details']['errorType'] == 'Object Already Exists':
                                panCore.logging.warning(f"Failed to create address group {addr_obj.name} as it already exists.")
                                errorObjects['alreadyExists'].append(addr_obj.name)
                            elif response.json()['_errors'][0]['details']['errorType'] == 'Invalid Object':
                                if 'is not a valid reference>' in response.json()['_errors'][0]['details']['message'][0]:
                                    invalidReference = response.json()['_errors'][0]['details']['message'][0].split("'")[1]
                                    panCore.logging.warning(f"\tFailed to create address group {addr_obj.name} as SCM believes it contains an invalid reference {invalidReference}.")
                                    errorObjects['invalidReference'][addr_obj.name] = {'errorType': response.json()['_errors'][0]['details']['errorType'],
                                                                                       'message': response.json()['_errors'][0]['details']['message'],
                                                                                       'invalidReference': invalidReference}
                                else:
                                    panCore.logging.warning(f"Failed to create address group {addr_obj.name} as SCM believes it's invalid. (Message Details Below):")
                                    panCore.logging.warning(response.json()['_errors'][0]['details']['message'])
                                    errorObjects['invalidObject'][addr_obj.name] = {'errorType': response.json()['_errors'][0]['details']['errorType'],
                                                                                    'message': response.json()['_errors'][0]['details']['message']}
                            else:
                                panCore.logging.warning(f"Unexpected HTTP 400 error encountered.")
                                errorObjects['otherError'][addr_obj.name] = {'errorType': response.json()['_errors'][0]['details']['errorType'],
                                                                             'message': response.json()['_errors'][0]['details']['message']}
            else:
                panCore.logging.warning(f"HTTP 400 received without _errors populated.")
                errorObjects['nonErrorResponse'][addr_obj.name] = response.json()
        else:
            panCore.logging.error("Unexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        addressNum += 1
    return errorObjects


def postRegions(source, destination):
    panCore.logging.info(f"\tRetrieving Region data from source: {source}")
    regions = panos.objects.Region().refreshall(source)
    regionCount = len(regions)
    panCore.logging.info(f"\tRetrieved {regionCount} regions.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    regionNum = 1
    for region_obj in regions:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
        devData = {'name': region_obj.about()['name'],
                   'address': region_obj.about()['address']}
        if region_obj.about()['latitude'] and region_obj.about()['longitude']:
            devData['geo_location'] = {'latitude': region_obj.about()['latitude'],
                                       'longitude': region_obj.about()['longitude']}
        panCore.logging.info(f"got info for region object {region_obj.about()['name']}. Posting to SCM... (Region {regionNum}/{regionCount}")
        response = requests.request("POST", panCore.scmConfURL + "/regions", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"\t{response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        regionNum += 1


def postApps(source, destination):
    panCore.logging.info(f"\tRetrieving Application data from source: {source}")
    apps = panos.objects.ApplicationObject().refreshall(source)
    appCount = len(apps)
    panCore.logging.info(f"\tRetrieved {appCount} addresses.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    appNum = 1
    for app_obj in apps:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
        devData = {'name': app_obj.about()['name'],
                   **({'category': app_obj.about()['category']} if app_obj.about()['category'] is not None else {}),
                   **({'subcategory': app_obj.about()['subcategory']} if app_obj.about()['subcategory'] is not None else {}),
                   **({'technology': app_obj.about()['technology']} if app_obj.about()['technology'] is not None else {}),
                   **({'risk': app_obj.about()['risk']} if app_obj.about()['risk'] is not None else {}),
                   **({'parent_app': app_obj.about()['parent_app']} if app_obj.about()['parent_app'] is not None else {}),
                   **({'timeout': app_obj.about()['timeout']} if app_obj.about()['timeout'] is not None else {}),
                   **({'tcp_timeout': app_obj.about()['tcp_timeout']} if app_obj.about()['tcp_timeout'] is not None else {}),
                   **({'udp_timeout': app_obj.about()['udp_timeout']} if app_obj.about()['udp_timeout'] is not None else {}),
                   **({'tcp_half_closed_timeout': app_obj.about()['tcp_half_closed_timeout']} if app_obj.about()['tcp_half_closed_timeout'] is not None else {}),
                   **({'tcp_time_wait_timeout': app_obj.about()['tcp_time_wait_timeout']} if app_obj.about()['tcp_time_wait_timeout'] is not None else {}),
                   **({'evasive_behavior': app_obj.about()['evasive_behavior']} if app_obj.about()['evasive_behavior'] is not None else {}),
                   **({'consume_big_bandwidth': app_obj.about()['consume_big_bandwidth']} if app_obj.about()['consume_big_bandwidth'] is not None else {}),
                   **({'used_by_malware': app_obj.about()['used_by_malware']} if app_obj.about()['used_by_malware'] is not None else {}),
                   **({'able_to_transfer_file': app_obj.about()['able_to_transfer_file']} if app_obj.about()['able_to_transfer_file'] is not None else {}),
                   **({'has_known_vulnerability': app_obj.about()['has_known_vulnerability']} if app_obj.about()['has_known_vulnerability'] is not None else {}),
                   **({'tunnel_other_application': app_obj.about()['tunnel_other_application']} if app_obj.about()['tunnel_other_application'] is not None else {}),
                   #**({'tunnel_applications': app_obj.about()['tunnel_applications']} if app_obj.about()['tunnel_applications'] is not None else {}),
                   # Ignore this field as custom apps can't seem to list the apps which tunnel through it.
                   # THEORETICALLY SCM should support this field as a "list" rather than "boolean" object, but it's
                   # seemingly moot since custom apps can't generate the list anyway.
                   **({'prone_to_misuse': app_obj.about()['prone_to_misuse']} if app_obj.about()['prone_to_misuse'] is not None else {}),
                   **({'pervasive_use': app_obj.about()['pervasive_use']} if app_obj.about()['pervasive_use'] is not None else {}),
                   **({'file_type_ident': app_obj.about()['file_type_ident']} if app_obj.about()['file_type_ident'] is not None else {}),
                   **({'virus_ident': app_obj.about()['virus_ident']} if app_obj.about()['virus_ident'] is not None else {}),
                   **({'data_ident': app_obj.about()['data_ident']} if app_obj.about()['data_ident'] is not None else {}),
                   **({'description': app_obj.about()['description']} if app_obj.about()['description'] is not None else {}),
                   **({'tag': app_obj.about()['tag']} if app_obj.about()['tag'] is not None else {})
                   }
        if app_obj.about()['default_type'] == 'ident-by-ip-protocol':
            devData['default'] = {'ident-by-ip-protocol': app_obj.about()['default_ip_protocol']}
        elif app_obj.about()['default_type'] == 'port':
            devData['default'] = {'port': app_obj.about()['default_port']}
        elif app_obj.about()['default_type'] == 'ident-by-icmp-type':
            devData['default'] = {'ident_by_icmp_type': {'code': str(app_obj.about()['default_icmp_code']),
                                                         'type': str(app_obj.about()['default_icmp_type'])}}
        elif app_obj.about()['default_type'] == 'ident-by-icmp6-type':
            devData['default'] = {'ident_by_icmp_type': {'code': str(app_obj.about()['default_icmp_code']),
                                                         'type': str(app_obj.about()['default_icmp_type'])}}
        """
        xmlData = panCore.xmlToLXML(pano_obj.xapi.get(app_obj.xpath()+'/signature'))
        devData['signature'] = []
        for sig in xmlData.xpath("/response/result/signature/entry"):
            sigData = {'name': sig.attrib['name'],
                       'scope': sig.find('scope').text,
                       **({'order_free': False} if sig.find('order-free').text == 'no' else {'order_free': True}),
                       'and_condition': []}
            for condition in sig.findall('and-condition/entry'):
                condData = {'name': condition.attrib['name'],
                            'or_condition': []}
                for childCondition in condition.findall('or-condition/entry'):
                    operatorType = childCondition.find('operator').getchildren()[0].tag
                    temp = {}
                    for child in childCondition.find(f'operator/{operatorType}').getchildren():
                        if child.tag == 'qualifier':
                            temp['qualifier'] = [{'name': child.find('entry').attrib['name'],
                                                  'value': child.find('entry/value').text}]
                        else:
                            temp[child.tag] = child.text
                    childData = {'name': childCondition.attrib['name'],
                                 'operator': {operatorType: temp}}
                    condData['or_condition'].append(childData)
                sigData['and_condition'].append(condData)
            devData['signature'].append(sigData)
        """
        panCore.logging.info(f"got info for address object {app_obj.about()['name']}. Posting to SCM... (Address {appNum}/{appCount}")
        response = requests.request("POST", panCore.scmConfURL + "/applications", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("HTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"\t{response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        appNum += 1


def postAppGroups(source, destination):
    panCore.logging.info(f"\tRetrieving Application Group data from source: {source}")
    groups = panos.objects.ApplicationGroup().refreshall(source)
    groupCount = len(groups)
    panCore.logging.info(f"\tRetrieved {groupCount} groups.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    grpNum = 1
    for grp_obj in groups:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': grp_obj.about()['name'],
                   **({'members': grp_obj.about()['value']} if grp_obj.about()['value'] is not None else {}),
                   **({'tag': grp_obj.about()['tag']} if grp_obj.about()['tag'] is not None else {})
                   }
        panCore.logging.info(f"\tgot info for App-ID group {grp_obj.about()['name']}. Posting to SCM... (group {grpNum}/{groupCount}")
        response = requests.request("POST", panCore.scmConfURL + "/application-groups", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        grpNum += 1


def postAppFilters(source, destination):
    panCore.logging.info(f"\tRetrieving Application filters from source: {source}")
    filters = panos.objects.ApplicationFilter().refreshall(source)
    filterCount = len(filters)
    panCore.logging.info(f"\tRetrieved {filterCount} groups.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    filterNum = 1
    for filter_obj in filters:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': filter_obj.about()['name'],
                   **({'category': filter_obj.about()['category']} if filter_obj.about()['category'] is not None else {}),
                   **({'subcategory': filter_obj.about()['subcategory']} if filter_obj.about()['subcategory'] is not None else {}),
                   **({'technology': filter_obj.about()['technology']} if filter_obj.about()['technology'] is not None else {}),
                   **({'risk': filter_obj.about()['risk']} if filter_obj.about()['risk'] is not None else {}),
                   **({'evasive': True} if filter_obj.about()['evasive'] is not None else {}),
                   **({'excessive_bandwidth_use': True} if filter_obj.about()['excessive_bandwidth_use'] is not None else {}),
                   **({'prone_to_misuse': True} if filter_obj.about()['prone_to_misuse'] is not None else {}),
                   **({'is_saas': True} if filter_obj.about()['is_saas'] is not None else {}),
                   **({'transfers_files': True} if filter_obj.about()['transfers_files'] is not None else {}),
                   **({'tunnels_other_apps': True} if filter_obj.about()['tunnels_other_apps'] is not None else {}),
                   **({'used_by_malware': True} if filter_obj.about()['used_by_malware'] is not None else {}),
                   **({'has_known_vulnerabilities': True} if filter_obj.about()['has_known_vulnerabilities'] is not None else {}),
                   **({'pervasive': True} if filter_obj.about()['pervasive'] is not None else {}),
                   **({'tagging': {'tag': filter_obj.about()['tag']}} if filter_obj.about()['tag'] is not None else {})}
        panCore.logging.info(f"\tgot info for App-ID group {filter_obj.about()['name']}. Posting to SCM... (group {filterNum}/{filterCount}")
        response = requests.request("POST", panCore.scmConfURL + "/application-filters", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        filterNum += 1

def postService(source, destination):
    panCore.logging.info(f"\tRetrieving service objects from source: {source}")
    services = panos.objects.ServiceObject().refreshall(source)
    svcCount = len(services)
    panCore.logging.info(f"\tRetrieved {svcCount} groups.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    serviceNum = 1
    for svc_obj in services:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': svc_obj.name,
                   **({'description': svc_obj.description} if svc_obj.description is not None else {}),
                   **({'tag': svc_obj.tag} if svc_obj.tag is not None else {}),
                   'protocol': {svc_obj.protocol: {
                       **({'port': svc_obj.destination_port} if svc_obj.destination_port is not None else {}),
                       **({'source_port': svc_obj.source_port} if svc_obj.source_port is not None else {}),
                   }}}
        if svc_obj.enable_override_timeout:
            devData['protocol'][svc_obj.protocol]['override'] = {
                **({'timeout': svc_obj.override_timeout} if svc_obj.override_timeout is not None else {}),
                **({'halfclose_timeout': svc_obj.override_half_close_timeout} if svc_obj.override_half_close_timeout is not None else {}),
                **({'timewait_timeout': svc_obj.override_time_wait_timeout} if svc_obj.override_time_wait_timeout is not None else {})
                }
        panCore.logging.info(f"\tgot info for service object {svc_obj.about()['name']}. Posting to SCM... (Service {serviceNum}/{svcCount})")
        response = requests.request("POST", panCore.scmConfURL + "/services", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new object.")
        elif response.status_code == 400:
            panCore.logging.warning("\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        serviceNum += 1

def postServiceGroup(source, destination):
    panCore.logging.info(f"Retrieving service objects from source: {source}")
    serviceGroups = panos.objects.ServiceGroup().refreshall(source)
    grpCount = len(serviceGroups)
    panCore.logging.info(f"\tRetrieved {grpCount} service objects.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    grpNum = 1
    for grp_obj in serviceGroups:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': grp_obj.name,
                   **({'members': grp_obj.value} if grp_obj.value is not None else {}),
                   **({'tag': grp_obj.tag} if grp_obj.tag is not None else {})
                   }
        panCore.logging.info(f"\tgot info for service group {grp_obj.about()['name']}. Posting to SCM... (Service {grpNum}/{grpCount})")
        response = requests.request("POST", panCore.scmConfURL + "/service-groups", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new group.")
        elif response.status_code == 400:
            panCore.logging.warning("\t\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\t\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\t\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        grpNum += 1


def postURLs(source, destination):
    panCore.logging.info(f"Retrieving custom URL objects from source: {source}")
    URLs = panos.objects.CustomUrlCategory().refreshall(source)
    URL_Count = len(URLs)
    panCore.logging.info(f"\tRetrieved {URL_Count} URL objects.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    URL_Num = 1
    for url_obj in URLs:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': url_obj.name,
                   'type': url_obj.type,
                   **({'description': url_obj.description} if url_obj.description is not None else {}),
                   **({'list': url_obj.url_value} if url_obj.url_value is not None else {})
                   }
        panCore.logging.info(f"\tgot info for custom URL objects {url_obj.about()['name']}. Posting to SCM... (URL {URL_Num}/{URL_Count})")
        response = requests.request("POST", panCore.scmConfURL + "/url-categories", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new custom URL objects.")
        elif response.status_code == 400:
            panCore.logging.warning("\t\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\t\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\t\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        URL_Num += 1

def postDynamicUserGroups(source, destination):
    panCore.logging.info(f"Retrieving dynamic user groups from source: {source}")
    groups = panos.objects.DynamicUserGroup().refreshall(source)
    grpCount = len(groups)
    panCore.logging.info(f"\tRetrieved {grpCount} dynamic user groups.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    grpNum = 1
    for grp_obj in groups:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        xmlData = panCore.xmlToLXML(pano_obj.xapi.get(grp_obj.xpath()))
        if xmlData.find('.//disable-override').text == 'yes':
            panCore.logging.error(f"Disable override set on {grp_obj.name} but not supported in SCM as overrides do not exist in SCM"
                                  f"Investigate please.")
        devData = {'name': grp_obj.name,
                   **({'description': grp_obj.description} if grp_obj.description is not None else {}),
                   **({'filter': grp_obj.filter} if grp_obj.filter is not None else {}),
                   **({'tag': grp_obj.tag} if grp_obj.tag is not None else {})
                   }
        panCore.logging.info(f"\tgot info for custom URL objects {grp_obj.about()['name']}. Posting to SCM... (URL {grpNum}/{grpCount})")
        response = requests.request("POST", panCore.scmConfURL + "/dynamic-user-groups", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new dynamic user group.")
        elif response.status_code == 400:
            panCore.logging.warning("\t\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\t\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\t\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        grpNum += 1


def postEDLs(source, destination):
    panCore.logging.info(f"Retrieving EDLs from source: {source}")
    EDLs = panos.objects.Edl().refreshall(source)
    edlCount = len(EDLs)
    panCore.logging.info(f"\tRetrieved {edlCount} EDLs.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    edlNum = 1
    for edl_obj in EDLs:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': edl_obj.name,
                   'type': {edl_obj.edl_type: {
                       **({'description': edl_obj.description} if edl_obj.description is not None else {}),
                       **({'url': edl_obj.source} if edl_obj.source is not None else {}),
                       **({'exception_list': edl_obj.exceptions} if edl_obj.exceptions is not None else {}),
                       **({'certificate_profile': edl_obj.certificate_profile} if edl_obj.certificate_profile is not None else {}),
                       'recurring': {edl_obj.repeat: {
                           **({'at': edl_obj.repeat_at} if edl_obj.repeat_at is not None else {}),
                           **({'day_of_week': edl_obj.repeat_day_of_week} if edl_obj.repeat_day_of_week is not None else {}),
                           **({'day_of_month': edl_obj.repeat_day_of_month} if edl_obj.repeat_day_of_month is not None else {})
                        }
                   }}}}
        if edl_obj.username:
            devData['type'][edl_obj.edl_type]['auth'] = {'username': edl_obj.username,
                                                     'password': edl_obj.password}
        panCore.logging.info(f"\tgot info for EDL {edl_obj.about()['name']}. Posting to SCM... (EDL {edlNum}/{edlCount})")
        response = requests.request("POST", panCore.scmConfURL + "/external-dynamic-lists", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new EDL.")
        elif response.status_code == 400:
            panCore.logging.warning("\t\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\t\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\t\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        edlNum += 1

def postSchedules(source, destination):
    panCore.logging.info(f"Retrieving schedule objects from source: {source}")
    schedules = panos.objects.ScheduleObject().refreshall(source)
    schedCount = len(schedules)
    panCore.logging.info(f"\tRetrieved {schedCount} schedule objects.")
    params = {'folder': destination}
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    schedNum = 1
    for sched_obj in schedules:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        devData = {'name': sched_obj.name,
                   'schedule_type': {sched_obj.type.replace('-','_'): {
                       **({sched_obj.recurrence: sched_obj.daily_time} if sched_obj.recurrence == 'daily' else {}),
                       **({sched_obj.recurrence: {
                           **({'monday': sched_obj.weekly_monday_time} if sched_obj.weekly_monday_time is not None else {}),
                           **({'tuesday': sched_obj.weekly_tuesday_time} if sched_obj.weekly_tuesday_time is not None else {}),
                           **({'wednesday': sched_obj.weekly_wednesday_time} if sched_obj.weekly_wednesday_time is not None else {}),
                           **({'thursday': sched_obj.weekly_thursday_time} if sched_obj.weekly_thursday_time is not None else {}),
                           **({'friday': sched_obj.weekly_friday_time} if sched_obj.weekly_friday_time is not None else {}),
                           **({'saturday': sched_obj.weekly_saturday_time} if sched_obj.weekly_saturday_time is not None else {}),
                           **({'sunday': sched_obj.weekly_sunday_time} if sched_obj.weekly_sunday_time is not None else {})
                           }} if sched_obj.recurrence == 'weekly' else {})
                   }}}
        if sched_obj.type == 'non-recurring':
            devData['schedule_type']['non_recurring'] = sched_obj.non_recurring_date_time
        panCore.logging.info(f"\tgot info for schedule {sched_obj.about()['name']}. Posting to SCM... (Schedule {schedNum}/{schedCount})")
        response = requests.request("POST", panCore.scmConfURL + "/schedules", headers=headers, data=json.dumps(devData), params=params)
        if response.status_code == 201:
            panCore.logging.info("\t\tSCM created new schedule.")
        elif response.status_code == 400:
            panCore.logging.warning("\t\tHTTP 400 encountered.")
            try:
                panCore.logging.warning(
                    f"    {response.json()['_errors'][0]['details']['errorType']} : {response.json()['_errors'][0]['details']['message']}")
            except:
                panCore.logging.warning("\t\tresponse does not contain anticipated error data.")
        else:
            panCore.logging.error("\t\tUnexpected HTTP status code encountered. HTTP status and JSON to follow:")
            panCore.logging.error(response.status_code)
            panCore.logging.error(response.json())
        schedNum += 1

def postSecurityRules(rule_obj, context, headers, destination, logDest='Cortex Data Lake'):
    devData = {'name': rule_obj.name,
               'from': rule_obj.fromzone,
               'to': rule_obj.tozone,
               'source': rule_obj.source,
               'source_user': rule_obj.source_user,
               'destination': rule_obj.destination,
               'application': rule_obj.application,
               'service': rule_obj.service,
               'category': rule_obj.category,
               'log_setting': logDest,  # Default rules to forward logs to Cortex Data Lake.
               'action': rule_obj.action,
               **({'description': rule_obj.description} if rule_obj.description is not None else {}),
               # rule_obj.log_start      SCM API unable to configure currently
               # rule_obj.log_end        SCM API unable to configure currently
               # rule_obj.type          SCM only seems to have 'Universal' rather than "inter" or "intra-zone" rules - at least within Prisma Access
               **({'tag': rule_obj.tag} if rule_obj.tag is not None else {}),
               **({'negate_source': rule_obj.negate_source} if rule_obj.negate_source is not None else {}),
               **({
                      'negate_destination': rule_obj.negate_destination} if rule_obj.negate_destination is not None else {}),
               **({'disabled': rule_obj.disabled} if rule_obj.disabled is not None else {}),
               # rule_obj.schedule
               # rule_obj.icmp_unreachable
               # rule_obj.disable_server_response_inspection
               **({'profile_setting': {'group': rule_obj.group}} if rule_obj.group is not None else {}),
               **({'source_hip': rule_obj.source_devices} if rule_obj.source_devices is not None else {}),
               **({'destination_hip': rule_obj.destination_devices} if rule_obj.destination_devices is not None else {})
               }
    submission = {
        'devData': devData,
        'thingName': rule_obj.name,
        'headers': headers,
        'endpoint': "/security-rules",
        'params': {'folder': destination,
                   'position': context}}
    scmErorrs = postThing(submission)
    return scmErorrs

def processRulebasePolicies(ruleBase, context, destination, logDest='Cortex Data Lake'):
    # HTTP post to SCM to create security policy in specified Pre- or Post- context in destination folder.
    ruleNum = 1
    ruleCount = len(ruleBase.children)
    panCore.logging.info(f"\tRetrieved {ruleCount} policies.")
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    if tokenExpiryTime <= time.time():
        panCore.logging.error("Error: Received expired token. Investigate.")
    for rule_obj in ruleBase.children:
        if time.time() >= tokenExpiryTime:
            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
            if tokenExpiryTime <= time.time():
                panCore.logging.error("Error: Received expired token. Investigate.")
        if isinstance(rule_obj, panos.policies.ApplicationOverride):
            print('ApplicationOverride')
        if isinstance(rule_obj, panos.policies.AuthenticationRule):
            print('AuthenticationRule')
        if isinstance(rule_obj, panos.policies.DecryptionRule):
            print('DecryptionRule')
        if isinstance(rule_obj, panos.policies.NatRule):
            print('NatRule')
        if isinstance(rule_obj, panos.policies.PolicyBasedForwarding):
            print('PolicyBasedForwarding')
        if isinstance(rule_obj, panos.policies.SecurityRule):
            panCore.logging.info(f"\tgot info for rule {rule_obj.name}. Posting to SCM... (Rule {ruleNum}/{ruleCount})")
            scmErrors = postSecurityRules(rule_obj, context, headers, destination, logDest)
        ruleNum += 1


def postThing(submission):
    devData = submission['devData']
    thingName = submission['name']
    headers = submission['headers']
    endpoint = submission['endpoint']
    params = submission['params']
    response = requests.request("POST", panCore.scmConfURL + endpoint, headers=headers, data=json.dumps(devData), params=params)
    scmErrors = {}
    if response.status_code == 201:
        panCore.logging.info(f"\t\tSCM created new object {thingName}.")
    elif response.status_code == 400:
        panCore.logging.warning(f"\t\tHTTP 400 encountered trying to create {thingName}.")
        if '_errors' in response.json().keys():
            if type(response.json()['_errors']) == list:
                errorCount = len(response.json()['_errors'])
                if 'details' in response.json()['_errors'][0].keys():
                    if type(response.json()['_errors'][0]['details']) == list:
                        panCore.logging.warning(f"Failed to create {thingName} due to {response.json()['_errors'][0]['details']}")
                        scmErrors['otherError'][thingName] = {'errorType': 'weird list response',
                                                                     'message': response.json()['_errors'][0]['details']}
                    elif 'errorType' in response.json()['_errors'][0]['details'].keys():
                        if response.json()['_errors'][0]['details']['errorType'] == 'Object Already Exists':
                            panCore.logging.warning(f"Failed to create {thingName} as it already exists.")
                            scmErrors['alreadyExists'].append(thingName)
                        elif response.json()['_errors'][0]['details']['errorType'] == 'Invalid Object':
                            if 'is not a valid reference>' in response.json()['_errors'][0]['details']['message'][0]:
                                invalidReference = response.json()['_errors'][0]['details']['message'][0].split("'")[1]
                                panCore.logging.warning(f"\tFailed to create {thingName} as SCM believes it contains an invalid reference: {invalidReference}.")
                                scmErrors['invalidReference'][thingName] = {'errorType': response.json()['_errors'][0]['details']['errorType'],
                                                                                   'message': response.json()['_errors'][0]['details']['message'],
                                                                                   'invalidReference': invalidReference}
                            else:
                                panCore.logging.warning(f"Failed to create {thingName} as SCM believes it's invalid. (Message Details Below):")
                                panCore.logging.warning(response.json()['_errors'][0]['details']['message'])
                                scmErrors['invalidObject'][thingName] = {'errorType': response.json()['_errors'][0]['details']['errorType'],
                                                                                'message': response.json()['_errors'][0]['details']['message']}
                        else:
                            panCore.logging.warning(f"Unexpected HTTP 400 error encountered.")
                            scmErrors['otherError'][thingName] = {'errorType': response.json()['_errors'][0]['details']['errorType'],
                                                                         'message': response.json()['_errors'][0]['details']['message']}
        else:
            panCore.logging.warning(f"HTTP 400 received without _errors populated.")
            scmErrors['nonErrorResponse'][thingName] = response.json()
    else:
        panCore.logging.error("Unexpected HTTP status code encountered. HTTP status and JSON to follow:")
        panCore.logging.error(response.status_code)
        panCore.logging.error(response.json())
    return scmErrors

def postAntivirusWildfire(source, destination):
    print("SCM not implemented yet...")


def getRegions():
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    params = {'folder': 'All'}
    response = requests.request("GET", panCore.scmConfURL + "/regions", headers=headers, data={}, params=params)
    return response


def getDynamicUserGroups():
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    params = {'folder': 'All'}
    response = requests.request("GET", panCore.scmConfURL + "/dynamic-user-groups", headers=headers, data={}, params=params)
    return response


def getThingFromSCM(thing, folder):
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    params = {'folder': folder}
    return requests.request("GET", f"{panCore.scmConfURL}/{thing}", headers=headers, data={}, params=params)


def temp():
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    response = requests.request("GET", panCore.scmConfURL + "/applications", headers=headers, data={},
                                params={'folder': "Shared", 'offset': '4380'})


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

colorCodes = {
    'color1': 'Red',
    'color2': 'Green',
    'color3': 'Blue',
    'color4': 'Yellow',
    'color5': 'Copper',
    'color6': 'Orange',
    'color7': 'Purple',
    'color8': 'Gray',
    'color9': 'Light Green',
    'color10': 'Cyan',
    'color11': 'Light Gray',
    'color12': 'Blue Gray',
    'color13': 'Lime',
    'color14': 'Black',
    'color15': 'Gold',
    'color16': 'Brown',
    'color17': 'Olive',
    'color19': 'Maroon',
    'color20': 'Red-Orange',
    'color21': 'Yellow-Orange',
    'color22': 'Forest Green',
    'color23': 'Turquoise Blue',
    'color24': 'Azure Blue',
    'color25': 'Cerulean Blue',
    'color26': 'Midnight Blue',
    'color27': 'Medium Blue',
    'color28': 'Cobalt Blue',
    'color29': 'Violet Blue',
    'color30': 'Blue Violet',
    'color31': 'Medium Violet',
    'color32': 'Medium Rose',
    'color33': 'Lavender',
    'color34': 'Orchid',
    'color35': 'Thistle',
    'color36': 'Peach',
    'color37': 'Salmon',
    'color38': 'Magenta',
    'color39': 'Red Violet',
    'color40': 'Mahogany',
    'color41': 'Burnt Sienna',
    'color42': 'Chestnut'
    }

panCore.logging.info("Posting tag data to SCM:\n")
if args[0].noShared:
    pass
else:
    postTags(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postTags(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

panCore.logging.info("Posting address data to SCM:\n")
if args[0].noShared:
    pass
else:
    postAddresses(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postAddresses(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

panCore.logging.info("Posting Address Groups to SCM:\n")
errObjects = {}
if args[0].noShared:
    pass
else:
    errObjects.update(postAddressGroups(pano_obj, args[0].sharedFolder))
for dgPair in args[0].deviceGroups.split(","):
    errObjects.update(postAddressGroups(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1]))

panCore.logging.info("Posting Regions to SCM:\n")
if args[0].noShared:
    pass
else:
    postRegions(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postRegions(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

panCore.logging.info("Posting App-ID data to SCM:\n")
if args[0].noShared:
    pass
else:
    postApps(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postApps(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

panCore.logging.info("Posting App-ID groups to SCM:\n")
if args[0].noShared:
    pass
else:
    postAppGroups(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postAppGroups(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

panCore.logging.info("Posting App-ID filters to SCM:\n")
if args[0].noShared:
    pass
else:
    postAppFilters(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postAppFilters(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

panCore.logging.info("Posting service objects to SCM:\n")
if args[0].noShared:
    pass
else:
    postService(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postService(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

panCore.logging.info("Posting service groups to SCM:\n")
if args[0].noShared:
    pass
else:
    postServiceGroup(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postServiceGroup(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])


panCore.logging.info("Posting custom URL objects to SCM:\n")
if args[0].noShared:
    pass
else:
    postURLs(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postURLs(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])


panCore.logging.info("Posting Dynamic User Groups to SCM:\n")
if args[0].noShared:
    pass
else:
    postDynamicUserGroups(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postDynamicUserGroups(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])


panCore.logging.info("Posting External Dynamic Lists to SCM:\n")
if args[0].noShared:
    pass
else:
    postEDLs(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postEDLs(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])


panCore.logging.info("Posting Schedules to SCM:\n")
if args[0].noShared:
    pass
else:
    postSchedules(pano_obj, args[0].sharedFolder)
for dgPair in args[0].deviceGroups.split(","):
    postSchedules(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])


""""
    2023-12-29
    Pausing development on this until SCM API updated to support profile configuration
panCore.logging.info("Gathering DG data from panGroupsAndProfiles")
if args[0].noShared:
    pass
else:
    panGroupsAndProfiles.pano_obj = pano_obj
    dgData = panGroupsAndProfiles.buildAll('/config/shared')
    for avProfile in dgData['AntiVirusProfiles']:
        print(avProfile)
"""


panCore.logging.info("Posting security policies to SCM:\n")
if args[0].noShared:
    pass
else:
    preRules = panos.policies.PreRulebase().refreshall(pano_obj)
    if preRules: # Don't try to import an empty list of rules.
        processRulebasePolicies(preRules[0], 'pre', "Shared") # select the rulebase from the list of rulebases returned
    postRules = panos.policies.PostRulebase().refreshall(pano_obj)
    if postRules:
        processRulebasePolicies(postRules[0], 'post', 'Shared')
for dgPair in args[0].deviceGroups.split(","):
    dg_obj, destination = pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1]
    preRules = panos.policies.PreRulebase().refreshall(dg_obj)
    if preRules:  # Don't try to import an empty list of rules.
        processRulebasePolicies(preRules[0], context='pre', destination=destination)  # select the rulebase from the list of rulebases returned
    postRules = panos.policies.PostRulebase().refreshall(dg_obj)
    if postRules:  # Don't try to import an empty list of rules.
        processRulebasePolicies(postRules[0], context='post', destination=destination)  # select the rulebase from the list of rulebases returned