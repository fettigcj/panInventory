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

2024-01-05:
    Added threading & thread queue functions to accelerate write operations

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
import sys, datetime, xlsxwriter, argparse, re, time, panos, requests, json, threading
from threading import Thread


def postTags(source, destination):  # pan-os-python object to copy from and SCM folder to post to
    panCore.logging.info(f"\t\tRetrieving tag data from source: {source}")
    tags = panos.objects.Tag.refreshall(source)
    tagCount = len(tags)
    panCore.logging.info(f"\t\tRetrieved {tagCount} tags.")
    tagNum = 1
    jobs = []
    for tag_obj in tags:
        devData = {'name': tag_obj.name,
                   **({'color': colorCodes[tag_obj.color]} if tag_obj.color is not None else {}),
                   **({'comments': tag_obj.comments} if tag_obj.comments is not None else {}),
                   }
        panCore.logging.info(f"\t\tGot tag info for tag {tag_obj.name}. Posting to SCM... (Tag {tagNum}/{tagCount})")
        submission = {
            'devData': devData,
            'thingName': tag_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/tags",
            'params': {'folder': destination}}
        jobs.append(Thread(target=postThing, args=(submission,)))
        tagNum += 1
    runJobs(jobs)


def postAddresses(source, destination):
    panCore.logging.info(f"\t\tRetrieving Address data from source: {source}")
    addresses = panos.objects.AddressObject().refreshall(source)
    addressCount = len(addresses)
    panCore.logging.info(f"\t\tRetrieved {addressCount} addresses.")
    addressNum = 1
    jobs = []
    for addr_obj in addresses:
        devData = {'name': addr_obj.name,
                   addr_obj.type.replace('-', '_'): addr_obj.value,
                   **({'description': addr_obj.description} if addr_obj.description is not None else {}),
                   **({'tag': addr_obj.tag} if addr_obj.tag is not None else {})
                   }
        panCore.logging.info(f"\t\tgot info for address object {addr_obj.name}. Posting to SCM... (Address {addressNum}/{addressCount}")
        submission = {
            'devData': devData,
            'thingName': addr_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/addresses",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        addressNum += 1
    runJobs(jobs)

def postAddressGroups(source, destination):
    panCore.logging.info(f"\tRetrieving Address data from source: {source}")
    addresses = panos.objects.AddressGroup().refreshall(source)
    addressCount = len(addresses)
    panCore.logging.info(f"\t\tRetrieved {addressCount} address groups.")
    addressNum = 1
    jobs = []
    for addr_obj in addresses:
        if addr_obj.dynamic_value is not None:
            panCore.logging.info(f"{addr_obj.name} is a dynamic object.")
        devData = {'name': addr_obj.name,
                   **({'dynamic': {'filter': addr_obj.dynamic_value}} if addr_obj.dynamic_value is not None else {}),
                   **({'static': addr_obj.static_value} if addr_obj.static_value is not None else {}),
                   **({'description': addr_obj.description} if addr_obj.description is not None else {}),
                   **({'tag': addr_obj.tag} if addr_obj.tag is not None else {}),
                   }
        panCore.logging.info(f"\t\tGot info for address group {addr_obj.name}. Posting to SCM... (Group {addressNum}/{addressCount}")
        submission = {
            'devData': devData,
            'thingName': addr_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/address-groups",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        addressNum += 1
    runJobs(jobs)

def postRegions(source, destination):
    panCore.logging.info(f"\tRetrieving Region data from source: {source}")
    regions = panos.objects.Region().refreshall(source)
    regionCount = len(regions)
    panCore.logging.info(f"\t\tRetrieved {regionCount} regions.")
    regionNum = 1
    jobs = []
    for region_obj in regions:
        devData = {'name': region_obj.name,
                   ** ({'address': region_obj.address} if region_obj.address is not None else {})}
        if region_obj.latitude is not None and region_obj.longitude is not None:
            devData['geo_location'] = {
                'latitude': region_obj.latitude,
                'longitude': region_obj.longitude}
        panCore.logging.info(f"got info for region object {region_obj.name}. Posting to SCM... (Region {regionNum}/{regionCount}")
        submission = {
            'devData': devData,
            'thingName': region_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/regions",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        regionNum += 1
    runJobs(jobs)

def postApps(source, destination):
    panCore.logging.info(f"\tRetrieving Application data from source: {source}")
    apps = panos.objects.ApplicationObject().refreshall(source)
    appCount = len(apps)
    panCore.logging.info(f"\t\tRetrieved {appCount} addresses.")
    appNum = 1
    jobs = []
    for app_obj in apps:
        devData = {'name': app_obj.name,
                   **({'category': app_obj.category} if app_obj.category is not None else {}),
                   **({'subcategory': app_obj.subcategory} if app_obj.subcategory is not None else {}),
                   **({'technology': app_obj.technology} if app_obj.technology is not None else {}),
                   **({'risk': app_obj.risk} if app_obj.risk is not None else {}),
                   **({'parent_app': app_obj.parent_app} if app_obj.parent_app is not None else {}),
                   **({'timeout': app_obj.timeout} if app_obj.timeout is not None else {}),
                   **({'tcp_timeout': app_obj.tcp_timeout} if app_obj.tcp_timeout is not None else {}),
                   **({'udp_timeout': app_obj.udp_timeout} if app_obj.udp_timeout is not None else {}),
                   **({'tcp_half_closed_timeout': app_obj.tcp_half_closed_timeout} if app_obj.tcp_half_closed_timeout is not None else {}),
                   **({'tcp_time_wait_timeout': app_obj.tcp_time_wait_timeout} if app_obj.tcp_time_wait_timeout is not None else {}),
                   **({'evasive_behavior': app_obj.evasive_behavior} if app_obj.evasive_behavior is not None else {}),
                   **({'consume_big_bandwidth': app_obj.consume_big_bandwidth} if app_obj.consume_big_bandwidth is not None else {}),
                   **({'used_by_malware': app_obj.used_by_malware} if app_obj.used_by_malware is not None else {}),
                   **({'able_to_transfer_file': app_obj.able_to_transfer_file} if app_obj.able_to_transfer_file is not None else {}),
                   **({'has_known_vulnerability': app_obj.has_known_vulnerability} if app_obj.has_known_vulnerability is not None else {}),
                   **({'tunnel_other_application': app_obj.tunnel_other_application} if app_obj.tunnel_other_application is not None else {}),
                   #**({'tunnel_applications': app_obj.tunnel_applications} if app_obj.tunnel_applications is not None else {}),
                   # Ignore this field as custom apps can't seem to list the apps which tunnel through it.
                   # THEORETICALLY SCM should support this field as a "list" rather than "boolean" object, but it's
                   # seemingly moot since custom apps can't generate the list anyway.
                   **({'prone_to_misuse': app_obj.prone_to_misuse} if app_obj.prone_to_misuse is not None else {}),
                   **({'pervasive_use': app_obj.pervasive_use} if app_obj.pervasive_use is not None else {}),
                   **({'file_type_ident': app_obj.file_type_ident} if app_obj.file_type_ident is not None else {}),
                   **({'virus_ident': app_obj.virus_ident} if app_obj.virus_ident is not None else {}),
                   **({'data_ident': app_obj.data_ident} if app_obj.data_ident is not None else {}),
                   **({'description': app_obj.description} if app_obj.description is not None else {}),
                   **({'tag': app_obj.tag} if app_obj.tag is not None else {})
                   }
        if app_obj.default_type == 'ident-by-ip-protocol':
            devData['default'] = {'ident-by-ip-protocol': app_obj.default_ip_protocol}
        elif app_obj.default_type == 'port':
            devData['default'] = {'port': app_obj.default_port}
        elif app_obj.default_type == 'ident-by-icmp-type':
            devData['default'] = {'ident_by_icmp_type': {'code': str(app_obj.default_icmp_code),
                                                         'type': str(app_obj.default_icmp_type)}}
        elif app_obj.default_type == 'ident-by-icmp6-type':
            devData['default'] = {'ident_by_icmp_type': {'code': str(app_obj.default_icmp_code),
                                                         'type': str(app_obj.default_icmp_type)}}
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
        panCore.logging.info(f"\t\tgot info for address object {app_obj.name}. Posting to SCM... (Address {appNum}/{appCount}")
        submission = {
            'devData': devData,
            'thingName': app_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/applications",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        appNum += 1
    runJobs(jobs)

def postAppGroups(source, destination):
    panCore.logging.info(f"\tRetrieving Application Group data from source: {source}")
    groups = panos.objects.ApplicationGroup().refreshall(source)
    groupCount = len(groups)
    panCore.logging.info(f"\t\tRetrieved {groupCount} groups.")
    grpNum = 1
    jobs = []
    for grp_obj in groups:
        devData = {'name': grp_obj.name,
                   **({'members': grp_obj.value} if grp_obj.value is not None else {}),
                   **({'tag': grp_obj.tag} if grp_obj.tag is not None else {})
                   }
        panCore.logging.info(f"\t\tgot info for App-ID group {grp_obj.name}. Posting to SCM... (group {grpNum}/{groupCount}")
        submission = {
            'devData': devData,
            'thingName': grp_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/application-groups",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        grpNum += 1
    runJobs(jobs)


def postAppFilters(source, destination):
    panCore.logging.info(f"\tRetrieving Application filters from source: {source}")
    filters = panos.objects.ApplicationFilter().refreshall(source)
    filterCount = len(filters)
    panCore.logging.info(f"\t\tRetrieved {filterCount} groups.")
    filterNum = 1
    jobs = []
    for filter_obj in filters:
        devData = {'name': filter_obj.name,
                   **({'category': filter_obj.category} if filter_obj.category is not None else {}),
                   **({'subcategory': filter_obj.subcategory} if filter_obj.subcategory is not None else {}),
                   **({'technology': filter_obj.technology} if filter_obj.technology is not None else {}),
                   **({'risk': filter_obj.risk} if filter_obj.risk is not None else {}),
                   **({'evasive': True} if filter_obj.evasive is not None else {}),
                   **({'excessive_bandwidth_use': True} if filter_obj.excessive_bandwidth_use is not None else {}),
                   **({'prone_to_misuse': True} if filter_obj.prone_to_misuse is not None else {}),
                   **({'is_saas': True} if filter_obj.is_saas is not None else {}),
                   **({'transfers_files': True} if filter_obj.transfers_files is not None else {}),
                   **({'tunnels_other_apps': True} if filter_obj.tunnels_other_apps is not None else {}),
                   **({'used_by_malware': True} if filter_obj.used_by_malware is not None else {}),
                   **({'has_known_vulnerabilities': True} if filter_obj.has_known_vulnerabilities is not None else {}),
                   **({'pervasive': True} if filter_obj.pervasive is not None else {}),
                   **({'tagging': {'tag': filter_obj.tag}} if filter_obj.tag is not None else {})}
        panCore.logging.info(f"\tgot info for App-ID group {filter_obj.name}. Posting to SCM... (group {filterNum}/{filterCount}")
        submission = {
            'devData': devData,
            'thingName': filter_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/application-filters",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        filterNum += 1
    runJobs(jobs)

def postService(source, destination):
    panCore.logging.info(f"\tRetrieving service objects from source: {source}")
    services = panos.objects.ServiceObject().refreshall(source)
    svcCount = len(services)
    panCore.logging.info(f"\tRetrieved {svcCount} groups.")
    serviceNum = 1
    jobs = []
    for svc_obj in services:
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
        panCore.logging.info(f"\tgot info for service object {svc_obj.name}. Posting to SCM... (Service {serviceNum}/{svcCount})")
        submission = {
            'devData': devData,
            'thingName': svc_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/services",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        serviceNum += 1
    runJobs(jobs)

def postServiceGroup(source, destination):
    panCore.logging.info(f"Retrieving service objects from source: {source}")
    serviceGroups = panos.objects.ServiceGroup().refreshall(source)
    grpCount = len(serviceGroups)
    panCore.logging.info(f"\tRetrieved {grpCount} service objects.")
    grpNum = 1
    jobs = []
    for grp_obj in serviceGroups:
        devData = {'name': grp_obj.name,
                   **({'members': grp_obj.value} if grp_obj.value is not None else {}),
                   **({'tag': grp_obj.tag} if grp_obj.tag is not None else {})
                   }
        panCore.logging.info(f"\tgot info for service group {grp_obj.name}. Posting to SCM... (Service {grpNum}/{grpCount})")
        submission = {
            'devData': devData,
            'thingName': grp_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/service-groups",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        grpNum += 1
    runJobs(jobs)

def postURLs(source, destination):
    panCore.logging.info(f"Retrieving custom URL objects from source: {source}")
    URLs = panos.objects.CustomUrlCategory().refreshall(source)
    URL_Count = len(URLs)
    panCore.logging.info(f"\tRetrieved {URL_Count} URL objects.")
    URL_Num = 1
    jobs = []
    for url_obj in URLs:
        devData = {'name': url_obj.name,
                   'type': url_obj.type,
                   **({'description': url_obj.description} if url_obj.description is not None else {}),
                   **({'list': url_obj.url_value} if url_obj.url_value is not None else {})
                   }
        panCore.logging.info(f"\tgot info for custom URL objects {url_obj.name}. Posting to SCM... (URL {URL_Num}/{URL_Count})")
        submission = {
            'devData': devData,
            'thingName': url_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/url-categories",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        URL_Num += 1
    runJobs(jobs)

def postDynamicUserGroups(source, destination):
    panCore.logging.info(f"Retrieving dynamic user groups from source: {source}")
    groups = panos.objects.DynamicUserGroup().refreshall(source)
    grpCount = len(groups)
    panCore.logging.info(f"\tRetrieved {grpCount} dynamic user groups.")
    grpNum = 1
    jobs = []
    for grp_obj in groups:
        xmlData = panCore.xmlToLXML(pano_obj.xapi.get(grp_obj.xpath()))
        if xmlData.find('.//disable-override').text == 'yes':
            panCore.logging.error(f"Disable override set on {grp_obj.name} but not supported in SCM as overrides do not exist in SCM"
                                  f"Investigate please.")
        devData = {'name': grp_obj.name,
                   **({'description': grp_obj.description} if grp_obj.description is not None else {}),
                   **({'filter': grp_obj.filter} if grp_obj.filter is not None else {}),
                   **({'tag': grp_obj.tag} if grp_obj.tag is not None else {})
                   }
        panCore.logging.info(f"\tgot info for custom URL objects {grp_obj.name}. Posting to SCM... (URL {grpNum}/{grpCount})")
        submission = {
            'devData': devData,
            'thingName': grp_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/dynamic-user-groups",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        grpNum += 1
    runJobs(jobs)

def postEDLs(source, destination):
    panCore.logging.info(f"\tRetrieving EDLs from source: {source}")
    EDLs = panos.objects.Edl().refreshall(source)
    edlCount = len(EDLs)
    panCore.logging.info(f"\t\tRetrieved {edlCount} EDLs.")
    edlNum = 1
    jobs = []
    for edl_obj in EDLs:
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
        panCore.logging.info(f"\t\tgot info for EDL {edl_obj.name}. Posting to SCM... (EDL {edlNum}/{edlCount})")
        submission = {
            'devData': devData,
            'thingName': edl_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/external-dynamic-lists",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        edlNum += 1
    runJobs(jobs)

def postSchedules(source, destination):
    panCore.logging.info(f"\tRetrieving schedule objects from source: {source}")
    schedules = panos.objects.ScheduleObject().refreshall(source)
    schedCount = len(schedules)
    panCore.logging.info(f"\t\tRetrieved {schedCount} schedule objects.")
    schedNum = 1
    jobs = []
    for sched_obj in schedules:
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
        panCore.logging.info(f"\t\tgot info for schedule {sched_obj.name}. Posting to SCM... (Schedule {schedNum}/{schedCount})")
        submission = {
            'devData': devData,
            'thingName': sched_obj.name,
            'headers': {'Content-Type': 'application/json'},
            'endpoint': "/schedules",
            'params': {'folder': destination}}
        jobs.append(threading.Thread(target=postThing, args=(submission,)))
        schedNum += 1
    runJobs(jobs)
def postSecurityRules(rule_obj, context, destination, logDest='Cortex Data Lake'):
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
               **({'negate_destination': rule_obj.negate_destination} if rule_obj.negate_destination is not None else {}),
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
        'headers': {'Content-Type': 'application/json'},
        'endpoint': "/security-rules",
        'params': {'folder': destination,
                   'position': context}}
    scmErorrs = postThing(submission)
    return scmErorrs

def processRulebasePolicies(ruleBase, context, destination, logDest='Cortex Data Lake'):
    # HTTP post to SCM to create security policy in specified Pre- or Post- context in destination folder.
    ruleNum = 1
    ruleCount = len(ruleBase.children)
    panCore.logging.info(f"\t\tRetrieved {ruleCount} policies.")
    jobs = []
    for rule_obj in ruleBase.children:
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
            jobs.append(Thread(target=postSecurityRules, args=(rule_obj, context, destination, logDest)))
        ruleNum += 1
    runJobs(jobs)


def postThing(submission):
    devData = submission['devData']
    thingName = submission['thingName']
    headers = submission['headers']
    endpoint = submission['endpoint']
    params = submission['params']
    headers['Authorization'] = f"Bearer {panCore.scmToken}"
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
                panCore.logging.error(f"\t\tReceived expired oAuth token. Investigate below HTTP response:\n"
                                      f"\t\t{resp}")
            else:
                headers['Authorization'] = f"Bearer {panCore.scmToken}"
    response = requests.request("POST", panCore.scmConfURL + endpoint, headers=headers, data=json.dumps(devData), params=params)
    scmErrors = {
        'otherError': {},
        'alreadyExists': [],
        'invalidReference': {},
        'nonErrorResponse': {}
    }
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



def runJobs(jobs):
    # Various functions build a list of jobs/threads. This function releases them in a
    # controlled fashion to avoid overloading the SCM API and triggering its flood protections.
    activeThreadsBefore = threading.active_count()
    jobsDone = []
    jobCount = len(jobs)
    i = 1
    for job in jobs:
        panCore.logging.info(f'Submitting job {i}/{jobCount}. Current thread count: {threading.active_count()}')
        while threading.active_count() >= activeThreadsBefore + args[0].limitThreads:
            panCore.logging.info(f"\t\t****** WAIT STATE ****\n"
                                 f"\t\tWaiting for other threads to finish... Current thread count: {threading.active_count()}")
            time.sleep(1)
        jobsDone.append(job)
        job.start()
        i += 1
    for job in jobsDone:
        # panCore.logging.info(f'cleaning up after {job}')
        # Probably a waste of time, but clean up the threads and ensure everything terminated cleanly, just in case...
        job.join()



def postAntivirusWildfire(source, destination):
    print("SCM not implemented yet...")


def getThingListFromSCM(thingType, folder, headers, limit=200, offset=0):
    params = {'folder': folder,
              'limit': limit,
              'offset': offset}
    return requests.request("GET", f"{panCore.scmConfURL}/{thingType}", headers=headers, data={}, params=params)

def getRuleListFromSCM(ruleType, folder, headers, position='pre', limit=200, offset=0):
    params = {'folder': folder,
              'limit': limit,
              'offset': offset,
              'position': position}
    return requests.request("GET", f"{panCore.scmConfURL}/{ruleType}", headers=headers, data={}, params=params)


def getThingFromSCM_byName(thingType, folder, headers, name=None, limit=200, offset=0):
    if name is not None:
        params = {
            'name': name,
            'folder': folder,
            'limit': limit,
            'offset': offset}
    return requests.request("GET", f"{panCore.scmConfURL}/{thingType}", headers=headers, data={}, params=params)

def getThingFromSCM_byID(thingType, id, headers):
    return requests.request("GET", f"{panCore.scmConfURL}/{thingType}/{id}", headers=headers, data={})

def deleteThingFromSCM_byID(argDict):
    thingType = argDict['thingType']
    idNum = argDict['idNum']
    headers = argDict['headers']
    #panCore.logging.info(f"deleting SCM object {idNum} ({thingType})")
    resp = requests.request("DELETE", f"{panCore.scmConfURL}/{thingType}/{idNum}", headers=headers, data={})
    if resp.status_code == 409:
        panCore.logging.error(f"Attempt to delete a {thingType} failed as it is still in use.")
    if resp.status_code == 400:
        if resp.json()['_errors'][0]['message'] == 'Failed to find obj-uuid for command get':
            panCore.logging.warning(f'Attempted to delete {thingType} which does not exist. {idNum}')
    return resp

def getKey():
    global headers, tokenExpiryTime
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    return headers, tokenExpiryTime

def resetSCM():
    headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)
    thingsToReset = {
        'securityRules': (True, 'security-rules'),
        'appOverrideRules': (True, 'app-override-rules'),
        'authRules': (True, 'authentication-rules'),
        'decryptRules': (True, 'decryption-rules'),
        'natRules': (False, 'unavailable'),
        'pbfRules': (False, 'unavailable'),
        'scheduleObjects': (True, 'schedules'),
        'edlObjects': (True, 'external-dynamic-lists'),
        'dynamicUserGrpObjects': (True, 'dynamic-user-groups'),
        'URL_Objects': (True, 'url-categories'),
        'serviceGroupObjects': (True, 'service-groups'),
        'serviceObjects': (True, 'services'),
        'appFilterObjects': (True, 'application-filters'),
        'appGroupObjects': (True, 'application-groups'),
        'appObjects': (True, 'applications'),
        'regionObjects': (True, 'regions'),
        'addressGroupObjects': (True, 'address-groups'),
        'addressObjects': (True, 'addresses'),
        'tagObjects': (True, 'tags')}
    foldersToReset = ['All', 'Shared']
    for thing in thingsToReset.keys():
        panCore.logging.info(f'Starting to process {thing}')
        thingType = thingsToReset[thing][1]
        if thingsToReset[thing][0]:
            if thing.endswith('Objects'):
                for folder in foldersToReset:
                    panCore.logging.info(f"\tPurging {thingType} from {folder}")
                    i = 1
                    deletionDict = {'failedToProgress': 0}
                    while i < 101:  # avoid endless loop. 200 items * 100 = delete up to 20k items
                        if deletionDict['failedToProgress'] == 5:
                            panCore.logging.error(
                                'Failed to delete anything for the previous 5 "While" loops. Breaking.')
                            break
                        if time.time() >= tokenExpiryTime:
                            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass,
                                                                            panCore.scmTSG)
                            if tokenExpiryTime <= time.time():
                                panCore.logging.error("Error: Received expired token. Investigate.")
                        thingList = getThingListFromSCM(thingsToReset[thing][1], folder, headers).json()['data']
                        deletionDict[i] = {'toDelete': len(thingList),
                                           'deleted': 0}
                        if i > 2 and len(thingList) < 200:
                            if deletionDict[i]['toDelete'] == deletionDict[i - 1]['toDelete']:
                                deletionDict['failedToProgress'] += 1
                        for item in thingList:
                            if 'id' not in item.keys() or 'snippet' in item.keys():
                                # Avoid trying to delete snippets where id #, name, and folder are only
                                # keys or predefined objects which have no ID number.
                                pass
                            else:
                                panCore.logging.info(f"\t\t\tDeleting {thingType} {item['name']}, from {folder}")
                                argDict = {
                                    'thingType': thingType,
                                    'idNum': item['id'],
                                    'headers': headers
                                }
                                x = threading.Thread(target=deleteThingFromSCM_byID, args=(argDict,))
                                x.start()
                                deletionDict[i]['deleted'] += 1
                        panCore.logging.info(f"\t\tWhile Loop iteration {i} statistics:\n"
                                             f"\t\t{deletionDict}")
                        if deletionDict[i]['deleted'] == 0:
                            print("\t\tNo items deleted during previous 'For' loop. Breaking from 'While' loop...")
                            break
                        i += 1
            elif thing.endswith('Rules'):
                for folder in foldersToReset:
                    panCore.logging.info(f"\tPurging {thingType} from {folder}")
                    i = 1
                    deletionDict = {'failedToProgressPre': 0,
                                    'failedToProgressPost': 0}
                    while i < 101:  # avoid endless loop. 200 items * 100 = delete up to 20k items.
                        if deletionDict['failedToProgressPre'] == 5 and deletionDict['failedToProgressPost'] == 5:
                            panCore.logging.error(
                                'Failed to delete anything for the previous 5 "While" loops. Breaking.')
                            break
                        if time.time() >= tokenExpiryTime:
                            headers, tokenExpiryTime = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass,
                                                                            panCore.scmTSG)
                            if tokenExpiryTime <= time.time():
                                panCore.logging.error("Error: Received expired token. Investigate.")
                        thingList = getRuleListFromSCM(thingType, folder, headers, 'pre').json()['data']
                        deletionDict[i] = {'toDeletePre': len(thingList),
                                           'deleted': 0}
                        if i > 2 and len(thingList) < 200:
                            if deletionDict[i]['toDeletePre'] == deletionDict[i - 1]['toDeletePre']:
                                deletionDict['failedToProgressPre'] += 1
                        for item in thingList:
                            if len(item.keys()) <= 3 or 'id' not in item.keys() or 'snippet' in item.keys():
                                # Avoid trying to delete snippets where id #, name, and folder are only
                                # keys or predefined objects which have no ID number.
                                pass
                            else:
                                panCore.logging.info(f"\t\t\tDeleting {item['name']}, from {item['folder']}")
                                argDict = {
                                    'thingType': thingType,
                                    'idNum': item['id'],
                                    'headers': headers
                                }
                                x = threading.Thread(target=deleteThingFromSCM_byID, args=(argDict,))
                                x.start()
                                deletionDict[i]['deleted'] += 1
                        thingList = getRuleListFromSCM(thingType, folder, headers, 'post').json()['data']
                        deletionDict[i]['toDeletePost'] = len(thingList)
                        for item in thingList:
                            if 'id' not in item.keys() or 'snippet' in item.keys():
                                # Avoid trying to delete snippets where id #, name, and folder are only
                                # keys or predefined objects which have no ID number.
                                pass
                            else:
                                panCore.logging.info(f"\t\t\tDeleting {item['name']}, from {item['folder']}")
                                argDict = {
                                    'thingType': thingType,
                                    'idNum': item['id'],
                                    'headers': headers
                                }
                                x = threading.Thread(target=deleteThingFromSCM_byID, args=(argDict,))
                                x.start()
                        panCore.logging.info(f"\t\tWhile Loop iteration {i} statistics:\n"
                                             f"\t\t{deletionDict}")
                        if deletionDict[i]['deleted'] == 0:
                            print(
                                "\t\tNo items deleted from 'pre' or 'post' rulbases during 'For' loop. Breaking from 'While' loop...")
                            break
                        i += 1

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
    parser.add_argument('-T', '--limitThreads', help="Limit number of threads to prevent overwhelming API destination", default=75)
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
    if args[0].noShared:
        pass
    else:
        postAddressGroups(pano_obj, args[0].sharedFolder)
    for dgPair in args[0].deviceGroups.split(","):
        postAddressGroups(pano_obj.find(dgPair.split(":")[0]), dgPair.split(":")[1])

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