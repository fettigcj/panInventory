from pancore import panCore
import requests, sys, time, zipfile, json, argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


parser = argparse.ArgumentParser(
    prog="PanInventory",
    description="Audit Panorama & connected firewalls to generate reports on system state & health")
    #epilog="Text")

parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='BPA_Generator.log')
parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument('-z', '--zipfile', help="Disable zip file", default="true", choices=['true', 'false'])
# NOTE bpa API expects STRINGS 'true' or 'false' so we CAN NOT use default=True and 'store_false' like below.
parser.add_argument('-e', '--extractzip', help="Disable extraction of ZIP file", default=True, action='store_false')
parser.add_argument('-k', '--key', help="BPA API Key")
args = parser.parse_known_args()

def stripHiddenChars(stringToStrip):
    stripChars = ['\r\n', '\n', '\r', '\t', '\0', '\x0B', '\\n', 'b\'', '\'']
    for stripChar in stripChars:
        if stripChar in stringToStrip:
            stringToStrip = stringToStrip.replace(stripChar, "")
    return stringToStrip


def getZip(taskID, bpaKey):
    return (requests.get(
        url="https://bpa.paloaltonetworks.com/api/v1/results/{0}/download/".format(taskID),
        headers={'Authorization': "Token {0}".format(bpaKey)},
        verify=False))


def getResults(taskID, bpaKey):
    return (requests.get(
        url="https://bpa.paloaltonetworks.com/api/v1/results/{0}/".format(taskID),
        headers={'Authorization': "Token {0}".format(bpaKey)},
        verify=False))


panCore.startLogging(args[0].logfile)
#panCore.initXLSX(args[0].workbookname)
panCore.configStart(headless=args[0].headless, configStorage=args[0].conffile)
if hasattr(panCore, 'panUser'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, 'panKey'):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    panCore.logging.critical("Found neither username/password nor API key. Exiting.")
    sys.exit()


hostname = pano_obj.hostname
tempTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())

panCore.logging.info(f"Starting to gather Panorama information for analysis by the BPA portal at {tempTime}")
runningConf = stripHiddenChars(str(panCore.ET2.tostring(pano_obj.op('show config running'))))
sysInfo = stripHiddenChars(str(panCore.ET2.tostring(pano_obj.op('show system info'))))
sysClock = stripHiddenChars(str(panCore.ET2.tostring(pano_obj.op('show clock'))))
licenseInfo = stripHiddenChars(str(panCore.ET2.tostring(pano_obj.op('request license info'))))

tempTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
panCore.logging.info(f"Sending Panorama information to BPA API for analysis at {tempTime}")
taskResponse = requests.post(
    url="https://bpa.paloaltonetworks.com/api/v1/create/",
    headers={'Authorization': "Token {0}".format(args[0].key)},
    verify=False,
    files={'xml': (None, runningConf),
           'system_info': (None, sysInfo),
           'license_info': (None, licenseInfo),
           'system_time': (None, sysClock),
           'generate_zip_bundle': (None, args[0].zipfile)
           })

if taskResponse.status_code != 202:
    finishTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
    panCore.logging.info(f"Submitting to generate BPA failed at {finishTime}. Response content below:")
    panCore.logging.info("HTTP Response Code: {0}".format(taskResponse.status_code))
    panCore.logging.info("HTTP Response content:")
    panCore.logging.info(taskResponse.content)
    sys.exit("Failed to retrieve task ID when trying to generate BPA")
else:
    taskID = (taskResponse.json())['task_id']
tempTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
panCore.logging.info(f"Finished submitting data to generate BPA at {tempTime}. Waiting 3 minutes to retrieve results.")
time.sleep(180)

bpaResults = getResults(taskID, args[0].key)
retryCount = 1
while (bpaResults.status_code == 202) and ("processing" in str(bpaResults.content)):
    tempTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
    if retryCount == 10:
        panCore.logging.info(f"BPA not completed after 10 retries. Giving up at {tempTime}.")
        sys.exit("BPA not completed after 10 retries")
    panCore.logging.info(f"BPA is still being generated as of {tempTime}. Waiting another minute (Retry number: {retryCount})")
    time.sleep(60)
    retryCount = retryCount + 1
    bpaResults = getResults(taskID, args[0].key)

tempTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
panCore.logging.info(f"Finished retrieving raw BPA data from PANW BPA portal. Writing it to disk at {tempTime}")

bpaDict = bpaResults.json()

file = open("bpa_whole.json", "w", encoding="utf-8")
file.write(json.dumps(bpaDict, indent=4))
file.close()

file = open("bpaAdoption.json", "w", encoding="utf-8")
file.write(json.dumps(bpaDict['results']['adoption'], indent=4))
file.close()

file = open("bpaAdoptionSummary.json", "w", encoding="utf-8")
file.write(json.dumps(bpaDict['results']['adoption_summary'], indent=4))
file.close()

file = open("bpaAdoptionTotals.json", "w", encoding="utf-8")
file.write(json.dumps(bpaDict['results']['adoption_grand_totals'], indent=4))
file.close()

file = open("bpaAdoptionTrend.json", "w", encoding="utf-8")
file.write(json.dumps(bpaDict['results']['adoption_trend'], indent=4))
file.close()

file = open("bpa.json", "w", encoding="utf-8")
file.write(json.dumps(bpaDict['results']['bpa'], indent=4))
file.close()

file = open("bpaChecksTotal.json", "w", encoding="utf-8")
file.write(json.dumps(bpaDict['results']['bpa_checks_grand_total'], indent=4))
file.close()

if args[0].zipfile == "true":
    tempTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
    panCore.logging.info(f"Downloading BPA ZIP from Palo Alto Networks BPA Portal at {tempTime}")
    bpaReport = getZip(taskID, args[0].key)
    retryCount = 1
    while (bpaReport.status_code == 404) and (args[0].zipfile == "true"):
        if retryCount == 12:
            finishTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
            panCore.logging.info(f"Time to give up. 12 retries have failed to download the BPA Zip. Terminating retries at {finishTime}.")
            sys.exit("ZIP download failed after 12 retries")
        tempTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
        panCore.logging.info(f"Report not ready or otherwise not found during download attempt {retryCount} at {tempTime}")
        panCore.logging.info("Waiting 5 minutes to try again")
        time.sleep(300)
        bpaReport = getZip(taskID, args[0].key)
        retryCount = retryCount + 1

    fileName = "BPA_" + hostname + "_" + tempTime + ".zip"
    with open(fileName, 'wb') as fd:
        for chunk in bpaReport.iter_content(chunk_size=128):
            fd.write(chunk)

    if args[0].extractzip == True:
        zipData = zipfile.ZipFile(fileName)
        zipInfos = zipData.infolist()
        for zipInfo in zipInfos:
            fileExt = (zipInfo.filename).split(".")[-1]
            zipInfo.filename = "bpa.{0}".format(fileExt)
            zipData.extract(zipInfo)
        zipData.close()

finishTime = time.strftime("%Y-%m-%d_%H-%M", time.localtime())
panCore.logging.info(f"Finished all processing at {finishTime}")