from pancore import panCore

def stripHiddenChars(stringToStrip):
    stripChars = ['\r\n', '\n', '\r', '\t', '\0', '\x0B', '\\n', 'b\'', '\'', '                  ','        ','      ']
    for stripChar in stripChars:
        if stripChar in stringToStrip:
            stringToStrip = stringToStrip.replace(stripChar, "")
    return stringToStrip

panCore.configStart()
pano_obj, deviceGroups, firewalls = panCore.buildPano_obj()

deletePaths = ["config/mgt-config/users",
               "config/mgt-config/password-complexity",
               "config/devices/entry[@name='localhost.localdomain']/deviceconfig",
               "config/devices/entry[@name='localhost.localdomain']/log-collector",
               "config/devices/entry[@name='localhost.localdomain']/log-collector-group",
               "config/panorama/server-profile",
               "config/panorama/log-settings"]


runningConf = panCore.xmlToLXML(pano_obj.op('show config running'))

for deletePath in deletePaths:
    deleteMe = runningConf.find('.//{0}'.format(deletePath))
    if deleteMe is not None:
        deleteMe.getparent().remove(deleteMe)

for importParent in runningConf.xpath("/response/result/config")[0].getchildren():
    if importParent.tag != "readonly":
        for importItem in importParent.getchildren():
            importPath = "/config/{0}".format(importParent.tag)
            print("Importing {0} into {1}".format(importItem.tag, importPath))
            importXML = stripHiddenChars(str(panCore.ET.tostring(importItem)))
            pano_obj.xapi.set(xpath=importPath,element=importXML)
