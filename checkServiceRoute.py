from pancore import panCore
fwCount = len(firewalls)
fwNum = 0
for fw_obj in firewalls:
    fwNum += 1
    if fw_obj.state.connected == False:
        print(f"\t> Device Offline: {fw_obj.serial} ({fwNum}/{fwCount})")
        continue
    hostname = fw_obj.show_system_info()['system']['hostname']
    print(f"Checking {hostname} ({fw_obj.serial}) for service route ({fwNum}/{fwCount})")
    xmlData = panCore.xmlToLXML(fw_obj.xapi.get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/route/service"))
    if len(xmlData.findall('.//entry')) > 0:
        print(f"{hostname} ({fw_obj.serial}) has {len(xmlData.findall('.//entry'))} service routes")
        for serviceRoute in xmlData.findall('.//entry'):
            print(f"\t{serviceRoute.attrib['name']} ")
            for child in serviceRoute[0].getchildren():
                print(f"\t\t{child.tag} = {child.text}")


