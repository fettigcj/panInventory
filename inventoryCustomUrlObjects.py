from pancore import panCore, panExcelStyles
import panos, sys, argparse, xlsxwriter


def checkQosRules(xpath):
    lxmlData = panCore.xmlToLXML(pano_obj.xapi.get(xpath))
    # Derive a simple ruleBase label from the xpath for reporting
    ruleBase = 'PreRulebase' if '/pre-rulebase/' in xpath else ('PostRulebase' if '/post-rulebase/' in xpath else 'Rulebase')
    rules = lxmlData.xpath('/response/result/rules/entry')
    panCore.logging.info(f"\t\tFound {len(rules)} QOS rules in {xpath}")
    for rule in rules:
        ruleName = rule.attrib['name']
        for category in rule.xpath('./category/member'):
            urlCategory = category.text
            if urlCategory == 'any':
                panCore.logging.info(f"\t\t\tRule '{ruleName}' uses 'any' URL category. Skipping...")
                continue
            elif urlCategory not in urlCategoryData.keys():
                panCore.logging.warning(f"  URL category '{urlCategory}' not found in the urlCategoryData dictionary. Skipping...")
                continue
            usage_type_value = f"{ruleBase}-QosRule"
            if urlCategoryData[urlCategory]['usage'] == 'NotDocumented':
                urlCategoryData[urlCategory]['usage'] = {1: {
                    'usageType': usage_type_value,
                    'usedBy': ruleName,
                    'parent': parentName,
                }}
            else:
                usageCount = len(urlCategoryData[urlCategory]['usage']) + 1
                urlCategoryData[urlCategory]['usage'][usageCount] = {
                    'usageType': usage_type_value,
                    'usedBy': ruleName,
                    'parent': parentName,
                }


if __name__ == "__main__":
    # Initialize CLI, logging, config, and Panorama connection
    parser = argparse.ArgumentParser(
        prog="PanSecurityGroupsAndProfiles",
        description="Audit Panorama report back on security profiles and security profile groups.")
    parser.add_argument('-l', '--headless', help="Operate in headless mode, without user input (Will disable panCore's ability to prompt for credentials)", default=False, action='store_true')
    parser.add_argument('-L', '--logfile', help="Log file to store log output to.", default='groupsAndProfiles.log')
    parser.add_argument('-c', '--conffile', help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
    parser.add_argument('-w', '--workbookname', help="Name of Excel workbook to be generated", default='SecurityProfilesAndGroups.xlsx')
    parser.add_argument('--urlSource', dest='urlSource', choices=['panw', 'brightcloud'], default='panw', help="Select predefined URL category source: 'panw' or 'brightcloud'. Default: panw")
    args, _ = parser.parse_known_args()
    panCore.startLogging(args.logfile)
    panCore.configStart(headless=args.headless, configStorage=args.conffile)
    if hasattr(panCore, 'panUser'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
    elif hasattr(panCore, 'panKey'):
        pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
    else:
        panCore.logging.critical("Found neither username/password nor API key. Exiting.")
        sys.exit()

    urlCategoryData = {}
    for parent_obj in [pano_obj] + deviceGroups:
        parentName = parent_obj.hostname if isinstance(parent_obj, panos.panorama.Panorama) else parent_obj.name
        panCore.logging.info(f"Gathering URL category data for: {parentName}")
        customURLCategories = panos.objects.CustomUrlCategory().refreshall(parent_obj)
        for url_obj in customURLCategories:
            if url_obj.name not in urlCategoryData.keys():
                urlCategoryData[url_obj.name] = {'usage': 'NotDocumented', 'configs': {1: {'name': url_obj.name, 'description': url_obj.description, 'url_value': url_obj.url_value, 'type': url_obj.type, 'xpath': url_obj.xpath()}}}
            else:
                nextNum = len(urlCategoryData[url_obj.name]['configs']) + 1
                urlCategoryData[url_obj.name]['configs'][nextNum] = {'name': url_obj.name, 'description': url_obj.description, 'url_value': url_obj.url_value, 'type': url_obj.type, 'xpath': url_obj.xpath()}
        externalDynamicLists = panos.objects.Edl().refreshall(parent_obj)
        for edl_obj in externalDynamicLists:
            if edl_obj.name not in urlCategoryData:
                urlCategoryData[edl_obj.name] = {1: {'name': edl_obj.name, 'description': edl_obj.description, 'url_value': edl_obj.source, 'type': 'externalDynamicList'}, 'xpath': edl_obj.xpath(), 'usage': 'NotDocumented'}
            else:
                nextNum = len(urlCategoryData[edl_obj.name]) + 1
                urlCategoryData[edl_obj.name][nextNum] = {'name': edl_obj.name, 'description': edl_obj.description, 'url_value': edl_obj.source, 'type': 'externalDynamicList', 'xpath': edl_obj.xpath()}

    for parent_obj in [pano_obj] + deviceGroups:
        # Use pan os python SDK to walk all rule types (Except QOS since it doesn't exist in SDK) and retrieve all URL category usages
        parentName = parent_obj.hostname if isinstance(parent_obj, panos.panorama.Panorama) else parent_obj.name
        panCore.logging.info(f"\tProcessing URL category usage for: {parentName}")
        # Consolidate rulebase fetching with ternary for None assignment if empty
        preRulebase_result = panos.policies.PreRulebase().refreshall(parent_obj)
        preRulebase = preRulebase_result[0] if (isinstance(preRulebase_result, list) and len(preRulebase_result) == 1) else None

        postRulebase_result = panos.policies.PostRulebase().refreshall(parent_obj)
        postRulebase = postRulebase_result[0] if (isinstance(postRulebase_result, list) and len(postRulebase_result) == 1) else None

        # Only attempt refreshall if the rulebase is not None
        preRules_security = panos.policies.SecurityRule().refreshall(preRulebase) if preRulebase else []
        postRules_security = panos.policies.SecurityRule().refreshall(postRulebase) if postRulebase else []
        preRules_decryption = panos.policies.DecryptionRule().refreshall(preRulebase) if preRulebase else []
        postRules_decryption = panos.policies.DecryptionRule().refreshall(postRulebase) if postRulebase else []
        preRules_authentication = panos.policies.AuthenticationRule().refreshall(preRulebase) if preRulebase else []
        postRules_authentication = panos.policies.AuthenticationRule().refreshall(postRulebase) if postRulebase else []

        # Count rules by type
        securityPre, securityPost = len(preRules_security), len(postRules_security)
        decryptionPre, decryptionPost = len(preRules_decryption), len(postRules_decryption)
        authenticationPre, authenticationPost = len(preRules_authentication), len(postRules_authentication)
        panCore.logging.info(f"\t\tFound (Pre, Post) {securityPre}, {securityPost} security and {decryptionPre}, {decryptionPost} decryption and {authenticationPre}, {authenticationPost} authentication rules")

        # Populate the rules list (preserving original functionality for downstream code)
        rules = []
        rules.extend(preRules_security or [])
        rules.extend(postRules_security or [])
        rules.extend(preRules_decryption or [])
        rules.extend(postRules_decryption or [])
        rules.extend(preRules_authentication or [])
        rules.extend(postRules_authentication or [])

        for rule_obj in rules:
            ruleName = rule_obj.name
            ruleType = type(rule_obj).__name__
            ruleBase = type(rule_obj.parent).__name__
            container_obj = (rule_obj.parent).parent
            ruleParent = "PanoramaShared" if isinstance(container_obj, panos.panorama.Panorama)  else container_obj.name
            if rule_obj.category and rule_obj.category != ['any']:
                for category in rule_obj.category:
                    if category not in urlCategoryData.keys():
                        panCore.logging.warning(f"  URL category '{category}' not found in the urlCategoryData dictionary. Skipping...")
                        continue
                    usage_type_value = f"{ruleBase}-{ruleType}"
                    if urlCategoryData[category]['usage'] == 'NotDocumented':
                        urlCategoryData[category]['usage'] = {1: {
                            'usageType': usage_type_value,
                            'usedBy': ruleName,
                            'parent': ruleParent,
                        }}
                    else:
                        usageCount = len(urlCategoryData[category]['usage']) + 1
                        urlCategoryData[category]['usage'][usageCount] = {
                            'usageType': usage_type_value,
                            'usedBy': ruleName,
                            'parent': ruleParent,
                        }
            else:
                #panCore.logging.info(f"  Rule '{ruleName}' uses 'any' URL category. Skipping...")
                continue
        # Resort to xapi bullshit to get the URL category usages the SDK can't retrieve due to unimplemented object types.
        # URL filtering profiles:
        if isinstance(parent_obj, panos.panorama.Panorama):
            xpath = "/config/shared/profiles/url-filtering"
        else:
            xpath = parent_obj.xpath() + "/profiles/url-filtering"
        urlProfiles = panCore.xmlToLXML(pano_obj.xapi.get(xpath))
        for urlProfile in urlProfiles.xpath('/response/result/url-filtering/entry'):
            profileName = urlProfile.attrib['name']
            panCore.logging.info(f"\t\tFound URL filtering profile: {profileName}")
            for usage in ['alert', 'allow', 'block', 'continue', 'override']:
                for category in urlProfile.xpath(f'./{usage}/member'):
                    if category.text in urlCategoryData.keys():
                        if urlCategoryData[category.text]['usage'] == 'NotDocumented':
                            urlCategoryData[category.text]['usage'] = {1: {
                                'usageType': 'URL Filtering Profile (Site Access)',
                                'usedBy': f"Site access action: {usage}",
                                'parent': parentName,
                            }}
                        else:
                            usageCount = len(urlCategoryData[category.text]['usage']) + 1
                            urlCategoryData[category.text]['usage'][usageCount] = {
                                'usageType': 'URL Filtering Profile (Site Access)',
                                'usedBy': f"Action: {usage}",
                                'parent': parentName,
                            }
                if usage != "override":
                    for category in urlProfile.xpath(f'./credential-enforcement/{usage}/member'):
                        if category.text in urlCategoryData.keys():
                            if urlCategoryData[category.text]['usage'] == 'NotDocumented':
                                urlCategoryData[category.text]['usage'] = {1: {
                                    'usageType': 'URL Filtering Profile (Credential Enforcement)',
                                    'usedBy': f"Action: {usage}",
                                    'parent': parentName,
                                }}
                            else:
                                usageCount = len(urlCategoryData[category.text]['usage']) + 1
                                urlCategoryData[category.text]['usage'][usageCount] = {
                                    'usageType': 'URL Filtering Profile (Credential Enforcement)',
                                    'usedBy': f"Action: {usage}",
                                    'parent': parentName,
                                }
        # QOS Rules:
        if isinstance(parent_obj, panos.panorama.Panorama):
            checkQosRules("/config/shared/pre-rulebase/qos/rules")
            checkQosRules("/config/shared/post-rulebase/qos/rules")
        else:
            checkQosRules(parent_obj.xpath() + "/pre-rulebase/qos/rules")
            checkQosRules(parent_obj.xpath() + "/post-rulebase/qos/rules")

    # --------------------
    # Build Excel workbook CustomUrlObjectDetails.xlsx
    # --------------------
    try:
        workbook = xlsxwriter.Workbook('CustomUrlObjectDetails.xlsx')
        fmt_header = workbook.add_format(panExcelStyles.styles['rowHeader'])
        fmt_label = workbook.add_format(panExcelStyles.styles['label'])
        fmt_black = workbook.add_format(panExcelStyles.styles['blackBox'])
        fmt_normal = workbook.add_format(panExcelStyles.styles['normalText'])

        # Helper: extract configs list from a record supporting both shapes (primary 'configs' dict or numeric keys)
        def get_configs_list(record: dict):
            if not isinstance(record, dict):
                return []
            if 'configs' in record and isinstance(record['configs'], dict):
                # Sort by numeric key order if possible
                items = []
                for k in sorted(record['configs'].keys(), key=lambda x: int(x) if str(x).isdigit() else str(x)):
                    items.append(record['configs'][k])
                return items
            # Fallback for legacy EDL mapping in this script
            numeric_keys = [k for k in record.keys() if isinstance(k, int) or (isinstance(k, str) and str(k).isdigit())]
            if numeric_keys:
                cfgs = []
                for k in sorted(numeric_keys, key=lambda x: int(x)):
                    entry = record.get(k)
                    if isinstance(entry, dict):
                        # Attach xpath/type from parent record if missing in entry
                        if 'xpath' in record and 'xpath' not in entry:
                            entry = dict(entry)
                            entry['xpath'] = record['xpath']
                        cfgs.append(entry)
                return cfgs
            return []

        # Helper: extract usages list (empty list when NotDocumented)
        def get_usages_list(record: dict):
            usage_block = (record or {}).get('usage', 'NotDocumented')
            if usage_block == 'NotDocumented' or usage_block is None:
                return []
            if isinstance(usage_block, dict):
                items = []
                for k in sorted(usage_block.keys(), key=lambda x: int(x) if str(x).isdigit() else str(x)):
                    urec = usage_block[k]
                    if isinstance(urec, dict):
                        items.append(urec)
                return items
            return []

        # 1) Full Details worksheet + anchor map for Index
        ws_full = workbook.add_worksheet('full details')
        headers = ['customObjectName', 'configuration#', 'description', 'value', 'type', 'xpath', 'BLACKBOX', 'usage#', 'usageType', 'usedBy', 'parent']
        ws_full.write_row(0, 0, headers, fmt_header)
        # Track first-row anchors and simple stats for Index sheet
        anchor_row_map = {}
        object_stats = {}
        row = 1
        for object_name in sorted(urlCategoryData.keys()):
            record = urlCategoryData[object_name]
            configs = get_configs_list(record)
            usages = get_usages_list(record)
            # Save stats for Index
            config_count = len(configs)
            usage_count = len(usages)
            object_stats[object_name] = {
                'configCount': config_count,
                'usageCount': usage_count,
                'multiConfig': 'yes' if config_count > 1 else 'no',
            }
            # Remember the first row where this object starts
            if object_name not in anchor_row_map:
                anchor_row_map[object_name] = row
            max_rows = max(config_count, usage_count, 1)
            for i in range(max_rows):
                # Meta data: object name repeated each row
                ws_full.write(row, 0, object_name, fmt_normal)
                # Config side
                if i < len(configs):
                    cfg = configs[i] or {}
                    ws_full.write(row, 1, i+1, fmt_normal)
                    ws_full.write(row, 2, (cfg.get('description') or ''), fmt_normal if cfg.get('description') else fmt_black)
                    # Values as Python list literal
                    val = cfg.get('url_value')
                    if isinstance(val, (list, tuple, set)):
                        val_text = repr(list(val)) if len(val) > 0 else ''
                    else:
                        val_text = (str(val).strip() if val not in (None, '') else '')
                    ws_full.write(row, 3, val_text, fmt_normal if val_text != '' else fmt_black)
                    typ = cfg.get('type')
                    ws_full.write(row, 4, (typ if typ else ''), fmt_normal if typ else fmt_black)
                    xp = cfg.get('xpath')
                    ws_full.write(row, 5, (xp if xp else ''), fmt_normal if xp else fmt_black)
                else:
                    # No config for this row
                    ws_full.write(row, 1, '', fmt_black)
                    ws_full.write(row, 2, '', fmt_black)
                    ws_full.write(row, 3, '', fmt_black)
                    ws_full.write(row, 4, '', fmt_black)
                    ws_full.write(row, 5, '', fmt_black)
                # Separator BLACKBOX column
                ws_full.write(row, 6, '', fmt_black)
                # Usage side
                if i < len(usages):
                    use = usages[i] or {}
                    usage_type = use.get('usageType') or ''
                    used_by = use.get('usedBy') or use.get('usageDescription') or use.get('UsedBy') or ''
                    parent_val = use.get('parent') or ''
                    ws_full.write(row, 7, i+1, fmt_normal)
                    ws_full.write(row, 8, (usage_type if usage_type else ''), fmt_normal if usage_type else fmt_black)
                    ws_full.write(row, 9, (used_by if used_by else ''), fmt_normal if used_by else fmt_black)
                    ws_full.write(row, 10, (parent_val if parent_val else ''), fmt_normal if parent_val else fmt_black)
                else:
                    ws_full.write(row, 7, '', fmt_black)
                    ws_full.write(row, 8, '', fmt_black)
                    ws_full.write(row, 9, '', fmt_black)
                    ws_full.write(row, 10, '', fmt_black)
                row += 1
        # Freeze headers and set column widths for readability
        ws_full.freeze_panes(1, 0)
        ws_full.set_column(0, 0, 32)
        ws_full.set_column(1, 1, 14)
        ws_full.set_column(2, 2, 40)
        ws_full.set_column(3, 3, 60)
        ws_full.set_column(4, 4, 16)
        ws_full.set_column(5, 5, 80)
        ws_full.set_column(6, 6, 10)
        ws_full.set_column(7, 10, 40)
        # Build Index worksheet with hyperlinks into Full Details
        try:
            ws_index = workbook.add_worksheet('Index')
            index_headers = ['customObjectName', 'configCount', 'usageCount']
            ws_index.write_row(0, 0, index_headers, fmt_header)
            r_index = 1
            for name in sorted(anchor_row_map.keys()):
                stats = object_stats.get(name, {})
                anchor_row = anchor_row_map[name]
                # Internal link to the first row for this object on 'full details'
                link_target = f"internal:'full details'!A{anchor_row}"
                ws_index.write_url(r_index, 0, link_target, fmt_normal, name)
                ws_index.write(r_index, 1, stats.get('configCount', 0), fmt_normal)
                ws_index.write(r_index, 2, stats.get('usageCount', 0), fmt_normal)
                r_index += 1
            # Freeze and set widths
            ws_index.freeze_panes(1, 0)
            ws_index.set_column(0, 0, 40)
            ws_index.set_column(1, 2, 16)
            # Add AutoFilter table if there is at least one data row
            if r_index > 1:
                ws_index.add_table(0, 0, r_index - 1, 2, {
                    'style': 'Table Style Light 9',
                    'columns': [
                        {'header': 'customObjectName'},
                        {'header': 'configCount'},
                        {'header': 'usageCount'},
                    ],
                })
        except Exception:
            # Do not fail the report if Index cannot be created
            panCore.logging.debug('Index worksheet creation failed', exc_info=True)

        # 2) configs worksheet (all configurations with opposite count: usageCount)
        ws_configs = workbook.add_worksheet('configs')
        ws_configs.write_row(0, 0, ['customObjectName', 'configuration#', 'description', 'value', 'type', 'xpath', 'usageCount'], fmt_header)
        r = 1
        for object_name in sorted(urlCategoryData.keys()):
            record = urlCategoryData[object_name]
            cfgs = get_configs_list(record)
            usages = get_usages_list(record)
            usage_count = len(usages)
            if not cfgs:
                # Still write a marker row so the object appears in filters
                ws_configs.write(r, 0, object_name, fmt_normal)
                ws_configs.write(r, 1, '', fmt_black)
                ws_configs.write(r, 2, '', fmt_black)
                ws_configs.write(r, 3, '', fmt_black)
                ws_configs.write(r, 4, '', fmt_black)
                ws_configs.write(r, 5, '', fmt_black)
                ws_configs.write(r, 6, usage_count, fmt_normal)
                r += 1
            else:
                for idx, cfg in enumerate(cfgs, start=1):
                    ws_configs.write(r, 0, object_name, fmt_normal)
                    ws_configs.write(r, 1, idx, fmt_normal)
                    desc = (cfg or {}).get('description')
                    ws_configs.write(r, 2, (desc if desc else ''), fmt_normal if desc else fmt_black)
                    val = (cfg or {}).get('url_value')
                    if isinstance(val, (list, tuple, set)):
                        val_text = repr(list(val)) if len(val) > 0 else ''
                    else:
                        val_text = (str(val).strip() if val not in (None, '') else '')
                    ws_configs.write(r, 3, val_text, fmt_normal if val_text != '' else fmt_black)
                    typ = (cfg or {}).get('type')
                    ws_configs.write(r, 4, (typ if typ else ''), fmt_normal if typ else fmt_black)
                    xp = (cfg or {}).get('xpath')
                    ws_configs.write(r, 5, (xp if xp else ''), fmt_normal if xp else fmt_black)
                    ws_configs.write(r, 6, usage_count, fmt_normal)
                    r += 1
        # Freeze header and set widths
        ws_configs.freeze_panes(1, 0)
        ws_configs.set_column(0, 0, 40)
        ws_configs.set_column(1, 1, 16)
        ws_configs.set_column(2, 2, 40)
        ws_configs.set_column(3, 3, 60)
        ws_configs.set_column(4, 4, 16)
        ws_configs.set_column(5, 5, 80)
        ws_configs.set_column(6, 6, 16)
        # Wrap range as Excel Table with AutoFilter if there is data
        if r > 1:
            ws_configs.add_table(0, 0, r - 1, 6, {
                'style': 'Table Style Light 9',
                'columns': [
                    {'header': 'customObjectName'},
                    {'header': 'configuration#'},
                    {'header': 'description'},
                    {'header': 'value'},
                    {'header': 'type'},
                    {'header': 'xpath'},
                    {'header': 'usageCount'},
                ],
            })

        # 3) usages worksheet (all usages with opposite count: configCount)
        ws_usages = workbook.add_worksheet('usages')
        ws_usages.write_row(0, 0, ['customObjectName', 'usage#', 'usageType', 'usedBy', 'parent', 'configCount'], fmt_header)
        r = 1
        for object_name in sorted(urlCategoryData.keys()):
            record = urlCategoryData[object_name]
            cfgs = get_configs_list(record)
            config_count = len(cfgs)
            usages = get_usages_list(record)
            if not usages:
                # No usages: optionally skip to keep sheet focused on usages only
                continue
            for idx, use in enumerate(usages, start=1):
                usage_type = (use or {}).get('usageType') or ''
                used_by = (use or {}).get('usedBy') or (use or {}).get('usageDescription') or (use or {}).get('UsedBy') or ''
                parent_val = (use or {}).get('parent') or ''
                ws_usages.write(r, 0, object_name, fmt_normal)
                ws_usages.write(r, 1, idx, fmt_normal)
                ws_usages.write(r, 2, (usage_type if usage_type else ''), fmt_normal if usage_type else fmt_black)
                ws_usages.write(r, 3, (used_by if used_by else ''), fmt_normal if used_by else fmt_black)
                ws_usages.write(r, 4, (parent_val if parent_val else ''), fmt_normal if parent_val else fmt_black)
                ws_usages.write(r, 5, config_count, fmt_normal)
                r += 1
        # Freeze header and set widths
        ws_usages.freeze_panes(1, 0)
        ws_usages.set_column(0, 0, 40)
        ws_usages.set_column(1, 1, 12)
        ws_usages.set_column(2, 2, 28)
        ws_usages.set_column(3, 3, 60)
        ws_usages.set_column(4, 4, 28)
        ws_usages.set_column(5, 5, 16)
        # Add table with AutoFilter if rows exist
        if r > 1:
            ws_usages.add_table(0, 0, r - 1, 5, {
                'style': 'Table Style Light 9',
                'columns': [
                    {'header': 'customObjectName'},
                    {'header': 'usage#'},
                    {'header': 'usageType'},
                    {'header': 'usedBy'},
                    {'header': 'parent'},
                    {'header': 'configCount'},
                ],
            })

        # 4) Multi-config Objects worksheet
        ws_multi = workbook.add_worksheet('multi-config Objects')
        # Include full config details and a usageCount per object
        ws_multi.write_row(0, 0, ['customObjectName', 'configuration#', 'description', 'value', 'type', 'xpath', 'usageCount'], fmt_header)
        r = 1
        for object_name in sorted(urlCategoryData.keys()):
            record = urlCategoryData[object_name]
            cfgs = get_configs_list(record)
            usages = get_usages_list(record)
            if len(cfgs) > 1:
                usage_count = len(usages)
                for idx, cfg in enumerate(cfgs, start=1):
                    ws_multi.write(r, 0, object_name, fmt_normal)
                    ws_multi.write(r, 1, idx, fmt_normal)
                    desc = (cfg or {}).get('description')
                    ws_multi.write(r, 2, (desc if desc else ''), fmt_normal if desc else fmt_black)
                    # Values as Python list literal, matching prior convention
                    val = (cfg or {}).get('url_value')
                    if isinstance(val, (list, tuple, set)):
                        val_text = repr(list(val)) if len(val) > 0 else ''
                    else:
                        val_text = (str(val).strip() if val not in (None, '') else '')
                    ws_multi.write(r, 3, val_text, fmt_normal if val_text != '' else fmt_black)
                    typ = (cfg or {}).get('type')
                    ws_multi.write(r, 4, (typ if typ else ''), fmt_normal if typ else fmt_black)
                    xp = (cfg or {}).get('xpath')
                    ws_multi.write(r, 5, (xp if xp else ''), fmt_normal if xp else fmt_black)
                    ws_multi.write(r, 6, usage_count, fmt_normal)
                    r += 1
        # Freeze header and set widths
        ws_multi.freeze_panes(1, 0)
        ws_multi.set_column(0, 0, 40)
        ws_multi.set_column(1, 1, 16)
        ws_multi.set_column(2, 2, 40)
        ws_multi.set_column(3, 3, 60)
        ws_multi.set_column(4, 4, 16)
        ws_multi.set_column(5, 5, 80)
        ws_multi.set_column(6, 6, 16)
        # Wrap as Table if rows exist
        if r > 1:
            ws_multi.add_table(0, 0, r - 1, 6, {
                'style': 'Table Style Light 9',
                'columns': [
                    {'header': 'customObjectName'},
                    {'header': 'configuration#'},
                    {'header': 'description'},
                    {'header': 'value'},
                    {'header': 'type'},
                    {'header': 'xpath'},
                    {'header': 'usageCount'},
                ],
            })

        workbook.close()
        panCore.logging.info("Wrote CustomUrlObjectDetails.xlsx successfully.")
    except Exception as exc:
        panCore.logging.exception(f"Failed to write CustomUrlObjectDetails.xlsx: {exc}")

