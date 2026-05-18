# readme_panGroupsAndProfiles — Security Profiles and Profile Groups

Purpose
- Enumerate security profiles (AV, Anti-Spyware, Vulnerability, URL, File Blocking, WildFire, DNS) and profile groups across devices managed by Panorama.
- Produce an at-a-glance workbook for compliance and hygiene reviews.

Typical inputs
- --conffile panCoreConfig.json
- --logfile SecurityProfilesAndGroups.log
- --workbookname SecurityProfilesAndGroups.xlsx

Quick start
```
py .\panGroupsAndProfiles.py -c panCoreConfig.json -L SecurityProfilesAndGroups.log -w SecurityProfilesAndGroups.xlsx
```

Scheduling tip
- Schedule weekly/monthly to maintain an audit trail of security profile posture.
