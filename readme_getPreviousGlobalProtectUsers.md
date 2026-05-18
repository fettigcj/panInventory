# readme_getPreviousGlobalProtectUsers — Historical GlobalProtect Users

Purpose
- Query GlobalProtect logs to enumerate previously seen users, devices, or IPs for audit and cleanup tasks.

Typical inputs
- --conffile panCoreConfig.json
- --logfile getPreviousGlobalProtectUsers.log

Quick start
```
py .\getPreviousGlobalProtectUsers.py -c panCoreConfig.json -L getPreviousGlobalProtectUsers.log
```

Outputs
- Text/CSV/XLSX list of historical GP users suitable for access reviews.

Scheduling tip
- Run monthly/quarterly to maintain a repository for identity hygiene efforts.
