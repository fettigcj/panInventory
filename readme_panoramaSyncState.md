# readme_panoramaSyncState — Panorama Sync State Audit

Purpose
- Audit Panorama for configuration sync health:
  - Uncommitted changes in Panorama
  - Template and Device Group sync state per device
  - HA state of Panorama
  - Commit/validation warnings (errors, app dependencies, rule shadowing)
  - Template Stack details and variables
- Produces an Excel workbook (panoSync.xlsx by default) and a JSON spill file of validation job results.

Typical inputs
- --conffile panCoreConfig.json
- --logfile panoSync.log
- --workbookname panoSync.xlsx
- --headless (optional)

Quick start
```
py .\panoramaSyncState.py -c panCoreConfig.json -L panoSync.log -w panoSync.xlsx
```

Outputs
- Excel workbook with worksheets for changes, HA state, sync states, validation messages, app dependencies, shadowing rules, and template stack details.
- A .txt JSON dump alongside the workbook containing validation job results.

Scheduling tip
- Use Task Scheduler or cron with a wrapper (batch/shell) to regenerate the sync report on a cadence for ongoing compliance visibility.
