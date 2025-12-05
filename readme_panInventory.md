# readme_panInventory — Panorama Inventory and Health Report

Purpose
- Connect to Panorama and iterate all connected firewalls to collect a comprehensive inventory and health dataset (interfaces, zones, HA, licenses, syslog, log forwarding, zone protection profiles, pending local changes, and more).
- Produces an Excel workbook (PanInventory.xlsx by default) with multiple worksheets and a detailed log file.

Typical inputs
- --conffile panCoreConfig.json: Panorama address and credentials/API key.
- --logfile panInventory.log: Path for logging.
- --workbookname PanInventory.xlsx: Output workbook name.

Quick start
```
py .\panInventory.py -c panCoreConfig.json -L panInventory.log -w PanInventory.xlsx
```

Notes
- Safe to schedule via runInventory.bat or runInventory.sh to refresh reports on a cadence.
- See also pancore/panGatherFunctions.py and pancore/panWorkbookFunctions.py for the underlying collectors and writers.
