# readme_RebootMinimumDate — Reboot Date Report

Purpose
- Scan devices and report the most recent reboot time per device to identify nodes that have not been rebooted since a minimum date (e.g., after upgrades or maintenance windows).

Quick start
```
py .\RebootMinimumDate.py -c panCoreConfig.json -L RebootLog.log
```

Outputs
- Text and/or Excel output listing devices with last reboot timestamps, often used with RebootLog_*.xlsx artifacts.

Scheduling tip
- Run nightly/weekly to highlight devices pending reboots after software changes.
