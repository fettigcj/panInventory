# readme_PanSysHealth — System Health Snapshot

Purpose
- Collect a lightweight snapshot of Panorama and/or firewall system health for quick checks or dashboards.

Typical inputs
- --conffile panCoreConfig.json
- --logfile PanSysHealth.log (or default)

Quick start
```
py .\PanSysHealth.py -c panCoreConfig.json -L PanSysHealth.log
```

Scheduling tip
- Schedule via Task Scheduler/cron to maintain a rolling health snapshot repository.
