# readme_upgradeFirewalls — Bulk PAN‑OS Upgrade Orchestration

Purpose
- Assess upgrade readiness and optionally orchestrate firmware upgrades across many firewalls via Panorama.
- See readme_panUpgrade.md for the original, detailed guide and examples.

Typical inputs
- --conffile panCoreConfig.json
- --logfile upgradeFirewalls.log (or default)
- --workbookname upgradeFirewalls.xlsx
- Various upgrade controls: --targetVersion, --enableUpgrade, --upgradeActive, --upgradeStandalone, email options, etc.

Quick start (report only)
```
py .\upgradeFirewalls.py -c panCoreConfig.json -L upgradeFirewalls.log -w upgradeFirewalls.xlsx
```

Upgrade example (dangerous; read the detailed guide first)
```
py .\upgradeFirewalls.py -c panCoreConfig.json -U -V 11.0.4
```

Scheduling tip
- Use Task Scheduler or cron with a wrapper, and store workbooks/logs in a repository for later review.
