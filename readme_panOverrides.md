# readme_panOverrides — Panorama Template Overrides Audit

Purpose
- Compare each firewall’s local configuration to the configuration pushed from Panorama templates to identify:
  - Active overrides (local config diverges from template)
  - Passive overrides (matches template but not sourced from it)
  - Pseudo‑passive overrides (matches aside from template provenance markers)
- Also analyzes Template Stack composition to highlight potential intra‑stack overrides.

Typical inputs
- --conffile panCoreConfig.json
- --logfile OverrideFinder.log
- --workbookname Overrides.xlsx
- --headless (optional)

Quick start
```
py .\panOverrides.py -c panCoreConfig.json -L OverrideFinder.log -w Overrides.xlsx
```

Outputs
- Excel workbook with worksheets for Active, Passive, Pseudo‑Passive overrides and Template Stack details.

Scheduling tip
- Use a simple batch/shell wrapper and schedule via Task Scheduler or cron to keep an up‑to‑date override report repository for later review.
