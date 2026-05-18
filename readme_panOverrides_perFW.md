# readme_panOverrides_perFW — Per‑Firewall Overrides Detail

Purpose
- Variant of overrides reporting that focuses on a single firewall at a time, useful for deep dives or targeted change reviews.

Typical inputs
- --conffile panCoreConfig.json
- --logfile Overrides_perFW.log
- --workbookname Overrides_perFW.xlsx
- Optional: --serial or input file to select the device(s)

Quick start
```
py .\panOverrides_perFW.py -c panCoreConfig.json -L Overrides_perFW.log -w Overrides_perFW.xlsx
```

Scheduling tip
- Usually ad‑hoc; schedule when tracking a specific device over time.
