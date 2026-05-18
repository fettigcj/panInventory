# readme_spotCheck — Targeted Spot Checks

Purpose
- Run small, targeted validations or checks against Panorama/firewalls (e.g., confirm a specific object exists or a config knob is set).

Quick start
```
py .\spotCheck.py -c panCoreConfig.json -L spotCheck.log
```

Scheduling tip
- Useful for temporary monitoring of a known issue; wrap and schedule if needed.
