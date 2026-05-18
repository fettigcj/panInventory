# readme_checkServiceRoute — Service Route Verification

Purpose
- Query devices to confirm service route configuration and connectivity for critical services (e.g., updates, telemetry, logging).

Quick start
```
py .\checkServiceRoute.py -c panCoreConfig.json -L checkServiceRoute.log
```

Outputs
- Console/log report of service route settings and any mismatches.

Scheduling tip
- Run periodically to detect inadvertent changes in service routing.
