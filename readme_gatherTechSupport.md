# readme_gatherTechSupport — Collect Tech Support Files

Purpose
- Automate collection of tech support files (TSFs) or similar diagnostics from Panorama/firewalls for TAC or internal investigations.

Typical inputs
- --conffile panCoreConfig.json
- --logfile gatherTechSupport.log
- Optional filters (serial list, device group, etc.) depending on implementation.

Quick start
```
py .\gatherTechSupport.py -c panCoreConfig.json -L gatherTechSupport.log
```

Scheduling tip
- Run on demand. If scheduled, consider storage rotation to avoid large archives accumulating.



## Direct firewall export behavior

As of 2026-04-14, gatherTechSupport connects directly to each managed firewall to generate and download exports (tech_support, stats_dump). This change avoids Panorama relay errors where the API reports the export as unsupported when proxied via Panorama.

Key points:
- The script discovers the firewall management IP via show system info obtained through the Panorama context, then builds a direct pan-os-python Firewall object per device.
- Authentication uses the Panorama API key. Assumption: the firewalls accept the same API key as Panorama. Ensure key distribution/policy on devices matches Panorama; otherwise, exports will fail per device.
- If the management IP cannot be determined for a device, that device is skipped with message "missing-management-ip".
- If a firewall does not have the local account/API key, authentication will fail with Invalid Credential (403). The script will log this to the main log and also append a line to output\gatherTechSupport.err with: timestamp, hostname, serial, mgmt-ip, category, and the message "invalid-credential".
- All other behavior remains the same: retries, polling intervals, per-device logs, and file naming convention.

TLS verification:
- By default, TLS certificate verification is disabled to accommodate self-signed or intercepted certificates. Use --verifySSL to enable strict validation.
