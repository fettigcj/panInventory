# readme_getPrismaAccessEgress — Prisma Access Egress IPs/Locations

Purpose
- Retrieve and report Prisma Access egress information (IPs, regions/locations) for allow-listing and routing considerations.

Quick start
```
py .\getPrismaAccessEgress.py --help
```

Outputs
- Text/CSV/XLSX list of egress IPs/locations (e.g., getPrismaAccessIPs.py and related artifacts).

Scheduling tip
- Run on a cadence to track changes and keep downstream allow-lists current.
