# readme_getPrismaAccessIPs — Prisma Access IP Inventory

Purpose
- Retrieve current Prisma Access IP address lists (egress, portal/gateway, or related), useful for firewall allow-lists and integrations.

Quick start
```
py .\getPrismaAccessIPs.py --help
```

Outputs
- Files like getPrismaAccessIPs.json/.txt/.xlsx depending on implementation.

Scheduling tip
- Schedule regularly to maintain an up‑to‑date allow‑list repository for downstream systems.
