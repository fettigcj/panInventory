# readme_setGroupMappingUserFormat — Normalize Group Mapping User Format

Purpose
- Audit and optionally modify the User-ID group mapping user format (e.g., domain\username vs. username@domain) for consistency across environments.

Quick start
```
py .\setGroupMappingUserFormat.py -c panCoreConfig.json -L setGroupMappingUserFormat.log
```

Scheduling tip
- Generally a one-time or infrequent action; schedule only if enforcing policy continuously.
