# readme_generateBPA — Best Practice Assessment (BPA) Report

Purpose
- Invoke Palo Alto Networks BPA APIs or tools to generate a Best Practice Assessment and save outputs for review.

Typical inputs
- Authentication/API settings (via conffile or environment)
- Output file targets (JSON, XLSX, PDF where applicable)

Quick start
```
py .\generateBPA.py --help
```

Outputs
- BPA artifacts (e.g., bpa*.json, bpa.xlsx, bpa.pdf) suitable for trending and governance reviews.

Scheduling tip
- Schedule monthly/quarterly to maintain a repository of BPA results over time.
