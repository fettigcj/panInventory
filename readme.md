# panInventory — Script Suite Overview

This repository contains a collection of Python automation and reporting scripts for Palo Alto Networks environments. Each script focuses on a specific audit, report, or control operation (e.g., inventory, overrides analysis, sync state, upgrades, BPA, Prisma Access reports).

How to run
- You can run any script directly with Python and the --help flag to see options. Example:
  - py .\panInventory.py --help
  - py .\panoramaSyncState.py --help
- Most scripts support a common set of arguments like --conffile (Panorama/API configuration), --logfile (log path), and sometimes --workbookname (Excel output name).

Scheduling for recurring reports
- Windows Task Scheduler: Use the included batch files to run on a schedule.
  - runInventory.bat sets up environment variables and calls panInventory.py. Create a basic task to run this .bat daily/weekly to keep reports refreshed in a shared repository.
  - You may also make a custom .bat file for any other script (e.g., panOverrides.py, panoramaSyncState.py) using setVariables.bat for consistent config.
- Linux/macOS cron: Use runInventory.sh or create your own shell wrapper that activates your Python environment and executes the desired script with parameters.
  - Example crontab entry (daily at 02:10):
    - 10 2 * * * /path/to/repo/runInventory.sh >> /var/log/panInventory_cron.log 2>&1

Outputs
- Many scripts generate Excel workbooks (.xlsx) and log files (.log). Place these outputs in a controlled folder or shared location to build a time-based report repository for later review.

Per‑script readme files
- Each top-level Python script has a companion readme_<scriptname>.md describing its purpose, key inputs/outputs, and a quick start example. Start here:
  - readme_panInventory.md
  - readme_panoramaSyncState.md
  - readme_panOverrides.md
  - readme_upgradeFirewalls.md (see also readme_panUpgrade.md for the detailed, original content)
  - Additional readmes exist for the other scripts in this directory.

Notes
- Configuration is commonly stored in panCoreConfig.json or a variant (see files like _Cloud_panCoreConfig.json). Update these to point at your Panorama and API credentials.
- Logs (e.g., panInventory.log, panoSync.log, OverrideFinder.log) are helpful for troubleshooting. Retain them alongside reports to understand when and how a report was produced.
