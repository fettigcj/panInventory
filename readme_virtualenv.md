# Deploying panInventory with a Python virtual environment

This guide shows how to run the scheduled inventory jobs inside an isolated Python virtual environment (venv). Doing so prevents differences between interactive user shells and root/cron from breaking the run.

## 1) Create a venv and install dependencies

Assumptions:
- Application directory: /app_data/panApps/panInventory
- You have Python 3.8+ installed on the server.

Commands (run as a privileged user or the service account that owns the cron job):

```bash
cd /app_data/panApps/panInventory
python3 -m venv .venv
source .venv/bin/activate
# Upgrade pip/tools
python -m pip install --upgrade pip wheel setuptools
# Install required packages
# If you have a requirements.txt, use it; otherwise install the known dependencies:
# python -m pip install -r requirements.txt
python -m pip install pan-os-python pan-python lxml xlsxwriter requests
# Optional: pin versions you rely on, e.g.:
# python -m pip install "pan-os-python==1.14.*" "pan-python==0.17.*"

# Verify versions
python -c "import sys, panos; import pan as panpython; print(sys.version); print('panos', getattr(panos,'__version__','?')); print('pan-python', getattr(panpython,'__version__','?'))"

# Leave the venv
deactivate
```

Notes:
- The repository contains logic in runInventory.sh to auto-detect and use a venv if present at either:
  - /app_data/panApps/panInventory/.venv/bin/python, or
  - /app_data/panApps/.venv/bin/python
- If neither exists, it falls back to python3 in PATH.

## 2) Update crontab to use the wrapper script

Your existing cron entry likely looks like this:

```
10 4 * * * /app_data/panApps/scripts/runInventory.sh /app_data/panApps naas
```

No change is required if you created the venv at /app_data/panApps/panInventory/.venv.
The wrapper will discover and use that interpreter automatically.

If you prefer a single shared venv for multiple apps, create it at /app_data/panApps/.venv and the wrapper will pick it up as well.

## 3) Where to find environment diagnostics

When panInventory.py starts, it now logs the following details at INFO level:
- Python executable and version
- Whether running inside a virtualenv (and the sys.prefix/base_prefix values)
- Platform, machine and processor
- Working directory and user
- pan-os-python and pan-python package versions

These appear at the top of the log file you pass via -L (e.g., /app_data/panApps/logs/naas_inventory.log). This helps compare interactive vs. cron environments.

## 4) Troubleshooting tips

- If cron still picks the system Python, confirm the venv’s python path exists and is executable:
  - /app_data/panApps/panInventory/.venv/bin/python
- Ensure permissions on the venv and application directory allow the cron user (often root) to execute Python and read the repo.
- Check the daily script log produced by runInventory.sh (e.g., /app_data/panApps/logs/updateReports_NaaS_YYYY-MM-DD.log) for lines like:
  - "Starting Python (/app_data/panApps/panInventory/.venv/bin/python): panInventory.py …"
- The panInventory application log (e.g., naas_inventory.log) will show the environment diagnostics at startup.

## 5) Optional: pin dependency versions

For reproducible scheduled runs across upgrades, consider pinning versions in a requirements.txt:

```
# requirements.txt
pan-os-python==1.14.0
pan-python==0.17.0
lxml==5.2.1
xlsxwriter==3.2.0
requests==2.32.3
```

Then install with:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Keep this file in the repository so that provisioning a new host is a one-liner.
