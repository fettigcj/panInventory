#!/bin/bash
# -u         : exit on unset variables (prevents typos from becoming silent empty strings)
# pipefail   : fail pipeline if any part fails (provides accurate pipeline exit codes)
# No -e here : allows continuing through all reports even if one fails
set -uo pipefail

# ---------- CONFIGURATION ----------
rotationDays=30   # Keep logs and archived reports for this many days

# ---------- ARGUMENT VALIDATION ----------
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <baseDir> <environment>"
    echo "Example: $0 /app_data/panApps NaaS"
    echo "Example: $0 /app_data/panApps Cloud"
    exit 1
fi

baseDir="$1"
envName="$2"

# ---------- PATHS ----------
confDir="${baseDir}/confs"
confFile="${confDir}/${envName,,}.json"
appPath="${baseDir}/panInventory"
logPath="${baseDir}/logs"
outputDir="${baseDir}/output/${envName,,}"
lockDir="${baseDir}/locks"
todayDate=$(date +%Y-%m-%d)
scriptLogFile="${logPath}/updateReports_${envName}_${todayDate}.log"

# ---------- PYTHON/VE NV DETECTION ----------
# Prefer a virtualenv's python if present
PYTHON_CMD="python3"
if [[ -x "${appPath}/.venv/bin/python" ]]; then
  PYTHON_CMD="${appPath}/.venv/bin/python"
elif [[ -x "${baseDir}/.venv/bin/python" ]]; then
  PYTHON_CMD="${baseDir}/.venv/bin/python"
fi

# ---------- CHECK MUST-EXIST DIRS ----------
if [[ ! -d "$appPath" ]]; then
    echo "Error: Required application path '$appPath' does not exist."
    echo "Please verify baseDir and install necessary Python scripts before running."
    exit 1
fi

# ---------- SAFETY CHECK: Count missing dirs for typo detection ----------
runtimeDirs=("$lockDir" "$logPath" "$outputDir" "$confDir")
missingCount=0
for dirPath in "${runtimeDirs[@]}"; do
    if [[ ! -d "$dirPath" ]]; then
        missingCount=$((missingCount+1))
    fi
done

if (( missingCount >= 2 )); then
    echo "Warning: $missingCount key directories missing."
    echo "Base directory '$baseDir' may be incorrect."
    read -rp "Proceed with creating missing directories? (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Aborting."
        exit 1
    fi
fi

# ---------- CREATE MISSING DIRECTORIES ----------
for dirPath in "${runtimeDirs[@]}"; do
    if [[ ! -d "$dirPath" ]]; then
        mkdir -p "$dirPath"
        echo "Created missing directory: $dirPath"
    fi
done

# ---------- PURGE OLD LOG FILES ----------
find "$logPath" -type f -name "updateReports_${envName}_*.log" -mtime +"$rotationDays" -exec rm {} +

# ---------- LOCK HANDLING ----------
lockFile="${lockDir}/updateReports_${envName}.lock"
exec 200>"$lockFile"
if ! flock -n 200; then
    echo "Another updateReports.sh for $envName is already running. Exiting."
    exit 1
fi

# ---------- MOVE INTO OUTPUT DIR ----------
cd "$outputDir"

# ---------- LOGGING FUNCTION ----------
log_msg() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" | tee -a "$scriptLogFile"
}

# ---------- PURGE OLD REPORTS (> rotationDays) ----------
log_msg "Purging reports older than $rotationDays days..."
find . -type f -mtime +"$rotationDays" -iname "*.xlsx" -exec rm {} + 2>/dev/null

# ---------- ARCHIVE & REPLACE FUNCTION ----------
archive_and_replace() {
    local baseName="$1"  # e.g., NaaS_PanInventory
    local current="${baseName}.xlsx"
    local temp="${baseName}_temp.xlsx"

    log_msg "Attempting to archive/replace using temp file: $temp"

    if [[ -f "$current" && -f "$temp" ]]; then
        local fileDate
        fileDate=$(date -u -r "$current" +'%y-%m-%d')
        local archive="${baseName}-${fileDate}.xlsx"

        mv "$current" "$archive"
        mv "$temp" "$current"
        chown apache:apache "$current" "$archive"
        chmod 664 "$current" "$archive"

        log_msg "Archived $current -> $archive, replaced with new report."

    elif [[ -f "$temp" ]]; then
        mv "$temp" "$current"
        chown apache:apache "$current"
        chmod 664 "$current"

        log_msg "Created new $current (first run / no prior report)."
    else
        log_msg "No temp file for $baseName found — skipping."
    fi
}

# ---------- SAFE PYTHON RUN CALLER ----------
run_python_report() {
    local scriptName="$1"
    local tempFile="$2"
    shift 2
    log_msg "Starting Python ($PYTHON_CMD): $scriptName -> expected output: $tempFile"
    if ! "$PYTHON_CMD" "$appPath/$scriptName" "$@"; then
        log_msg "ERROR: $scriptName failed — skipping archive step."
        return 1
    fi
    log_msg "Python completed: $scriptName -> generated $tempFile"
    return 0
}

# ---------- REPORT GENERATION & ROTATION ----------
log_msg "Generating and rotating reports for environment '$envName'..."

if run_python_report "panInventory.py" "${envName}_PanInventory_temp.xlsx" -s -c "$confFile" -L "$logPath/${envName,,}_inventory.log" -w "${envName}_PanInventory_temp.xlsx"; then
    archive_and_replace "${envName}_PanInventory"
fi

if run_python_report "panoramaSyncState.py" "${envName}_PanoState_temp.xlsx" -c "$confFile" -L "$logPath/${envName,,}_PanoState.log" -w "${envName}_PanoState_temp.xlsx"; then
    archive_and_replace "${envName}_PanoState"
fi

if run_python_report "panGroupsAndProfiles.py" "${envName}_SecurityProfilesAndGroups_temp.xlsx" -c "$confFile" -L "$logPath/${envName,,}_SecurityProfilesAndGroups.log" -w "${envName}_SecurityProfilesAndGroups_temp.xlsx"; then
    archive_and_replace "${envName}_SecurityProfilesAndGroups"
fi

if run_python_report "panOverrides.py" "${envName}_overrides_temp.xlsx" -c "$confFile" -L "$logPath/${envName,,}_overrides.log" -w "${envName}_overrides_temp.xlsx"; then
    archive_and_replace "${envName}_overrides"
fi

log_msg "Report update process completed."