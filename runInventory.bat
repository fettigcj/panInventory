@echo off
setlocal enabledelayedexpansion

:: ---------------------------------------------
:: CONFIGURATION
:: ---------------------------------------------
set rotationDays=60

:: ---------------------------------------------
:: ARGUMENT VALIDATION
:: ---------------------------------------------
if "%~2"=="" (
    echo Usage: %~nx0 baseDir environment
    echo Example: %~nx0 C:\app_data\panApps NaaS
    echo Example: %~nx0 C:\app_data\panApps Cloud
    exit /b 1
)

set "baseDir=%~1"
set "envName=%~2"

:: ---------------------------------------------
:: PATHS
:: ---------------------------------------------
set "confDir=%baseDir%\confs"
set "confFile=%confDir%\%envName%.json"
set "appPath=%baseDir%\panInventory"
set "logPath=%baseDir%\logs"
set "outputDir=%baseDir%\output\%envName%"
set "lockDir=%baseDir%\locks"

for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "todayDate=%%c-%%a-%%b"
)
set "scriptLogFile=%logPath%\updateReports_%envName%_%todayDate%.log"

::: ---------------------------------------------
::: PYTHON/VENV DETECTION
::: Prefer a virtualenv's python if present
::: ---------------------------------------------
set "PYTHON_CMD=python"
if exist "%appPath%\.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%appPath%\.venv\Scripts\python.exe"
) else (
    if exist "%baseDir%\.venv\Scripts\python.exe" (
        set "PYTHON_CMD=%baseDir%\.venv\Scripts\python.exe"
    )
)

:: ---------------------------------------------
:: CHECK MUST-EXIST DIRS
:: ---------------------------------------------
if not exist "%appPath%" (
    echo Error: Required application path "%appPath%" does not exist.
    exit /b 1
)

:: ---------------------------------------------
:: SAFETY PROMPT FOR MISSING DIRECTORIES
:: ---------------------------------------------
set missingCount=0
for %%D in ("%lockDir%" "%logPath%" "%outputDir%" "%confDir%") do (
    if not exist "%%~D" (
        set /a missingCount+=1
    )
)

if !missingCount! GEQ 1 (
    echo Warning: !missingCount! directories missing.
    echo Base directory "%baseDir%" may be incorrect.
    set /p response=Proceed with creating missing directories? (y/N):
    if /i not "!response!"=="Y" (
        echo Aborting.
        exit /b 1
    )
)

:: ---------------------------------------------
:: CREATE MISSING DIRECTORIES
:: ---------------------------------------------
for %%D in ("%lockDir%" "%logPath%" "%outputDir%" "%confDir%") do (
    if not exist "%%~D" (
        mkdir "%%~D"
        echo Created missing directory: %%~D
    )
)

:: ---------------------------------------------
:: PURGE OLD LOG FILES (>rotationDays)
:: ---------------------------------------------
forfiles /p "%logPath%" /m "updateReports_%envName%_*.log" /d -%rotationDays% /c "cmd /c del /q @path"

:: ---------------------------------------------
:: LOCK HANDLING
:: ---------------------------------------------
set "lockFile=%lockDir%\updateReports_%envName%.lock"
if exist "%lockFile%" (
    echo Another updateReports for %envName% is already running. Exiting.
    exit /b 1
)
echo Locked > "%lockFile%"

:: ---------------------------------------------
:: MOVE INTO OUTPUT DIR
:: ---------------------------------------------
cd /d "%outputDir%"

:: ---------------------------------------------
:: LOGGING FUNCTION
:: ---------------------------------------------
:log_msg
set "msg=%~1"
for /f "tokens=1-3 delims=/: " %%a in ("%date%") do (
    set "yyyy=%%c" & set "mm=%%a" & set "dd=%%b"
)
set "timeVal=%time%"
>> "%scriptLogFile%" echo [%yyyy%-%mm%-%dd% %timeVal%] %msg%
goto :EOF

:: ---------------------------------------------
:: PURGE OLD REPORTS (>rotationDays)
:: ---------------------------------------------
call :log_msg "Purging reports older than %rotationDays% days..."
forfiles /p "%outputDir%" /m "*.xlsx" /d -%rotationDays% /c "cmd /c del /q @path"

:: ---------------------------------------------
:: ARCHIVE & REPLACE FUNCTION
:: ---------------------------------------------
:archive_and_replace
set "baseName=%~1"
set "current=%baseName%.xlsx"
set "temp=%baseName%_temp.xlsx"

call :log_msg "Attempting to archive/replace using temp file: %temp%"

if exist "%current%" if exist "%temp%" (
    for %%F in ("%current%") do set "fileDate=%%~tF"
    set "fileDate=%fileDate:~0,10%"
    set "fileDate=%fileDate:/=-%"
    set "archive=%baseName%-%fileDate%.xlsx"
    ren "%current%" "%archive%"
    ren "%temp%" "%current%"
    call :log_msg "Archived %current% -> %archive%, replaced with new report."
) else if exist "%temp%" (
    ren "%temp%" "%current%"
    call :log_msg "Created new %current% (first run / no prior report)."
) else (
    call :log_msg "No temp file for %baseName% found — skipping."
)
goto :EOF

:: ---------------------------------------------
:: SAFE PYTHON RUN CALLER
:: ---------------------------------------------
:run_python_report
set "scriptName=%~1"
set "tempFile=%~2"
shift
shift
set "args=%*"
call :log_msg "Starting Python (%PYTHON_CMD%): %scriptName% -> expected output: %tempFile%"
"%PYTHON_CMD%" "%appPath%\%scriptName%" %args%
if errorlevel 1 (
    call :log_msg "ERROR: %scriptName% failed — skipping archive step."
    exit /b 1
)
call :log_msg "Python completed: %scriptName% -> generated %tempFile%"
goto :EOF

:: ---------------------------------------------
:: REPORT GENERATION & ROTATION
:: ---------------------------------------------
call :log_msg "Generating and rotating reports for environment '%envName%'..."
call :log_msg "Using Python interpreter: %PYTHON_CMD%"

call :run_python_report panInventory.py %envName%_PanInventory_temp.xlsx -s -c "%confFile%" -L "%logPath%\%envName%_inventory.log" -w "%envName%_PanInventory_temp.xlsx"
if exist "%envName%_PanInventory_temp.xlsx" call :archive_and_replace %envName%_PanInventory

call :run_python_report panoramaSyncState.py %envName%_PanoState_temp.xlsx -c "%confFile%" -L "%logPath%\%envName%_PanoState.log" -w "%envName%_PanoState_temp.xlsx"
if exist "%envName%_PanoState_temp.xlsx" call :archive_and_replace %envName%_PanoState

call :run_python_report panGroupsAndProfiles.py %envName%_SecurityProfilesAndGroups_temp.xlsx -c "%confFile%" -L "%logPath%\%envName%_SecurityProfilesAndGroups.log" -w "%envName%_SecurityProfilesAndGroups_temp.xlsx"
if exist "%envName%_SecurityProfilesAndGroups_temp.xlsx" call :archive_and_replace %envName%_SecurityProfilesAndGroups

call :run_python_report panOverrides.py %envName%_overrides_temp.xlsx -c "%confFile%" -L "%logPath%\%envName%_overrides.log" -w "%envName%_overrides_temp.xlsx"
if exist "%envName%_overrides_temp.xlsx" call :archive_and_replace %envName%_overrides

call :log_msg "Report update process completed."

:: ---------------------------------------------
:: RELEASE LOCK
:: ---------------------------------------------
del "%lockFile%" >nul
endlocal
exit /b 0