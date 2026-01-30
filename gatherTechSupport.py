import panos, panos.firewall, requests
from pancore import panCore
from pancore import panGatherFunctions
import sys, argparse, re, time, logging, threading
from datetime import datetime, timedelta

"""
Changelog
2024-04-05  Added to GIT repo
2026-01-16  Refactor: add --exportType; queue jobs across all firewalls and record Job IDs per category

Goals
- Phase 1: queue jobs only (tech_support, stats_dump) and build a results dictionary
- Retrieval/writing will be added in a subsequent update
"""

# Helper to queue a single export category and return the standard entry dict
# Returns: (entry_dict, job_id)
# entry_dict schema: {"state": "queued"|"error", "job_id": str, "message": str}

parser = argparse.ArgumentParser(prog="gatherTechSupport", description="Run PAN-OS export jobs (tech_support, stats_dump, or both) across managed firewalls with optional multithreading and download to disk.")
parser.add_argument("-I", "--headless", help="Disable Interactions; operate in headless mode, without user input (disables panCore credential prompts)", default=False, action="store_true")
parser.add_argument("-L", "--logfile", help="Log file to store log output to.", default="gatherTSF.log")
parser.add_argument("-c", "--conffile", help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument("-E", "--exportType", help="Which export to run: 'tech_support', 'stats_dump', or 'both'", choices=["tech_support", "stats_dump", "both"], default="both")
parser.add_argument("-O", "--outputDirectory", help="Directory to save downloaded export archives. Defaults to current working directory.", default=".")
parser.add_argument("-T", "--threadLimit", type=int, help="Maximum number of devices to process concurrently.", default=15)
parser.add_argument("-R", "--retryLimit", type=int, help="Maximum number of attempts for job creation and status polling (default: 10).", default=15)
parser.add_argument("-W", "--retryInterval", type=int, help="Seconds to wait between attempts when the device is busy or job remains active (default: 60).", default=180)
args, _ = parser.parse_known_args()
logger = panCore.startLogging(args.logfile)

# Ensure every LogRecord has a default device_prefix so formatters never break on main thread
old_record_factory = logging.getLogRecordFactory()

def _device_prefix_record_factory(*args, **kwargs):
    record = old_record_factory(*args, **kwargs)
    # Ensure every record has a device/thread prefix; derive from the record's thread id by default
    if not hasattr(record, "device_prefix"):
        try:
            thread_id = getattr(record, "thread", None)
            if isinstance(thread_id, int):
                record.device_prefix = f"[T{thread_id % 1000:03d}]"
            else:
                # Fallback to main tag if thread id is unavailable
                record.device_prefix = "[T000]"
        except Exception:
            record.device_prefix = "[T000]"
    return record

logging.setLogRecordFactory(_device_prefix_record_factory)

# Inject a lightweight thread-id prefix into all log records in the main log
_thread_context = threading.local()

class ThreadPrefixFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Use last 3 digits of thread id for compactness
        record.device_prefix = f"[T{record.thread % 1000:03d}]"
        return True

root_logger = logging.getLogger()
root_logger.addFilter(ThreadPrefixFilter())
# Prepend the device/thread prefix to all existing handlers' formatters
for handler in list(root_logger.handlers):
    existing_formatter = handler.formatter or logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(logging.Formatter(f"%(device_prefix)s {existing_formatter._fmt}"))

# Build Panorama context
panCore.configStart(headless=args.headless, configStorage=args.conffile)
if hasattr(panCore, "panUser"):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panUser=panCore.panUser, panPass=panCore.panPass)
elif hasattr(panCore, "panKey"):
    pano_obj, deviceGroups, firewalls, templates, tStacks = panCore.buildPano_obj(panAddress=panCore.panAddress, panKey=panCore.panKey)
else:
    logger.critical("Found neither username/password nor API key. Exiting.")
    sys.exit(1)

logger.info("Starting export and download tasks...")

# Determine output directory and ensure it exists
import os
output_directory = args.outputDirectory or "."
os.makedirs(output_directory, exist_ok=True)

# Determine which categories to run (snake_case); when both, run tech_support first, then stats_dump
if args.exportType == "both":
    selected_categories = ["tech_support", "stats_dump"]
else:
    selected_categories = [args.exportType]

# Threaded execution with a concurrency limit
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict as _Dict, List as _List, Tuple as _Tuple

# Per-thread log file filter and filename sanitizer
class ThreadIdentityFilter(logging.Filter):
    def __init__(self, allowed_thread_id: int):
        super().__init__()
        self.allowed_thread_id = allowed_thread_id

    def filter(self, record: logging.LogRecord) -> bool:
        return getattr(record, "thread", None) == self.allowed_thread_id

def _safe_filename_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_.-]", "_", value or "unknown")
    token = token.strip("._")
    return token or "unknown"

thread_limit = getattr(args, "threadLimit", 8)

# Helper to gather identity once and run categories sequentially per device

def export_categories_for_device(firewall_obj, categories: _List[str]) -> _Tuple[str, str, _Dict[str, _Dict[str, str]]]:
    serial_number = getattr(firewall_obj, "serial", "UnknownSerial")
    try:
        system_info = firewall_obj.show_system_info()
        hostname = system_info.get("system", {}).get("hostname", serial_number)
    except Exception:
        hostname = (
            getattr(firewall_obj, "hostname", None)
            or getattr(firewall_obj, "name", None)
            or serial_number
        )

    # Set up per-thread/device log file capturing only this worker's records
    sanitized_host = _safe_filename_token(hostname)
    sanitized_sn = _safe_filename_token(serial_number)
    per_device_log_path = os.path.join(output_directory, f"{sanitized_host}_{sanitized_sn}.log")
    current_thread_id = threading.get_ident()
    per_device_handler = logging.FileHandler(per_device_log_path, mode="a", encoding="utf-8")
    per_device_handler.setLevel(logging.INFO)
    per_device_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    per_device_handler.addFilter(ThreadIdentityFilter(current_thread_id))

    root_logger = logging.getLogger()
    root_logger.addHandler(per_device_handler)

    try:
        per_category = {}
        for export_category in categories:
            is_successful, job_id, saved_path, message = panGatherFunctions.either_RunExportAndDownload(
                firewall_obj,
                exportType=export_category,
                file_prefix="",
                output_dir=output_directory,
                retry_limit=getattr(args, "retryLimit", 10),
                retry_interval=getattr(args, "retryInterval", 60),
                known_hostname=hostname,
                known_serial=serial_number,
            )
            per_category[export_category] = {
                "state": "success" if is_successful else "error",
                "job_id": job_id,
                "file_path": saved_path,
                "message": message,
            }
        return serial_number, hostname, per_category
    finally:
        # Clean up per-thread handler to prevent leakage across tasks
        try:
            root_logger.removeHandler(per_device_handler)
        finally:
            per_device_handler.close()

results: _Dict[str, _Dict[str, _Dict[str, str]]] = {}

# Split connected vs offline for clarity
connected_firewalls = []
offline_firewalls = []
for device in firewalls:
    try:
        if getattr(device, "state", None) and getattr(device.state, "connected", False):
            connected_firewalls.append(device)
        else:
            offline_firewalls.append(device)
    except Exception:
        offline_firewalls.append(device)

for device in offline_firewalls:
    sn = getattr(device, "serial", "UnknownSerial")
    hostname = getattr(device, "hostname", None) or getattr(device, "name", None) or f"{sn}-Disconnected"
    results[sn] = {c: {"state": "skipped", "job_id": "", "file_path": "", "message": "device-offline"} for c in selected_categories}
    logger.info(f"Skipped offline device: {hostname} ({sn})")

logger.info(f"Dispatching {len(connected_firewalls)} device task(s) with thread limit {thread_limit}...")

future_to_serial = {}
with ThreadPoolExecutor(max_workers=thread_limit) as executor:
    for device in connected_firewalls:
        future = executor.submit(export_categories_for_device, device, selected_categories)
        future_to_serial[future] = getattr(device, "serial", "UnknownSerial")

    for future in as_completed(future_to_serial):
        try:
            serial_number, hostname, per_category = future.result()
            results[serial_number] = per_category
            # Compose a brief per-device summary for the log
            statuses = ", ".join(
                f"{cat}:{'ok' if meta['state']=='success' else 'err'}" for cat, meta in per_category.items()
            )
            logger.info(f"Completed: {hostname} ({serial_number}) -> {statuses}")
        except Exception as exc:
            serial_number = future_to_serial.get(future, "UnknownSerial")
            results.setdefault(serial_number, {})
            for cat in selected_categories:
                results[serial_number][cat] = {
                    "state": "error",
                    "job_id": "",
                    "file_path": "",
                    "message": str(exc),
                }
            logger.exception(f"Worker failed for device {serial_number}")

# Summaries
success_counts = {"tech_support": 0, "stats_dump": 0}
error_counts = {"tech_support": 0, "stats_dump": 0}
skipped_counts = {"tech_support": 0, "stats_dump": 0}
for serial_number, category_map in results.items():
    for cat in selected_categories:
        state = category_map.get(cat, {}).get("state", "error")
        if state == "success":
            success_counts[cat] += 1
        elif state == "skipped":
            skipped_counts[cat] += 1
        else:
            error_counts[cat] += 1

for cat in selected_categories:
    logger.info(
        f"Summary {cat}: success={success_counts[cat]}, errors={error_counts[cat]}, skipped={skipped_counts[cat]}"
    )
