from pancore import panCore
import argparse
import time
import sys
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Base URL for Prisma SD-WAN API
SDWAN_API_BASE = "https://api.sase.paloaltonetworks.com/sdwan/v4.12/api"

# Parse arguments
parser = argparse.ArgumentParser(description="Run bandwidth tests from all Prisma SD-WAN Ion devices to the Internet")
parser.add_argument("--conffile", "-c", help="Specify the config file to read options from. Default 'panCoreConfig.json'.", default="panCoreConfig.json")
parser.add_argument("--concurrent", "-n", type=int, default=5, help="Number of concurrent tests to run")
parser.add_argument("--duration", "-d", type=int, default=10, help="Duration of each test in seconds")
parser.add_argument("--output", "-o", help="Output file for results (JSON format)", default="bw_test_results.json")
parser.add_argument("--headless", "-l", help="Operate in headless mode, without user input", default=False, action='store_true')
parser.add_argument("--logfile", "-L", help="Log file to store log output to.", default='PrismaSDWAN_SpeedTest.log')
args, unknown = parser.parse_known_args()

# Start logging
panCore.startLogging(args.logfile)

# Get credentials and token
panCore.configStart(headless=args.headless, configStorage=args.conffile)
headers, token_expiry_time = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)

# Check if authentication was successful
if 'Authorization' not in headers:
    print("Failed to authenticate to Prisma SD-WAN")
    sys.exit(1)

print("Successfully authenticated to Prisma SD-WAN")


payload = {}
headers['Accept'] = 'application/json'
response = requests.request("GET", f"{SDWAN_API_BASE}/sites", headers=headers, data=payload)
response = requests.request("GET", f"{url}", headers=headers)
response.raise_for_status()

# Get all sites
try:
    sites_resp = requests.get(f"{SDWAN_API_BASE}/sites", headers=headers)
    sites_resp.raise_for_status()
    sites = sites_resp.json().get("items", [])
    print(f"Found {len(sites)} sites")
except Exception as e:
    print(f"Error retrieving sites: {str(e)}")
    sys.exit(1)

# Get all elements (Ion devices)
try:
    elements_resp = requests.get(f"{SDWAN_API_BASE}/elements", headers=headers)
    elements_resp.raise_for_status()
    elements = elements_resp.json().get("items", [])
    print(f"Found {len(elements)} elements (Ion devices)")
except Exception as e:
    print(f"Error retrieving elements: {str(e)}")
    sys.exit(1)

# Create a mapping of site_id to site_name for easier reference
site_id_to_name = {site.get("id"): site.get("name") for site in sites}

# Group elements by site
site_elements = {}
for element in elements:
    site_id = element.get("site_id")
    if site_id not in site_elements:
        site_elements[site_id] = []
    site_elements[site_id].append(element)


# Function to refresh token if needed
def refresh_token_if_needed():
    global headers, token_expiry_time
    if time.time() > token_expiry_time - 60:  # Refresh if less than 1 minute left
        headers, token_expiry_time = panCore.getSCM_Token(panCore.scmUser, panCore.scmPass, panCore.scmTSG)

# Function to run bandwidth test for a single element
def run_bw_test(element, site_name):
    element_id = element.get("id")
    element_name = element.get("name")
    site_id = element.get("site_id")

    print(f"Starting Internet bandwidth test for {element_name} at site {site_name}...")

    # Refresh token if needed
    refresh_token_if_needed()

    # Create bandwidth test to Internet
    # Note: For Internet tests, we only specify the source
    bw_test_data = {
        "source": {
            "element_id": element_id,
            "site_id": site_id
        },
        "destination": {
            "type": "internet"  # Specify Internet as destination
        },
        "duration": args.duration
    }

    try:
        bw_test_resp = requests.post(f"{SDWAN_API_BASE}/tenant/bwtests", headers=headers, json=bw_test_data)
        bw_test_resp.raise_for_status()
        test_id = bw_test_resp.json().get("id")
        print(f"Bandwidth test started with ID: {test_id} for {element_name}")
    except Exception as e:
        print(f"Error starting bandwidth test for {element_name}: {str(e)}")
        return {
            "site_name": site_name,
            "element_name": element_name,
            "status": "failed_to_start",
            "error": str(e)
        }

    # Wait for test to complete
    status = "requested"
    while status in ["requested", "started"]:
        time.sleep(5)

        # Refresh token if needed
        refresh_token_if_needed()

        try:
            status_resp = requests.get(f"{SDWAN_API_BASE}/tenant/bwtests/{test_id}", headers=headers)
            status_resp.raise_for_status()
            status = status_resp.json().get("status")
            print(f"Current test status for {element_name}: {status}")
        except Exception as e:
            print(f"Error checking test status for {element_name}: {str(e)}")
            return {
                "site_name": site_name,
                "element_name": element_name,
                "status": "failed_during_test",
                "error": str(e)
            }

    # Get results
    if status == "completed":
        results = status_resp.json().get("results", {})
        return {
            "site_name": site_name,
            "element_name": element_name,
            "status": "completed",
            "download_bandwidth": results.get("download_bandwidth"),
            "upload_bandwidth": results.get("upload_bandwidth"),
            "rtt": results.get("rtt"),
            "packet_loss": results.get("packet_loss"),
            "jitter": results.get("jitter"),
            "test_id": test_id
        }
    else:
        return {
            "site_name": site_name,
            "element_name": element_name,
            "status": status,
            "test_id": test_id
        }


# Prepare list of all tests to run
all_tests = []
for site_id, elements_list in site_elements.items():
    site_name = site_id_to_name.get(site_id, "Unknown Site")
    for element in elements_list:
        all_tests.append((element, site_name))

print(f"Preparing to run {len(all_tests)} bandwidth tests...")

# Run tests with concurrency limit
results = []
with ThreadPoolExecutor(max_workers=args.concurrent) as executor:
    future_to_element = {executor.submit(run_bw_test, element, site_name): (element, site_name)
                         for element, site_name in all_tests}

    for future in as_completed(future_to_element):
        element, site_name = future_to_element[future]
        try:
            result = future.result()
            results.append(result)

            # Print result summary
            if result["status"] == "completed":
                print(f"\nBandwidth Test Results for {result['element_name']} at {result['site_name']}:")
                print(f"Download bandwidth: {result.get('download_bandwidth', 'N/A')} Mbps")
                print(f"Upload bandwidth: {result.get('upload_bandwidth', 'N/A')} Mbps")
                print(f"Round-trip time: {result.get('rtt', 'N/A')} ms")
                print(f"Packet loss: {result.get('packet_loss', 'N/A')}%")
                print(f"Jitter: {result.get('jitter', 'N/A')} ms")
            else:
                print(f"\nTest for {result['element_name']} at {result['site_name']} failed with status: {result['status']}")

        except Exception as exc:
            element_name = element.get("name", "Unknown")
            print(f"Test for {element_name} generated an exception: {exc}")
            results.append({
                "site_name": site_name,
                "element_name": element_name,
                "status": "exception",
                "error": str(exc)
            })

# Save results to file
with open(args.output, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\nAll tests completed. Results saved to {args.output}")

# Log completion
panCore.logging.info("PrismaSDWAN_SpeedTest completed successfully")
