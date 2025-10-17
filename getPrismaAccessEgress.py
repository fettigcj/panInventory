import os
import requests
import json
import sys

# This script demonstrates how to use the Prisma SASE Unified API.
# It correctly handles versioning differences between services by
# using a separate API version for each service.

# --- USER-DEFINED CONFIGURATION ---
# Replace these with your actual credentials and tenant-specific information.
# Using environment variables is the most secure practice.

client_id = os.environ.get("scmUser", "YOUR_CLIENT_ID_HERE")
client_secret = os.environ.get("scmPass", "YOUR_CLIENT_SECRET_HERE")
tsg_id = os.environ.get("scmTSG", "YOUR_TSG_ID_HERE")

# API Endpoints
auth_url = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
api_base_url = "https://api.sase.paloaltonetworks.com"

# The API version for SD-WAN endpoints is set based on your previous
# discovery that v4.12 is the correct version for your tenant's resources.
sdwan_api_version = "v4.12"
sdwan_profile_api_version = "v2.1"
sdwan_api_url = f"{api_base_url}/sdwan/{sdwan_api_version}/api"

# The profile call is a critical step for SD-WAN APIs and is versioned
# with the SD-WAN service itself.
profile_url = f"{api_base_url}/sdwan/{sdwan_profile_api_version}/api/profile"

# For Prisma Access Configuration APIs (like Address Groups), the versioning
# may be different. We will use a separate variable for clarity and correctness.
sse_api_version = "v4.12"  # Assuming this version matches your tenant's SSE config
sse_application_api_version = "v1"
sse_config_url = f"{api_base_url}/sse/config/{sse_api_version}"
sse_application_config_url = f"{api_base_url}/sse/config/{sse_application_api_version}"

address_groups_url = f"{sse_config_url}/address-groups"
application_groups_url = f"{sse_application_config_url}/application-groups"


# --- HELPER FUNCTIONS ---

def get_access_token(client_id, client_secret, tsg_id):
    """
    Authenticates with the Prisma SASE API using OAuth2 and returns an access token.
    This function also makes the required profile call for SD-WAN APIs.
    """
    print("Attempting to get OAuth2 access token...")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "grant_type": "client_credentials",
        "scope": f"tsg_id:{tsg_id}"
    }

    try:
        response = requests.post(auth_url, headers=headers, data=data, auth=(client_id, client_secret))
        response.raise_for_status()

        token_data = response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise ValueError("Access token not found in response.")

        print("Successfully obtained access token.")

        # --- CRITICAL STEP FOR SD-WAN APIs ---
        # Make the required profile call immediately after getting the token.
        # This call uses the SD-WAN API version, as it's a specific SD-WAN service endpoint.
        profile_headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        profile_response = requests.get(profile_url, headers=profile_headers)
        profile_response.raise_for_status()
        print("Successfully called the profile endpoint.")

        return access_token
    except requests.exceptions.RequestException as e:
        print(f"Error during authentication or profile call: {e}", file=sys.stderr)
        return None
    except ValueError as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return None


def get_sites(access_token, api_url):
    """
    Fetches the list of sites from the Prisma SD-WAN API.
    """
    print(f"Fetching list of sites from {api_url}...")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # The 'folder' query parameter is required for the sites endpoint.
    params = {
        "folder": "All"
    }

    try:
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()

        sites_data = response.json()
        # SD-WAN API responses often contain an 'items' key with the list.
        sites = sites_data.get('items', [])
        print(f"Found {len(sites)} sites.")
        return sites
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching sites: {e}", file=sys.stderr)
        if e.response.status_code == 404:
            print("Received a 404 Not Found error. This URL may be incorrect for your tenant's API version.", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None


def get_address_groups(access_token, api_url):
    """
    Fetches the list of address groups using the unified API.
    Includes the required 'folder' query parameter.
    """
    print(f"Fetching Prisma Access address groups from {api_url}...")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # The 'folder' query parameter is required for this endpoint.
    params = {
        "folder": "All"
    }

    try:
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()

        groups_data = response.json()
        return groups_data
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching address groups: {e}", file=sys.stderr)
        if e.response.status_code == 403:
            print("Received a 403 Forbidden error. Check permissions for your service account.", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None


def get_application_groups(access_token, api_url):
    """
    Fetches the list of application groups using the unified API.
    Includes the required 'folder' query parameter.
    """
    print(f"Fetching Prisma Access application groups from {api_url}...")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    # The 'folder' query parameter is required for this endpoint.
    params = {
        "folder": "All"
    }

    try:
        response = requests.get(api_url, headers=headers, params=params)
        response.raise_for_status()

        groups_data = response.json()
        return groups_data
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching application groups: {e}", file=sys.stderr)
        if e.response.status_code == 403:
            print("Received a 403 Forbidden error. Check permissions for your service account.", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    if not all([client_id, client_secret, tsg_id]):
        print("Please set the environment variables or update the script with your credentials.", file=sys.stderr)
        sys.exit(1)

    access_token = get_access_token(client_id, client_secret, tsg_id)

    if access_token:
        # Get the site information using the unified API
        sites_info = get_sites(access_token, f"{sdwan_api_url}/sites")

        if sites_info:
            print("\n--- Prisma SD-WAN Sites from Unified API ---")
            for site in sites_info:
                print(f"Site Name: {site.get('name')}, Site ID: {site.get('id')}")
            print("------------------------------------------")
        else:
            print("Failed to retrieve sites.", file=sys.stderr)

        # Get the address group information
        address_groups_info = get_address_groups(access_token, address_groups_url)

        if address_groups_info:
            print("\n--- Prisma Access Address Groups from Unified API ---")
            print(json.dumps(address_groups_info, indent=2))
            print("-------------------------------------------------------")
        else:
            print("Failed to retrieve address groups.", file=sys.stderr)

        # Get the application group information
        application_groups_info = get_application_groups(access_token, application_groups_url)

        if application_groups_info:
            print("\n--- Prisma Access Application Groups from Unified API ---")
            print(json.dumps(application_groups_info, indent=2))
            print("-------------------------------------------------------")
        else:
            print("Failed to retrieve application groups.", file=sys.stderr)
