import os
import requests
import json
import sys

# This script demonstrates how to use the Prisma SD-WAN Unified API
# to get a list of sites. It uses the modern OAuth2 authentication flow.

# NOTE: This script requires you to have a Service Account with the
# necessary roles and permissions to perform these actions.
# You must obtain the following credentials from the Prisma SASE portal.

# --- USER-DEFINED CONFIGURATION ---
# Replace these with your actual credentials and tenant-specific information.
# Using environment variables is the most secure practice.

CLIENT_ID = os.environ.get("scmUser", "YOUR_CLIENT_ID_HERE")
CLIENT_SECRET = os.environ.get("scmPass", "YOUR_CLIENT_SECRET_HERE")
TSG_ID = os.environ.get("scmTSG", "YOUR_TSG_ID_HERE")

# API Endpoints
AUTH_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
API_BASE_URL = "https://api.sase.paloaltonetworks.com"
url = "https://api.sase.paloaltonetworks.com/sdwan/v2.0/api/api_versions"
# The API versions may change, so always check the latest pan.dev documentation.
# The user-specified endpoint is v4.12, so we'll use that.
SDWAN_API_VERSION = "v4.12"
API_URL = f"{API_BASE_URL}/sdwan/{SDWAN_API_VERSION}/api"


# --- HELPER FUNCTIONS ---

def get_access_token(client_id, client_secret, tsg_id):
    """
    Authenticates with the Prisma SASE API using OAuth2 and returns an access token.
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
        response = requests.post(AUTH_URL, headers=headers, data=data, auth=(client_id, client_secret))
        response.raise_for_status()

        token_data = response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise ValueError("Access token not found in response.")

        print("Successfully obtained access token.")
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"Error during authentication: {e}", file=sys.stderr)
        return None
    except ValueError as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return None


def get_site_list(access_token):
    """
    Fetches the list of sites from the Prisma SD-WAN API.
    """
    print("Fetching list of sites...")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # Endpoint to get the list of sites
    sites_url = f"{API_URL}/sites"

    try:
        response = requests.get(sites_url, headers=headers)
        response.raise_for_status()

        sites = response.json().get('items', [])
        print(f"Found {len(sites)} sites.")
        return sites
    except requests.exceptions.RequestException as e:
        print(f"Error fetching sites: {e}", file=sys.stderr)
        return None


# --- MAIN EXECUTION ---
if __name__ == "__main__":
    if not all([CLIENT_ID, CLIENT_SECRET, TSG_ID]):
        print("Please set the environment variables or update the script with your credentials.", file=sys.stderr)
        sys.exit(1)

    access_token = get_access_token(CLIENT_ID, CLIENT_SECRET, TSG_ID)

    if access_token:
        sites = get_site_list(access_token)

        if sites:
            print("\n--- Site List ---")
            for site in sites:
                print(f"Site Name: {site.get('name')}, Site ID: {site.get('id')}")
            print("-----------------")
