import requests
import time

API_KEY = 'Insert API Key here'

URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/"


def submit_url_scan(url_to_scan, visibility="public"):
    """
    Submits a URL to URLScan.io for scanning and returns the scan UUID.

    :param url_to_scan: The URL to scan.
    :param visibility: The scan visibility, either "public" or "private".
    :return: The scan UUID if successful, otherwise None.
    """
    headers = {
        "API-Key": API_KEY,
        "Content-Type": "application/json"
    }

    data = {
        "url": url_to_scan,
        "visibility": visibility
    }

    response = requests.post(URLSCAN_SUBMIT_URL, headers=headers, json=data)

    if response.status_code == 200:
        result = response.json()
        return result.get("uuid")
    else:
        return {"error": f"Error submitting URL: {response.json()}"}


def get_scan_results(uuid):
    """
    Fetches the scan results using the scan UUID.

    :param uuid: The scan UUID obtained from the submission.
    :return: The scan results JSON if successful, otherwise None.
    """
    url = f"{URLSCAN_RESULT_URL}{uuid}/"
    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error fetching results: {response.json()}"}


def analyze_results(scan_data):
    """
    Extracts important details from the scan results.

    :param scan_data: The JSON scan result.
    :return: A tuple containing the risk score and malicious verdict.
    """
    if not scan_data or "error" in scan_data:
        return {"error": "No valid scan data to analyze."}

    verdicts = scan_data.get("verdicts", {}).get("overall", {})

    return {
        "score": verdicts.get("score", "N/A"),
        "malicious": verdicts.get("malicious", False)
    }
