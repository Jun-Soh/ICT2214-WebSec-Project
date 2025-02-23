import sys
import requests
import time
import json


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <domain_name>")
        return

    test_url = sys.argv[1]
    # test_url = "https://check.oaoii.online/gkcxv.google" # Replace with the URL you want to check

    result = scan_url_vt(test_url)
    print(json.dumps(result, indent=4, sort_keys=True))


def scan_url_vt(url_to_scan):
    """
    Submits a URL to VirusTotal and retrieves the scan report.

    :param url_to_scan: The URL to scan.
    :return: The scan report JSON response.
    """

    # Replace with your VirusTotal API key
    API_KEY = "1dab91315611bb604dfdf7a3020923bc26a71e2fef1675feb274070f5f16f0ee"
    VT_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"
    VT_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/"

    VT_RESULT_CATEGORIES = {
        "confirmed-timeout": "AV reached a timeout when analysing that file. Only returned in file analyses.",
        "timeout": "AV reached a timeout when analysing that file.",
        "failure": "AV failed when analysing this file. Only returned in file analyses.",
        "harmless": "AV thinks the file is not malicious.",
        "undetected": "AV has no opinion about this file.",
        "suspicious": "AV thinks the file is suspicious.",
        "malicious": "AV thinks the file is malicious.",
        "type-unsupported": "AV can't analyse that file. Only returned in file analyses."
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": API_KEY,
    }

    data = {"url": url_to_scan}

    # Step 1: Submit the URL for scanning
    response = requests.post(VT_SUBMIT_URL, headers=headers, data=data)

    if response.status_code != 200:
        return {"error": f"Failed to submit URL: {response.text}"}

    response_json = response.json()
    analysis_id = response_json.get("data", {}).get("id")

    if not analysis_id:
        return {"error": "Failed to get analysis ID from response"}

    print(f"URL {url_to_scan} submitted successfully. Analysis ID: {analysis_id}")

    # Step 2: Retrieve scan results
    # Wait for results to be processed, too short results in "queued" query status
    time.sleep(15)

    report_url = f"{VT_REPORT_URL}{analysis_id}"
    report_response = requests.get(report_url, headers=headers)

    if report_response.status_code != 200:
        return {"error": f"Failed to retrieve report: {report_response.text}"}

    return report_response.json()  # Return the scan report


# Example Usage
if __name__ == "__main__":
    main()
