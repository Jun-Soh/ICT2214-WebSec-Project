import requests
import time

API_KEY = "1dab91315611bb604dfdf7a3020923bc26a71e2fef1675feb274070f5f16f0ee"  
VT_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"
VT_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/"


def scan_url_vt(url_to_scan):
    """
    Submits a URL to VirusTotal and retrieves the scan report.

    :param url_to_scan: The URL to scan.
    :return: The scan report JSON response.
    """

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
    time.sleep(15)  # Wait for results to be processed, too short results in "queued" query status

    report_url = f"{VT_REPORT_URL}{analysis_id}"
    report_response = requests.get(report_url, headers=headers)

    if report_response.status_code != 200:
        return {"error": f"Failed to retrieve report: {report_response.text}"}

    return report_response.json()  # Return the scan report

def process_results(report):
    engine_results = {}
    engine_results = report["data"]["attributes"]["results"]
    for engine_name, engine_data in engine_results.items():
        category = engine_data.get("category")
        engine_results[engine_name] = category
    return engine_results

def retrieve_vt_score(report):
    stats = report["data"]["attributes"]["stats"]
    return stats