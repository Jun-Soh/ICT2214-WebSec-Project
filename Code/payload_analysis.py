import requests
from bs4 import BeautifulSoup
import os
import time
from urllib.parse import urljoin, urlparse

VT_API_KEY = 'Insert API Key here'
HYBRID_API_KEY = 'Insert API Key here'
URL = "http://127.0.0.1"

VT_HEADERS = {"X-Apikey": VT_API_KEY}
HYBRID_HEADERS = {
    "accept": "application/json",
    "user-agent": "Falcon Sandbox",
    "api-key": HYBRID_API_KEY
}


def submit_url_to_virustotal(url):
    data = {"url": url}
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls", headers=VT_HEADERS, data=data)
    return response.json()


def get_virustotal_report(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url, headers=VT_HEADERS)
    return response.json()


def submit_file_to_virustotal(file_path):
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(
            "https://www.virustotal.com/api/v3/files", headers=VT_HEADERS, files=files)
    return response.json()


def get_virustotal_file_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=VT_HEADERS)
    return response.json()


def submit_file_to_hybrid_analysis(file_path):
    with open(file_path, "rb") as f:
        files = {"file": (file_path, f)}
        params = {"environment_id": 100, "no_share_third_party": True}
        response = requests.post("https://www.hybrid-analysis.com/api/v2/submit/file",
                                 headers=HYBRID_HEADERS, files=files, data=params)
    return response.json()


def get_hybrid_analysis_report(job_id):
    url = f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary"
    response = requests.get(url, headers=HYBRID_HEADERS)
    return response.json()


def fetch_download_links(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    download_links = []

    for a_tag in soup.find_all('a', href=True):
        link = a_tag['href']
        if any(link.lower().endswith(ext) for ext in ['.exe', '.zip', '.msi', '.rar', '.dmg', '.pdf', 'doc', 'docx']):
            download_links.append(link)

    return download_links


def print_virustotal_report(vt_report):
    stats = vt_report.get("data", {}).get(
        "attributes", {}).get("last_analysis_stats", {})
    category = vt_report.get("data", {}).get(
        "attributes", {}).get("category", "N/A")

    print("\nVirusTotal Report:")
    print(f"  - Stats: {stats}")
    print(f"  - Category: {category}")

    analysis_status = vt_report.get("data", {}).get(
        "attributes", {}).get("status", "N/A")
    file_type = vt_report.get("data", {}).get(
        "attributes", {}).get("type", "N/A")
    print(f"  - Analysis Status: {analysis_status}")
    print(f"  - File Type: {file_type}")


def print_hybrid_analysis_report(ha_report, file_name):
    network_connections = ha_report.get("network", {}).get(
        "total_network_connections", "N/A")
    verdict = ha_report.get("verdict", "N/A")
    av_detect = ha_report.get("av_detect", "N/A")

    print("\nHybrid Analysis Report:")
    print(f"  - Total Network Connections: {network_connections}")
    print(f"  - Verdict: {verdict}")
    print(f"  - AV Detection: {av_detect}")

    file_type = ha_report.get('file_info', {}).get('file_type', 'N/A')
    malware_behavior = ha_report.get('malware', {}).get('behavior', 'N/A')
    signature_analysis = ha_report.get(
        'signature_analysis', {}).get('signature', 'N/A')

    print(f"  - File Type: {file_type}")
    print(f"  - Malware Behavior: {malware_behavior}")
    print(f"  - Signature Analysis: {signature_analysis}")
    return [file_name, network_connections, verdict, av_detect, file_type, malware_behavior, signature_analysis]


def payload_scan(URL):
    print("Scanning webpage for downloadable files...")
    download_urls = fetch_download_links(URL)

    if download_urls:
        results = []
        for file_url in download_urls:
            print(f"Found file: {file_url}")

            file_url = urljoin(URL, file_url)
            file_name = os.path.basename(urlparse(file_url).path)

            print(f"Downloading: {file_name}")
            file_response = requests.get(file_url, stream=True)
            with open(file_name, 'wb') as f:
                for chunk in file_response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            print(f"Submitting {file_name} to Hybrid Analysis...")
            ha_response = submit_file_to_hybrid_analysis(file_name)
            ha_job_id = ha_response.get("job_id")

            if ha_job_id:
                print("Waiting for Hybrid Analysis report...")
                time.sleep(20)  # Allow some time for analysis
                ha_file_report = get_hybrid_analysis_report(ha_job_id)
                results.append(print_hybrid_analysis_report(
                    ha_file_report, file_name))

            os.remove(file_name)
            print(f"Deleted {file_name} after submission.")
            return results

    else:
        return None
    print("Scanning complete!")
