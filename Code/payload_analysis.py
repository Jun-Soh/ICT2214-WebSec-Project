import requests
from bs4 import BeautifulSoup
import os
import time
from urllib.parse import urljoin, urlparse

# API Keys (Replace with your own)
VT_API_KEY = "1dab91315611bb604dfdf7a3020923bc26a71e2fef1675feb274070f5f16f0ee"
HYBRID_API_KEY = "thh7m2hfb058cd05cty1u1ny5522fcce4ehsyf8i0cd55ca6uicwiibj6cdb94ac"

# Target URL (Change this to the site you want to scan)
URL = "http://127.0.0.1"

# Headers
VT_HEADERS = {"X-Apikey": VT_API_KEY}
HYBRID_HEADERS = {
    "accept": "application/json",
    "user-agent": "Falcon Sandbox",
    "api-key": HYBRID_API_KEY
}

# Function to submit a URL to VirusTotal
def submit_url_to_virustotal(url):
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=VT_HEADERS, data=data)
    return response.json()

# Function to get the VirusTotal analysis report
def get_virustotal_report(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(url, headers=VT_HEADERS)
    return response.json()

# Function to submit a file to VirusTotal
def submit_file_to_virustotal(file_path):
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post("https://www.virustotal.com/api/v3/files", headers=VT_HEADERS, files=files)
    return response.json()

# Function to get VirusTotal file report using SHA256 hash
def get_virustotal_file_report(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=VT_HEADERS)
    return response.json()

# Function to submit a file to Hybrid Analysis
def submit_file_to_hybrid_analysis(file_path):
    with open(file_path, "rb") as f:
        files = {"file": (file_path, f)}
        params = {"environment_id": 100, "no_share_third_party": True}
        response = requests.post("https://www.hybrid-analysis.com/api/v2/submit/file", headers=HYBRID_HEADERS, files=files, data=params)
    return response.json()

# Function to get Hybrid Analysis report
def get_hybrid_analysis_report(job_id):
    url = f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary"
    response = requests.get(url, headers=HYBRID_HEADERS)
    return response.json()

# Function to fetch download links from the webpage
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
    # Extract stats and category
    stats = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    category = vt_report.get("data", {}).get("attributes", {}).get("category", "N/A")
    
    print("\n🔍 VirusTotal Report:")
    print(f"  - Stats: {stats}")
    print(f"  - Category: {category}")
    
    # Print additional useful fields
    analysis_status = vt_report.get("data", {}).get("attributes", {}).get("status", "N/A")
    file_type = vt_report.get("data", {}).get("attributes", {}).get("type", "N/A")
    print(f"  - Analysis Status: {analysis_status}")
    print(f"  - File Type: {file_type}")
  
    
def print_hybrid_analysis_report(ha_report, file_name):
    # Extract key details from Hybrid Analysis report
    network_connections = ha_report.get("network", {}).get("total_network_connections", "N/A")
    verdict = ha_report.get("verdict", "N/A")
    av_detect = ha_report.get("av_detect", "N/A")

    print("\n🔍 Hybrid Analysis Report:")
    print(f"  - Total Network Connections: {network_connections}")
    print(f"  - Verdict: {verdict}")
    print(f"  - AV Detection: {av_detect}")

    # Print additional useful fields
    file_type = ha_report.get('file_info', {}).get('file_type', 'N/A')
    malware_behavior = ha_report.get('malware', {}).get('behavior', 'N/A')
    signature_analysis = ha_report.get('signature_analysis', {}).get('signature', 'N/A')

    print(f"  - File Type: {file_type}")
    print(f"  - Malware Behavior: {malware_behavior}")
    print(f"  - Signature Analysis: {signature_analysis}")
    return [file_name, network_connections, verdict, av_detect, file_type, malware_behavior, signature_analysis]


def payload_scan(URL):
    # Main script
    print("🔍 Scanning webpage for downloadable files...")
    download_urls = fetch_download_links(URL)

    if download_urls:
        results = []
        for file_url in download_urls:
            print(f"📥 Found file: {file_url}")

            # Fix relative URLs
            file_url = urljoin(URL, file_url)

            # Extract filename from URL
            file_name = os.path.basename(urlparse(file_url).path)

            # Download the file
            print(f"⬇️ Downloading: {file_name}")
            file_response = requests.get(file_url, stream=True)
            with open(file_name, 'wb') as f:
                for chunk in file_response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)

            # Submit to Hybrid Analysis
            print(f"🚀 Submitting {file_name} to Hybrid Analysis...")
            ha_response = submit_file_to_hybrid_analysis(file_name)
            ha_job_id = ha_response.get("job_id")

            # Fetch Hybrid Analysis Report
            if ha_job_id:
                print("⏳ Waiting for Hybrid Analysis report...")
                time.sleep(20)  # Allow some time for analysis
                ha_file_report = get_hybrid_analysis_report(ha_job_id)
                results.append(print_hybrid_analysis_report(ha_file_report, file_name))

            # Delete the file after submission
            os.remove(file_name)
            print(f"🗑️ Deleted {file_name} after submission.")
            return results

    else:
        return None
    print("✅ Scanning complete!")
