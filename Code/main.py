from genDomain import genDomain
from ipdb_scanner import check_ipdb_reputation, get_domain_ip, calculate_ipdb_score
from vt_scanner import scan_url_vt, process_results, retrieve_vt_score
from urlscanio_scanner import submit_url_scan, get_scan_results, analyze_results
from whois_info import query_whois, check_a_records
from payload_analysis import payload_scan
import time


def main():
    domainName = getDomainName()

    domainsTable, domainsGenerated = genDomainTable(domainName)

    htmlBody = f"""<body class="p-3 mb-2 bg-dark text-white">
                        <nav class="navbar  bg-body-tertiary-dark">
                            <div class="container-fluid">
                                <h1>MyLittlePuny - Homoglyph domain scan report for: {domainName}</h1>
                            </div>
                        </nav>
                        
                        <div class = "container">
                            <div class="row">
                                {domainsTable}
                            </div>
                        <hr>"""


    
    for domain, score in domainsGenerated:
        print("Scanning domain: ", domain)

        # Check if domain is alive else don't scan it
        if check_a_records(domain):
            whoisTable = genWhoisTable(domain)
            ipscansTable = genIPScanTable(domain)
            vtTable = genVTTable(domain)
            abuseIPDBTable = genAbuseIPDBTable(domain)
            payloadTable = genPayloadTable(domain)

            htmlBody += f"""    <div class="row">
                                    <div class="column">
                                        <div class="nested-container">
                                            <div class="nested-item">
                                                {whoisTable}
                                            </div>
                                            <div class="nested-item">
                                                {ipscansTable}
                                            </div>
                                            <div class="nested-item">
                                                {abuseIPDBTable}
                                            </div>
                                        </div>
                                    </div>

                                    <div class="column">
                                        <div class="nested-container">
                                            <div class="nested-item">
                                                {vtTable}
                                            </div>
                                            <div class="nested-item">
                                                {payloadTable}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <hr>
                            """

    write_output(domainName, htmlBody)


def getDomainName():
    return input("Enter target domain to enumerate (e.g. apple.com, google.com): ")


def genPayloadTable(domainName):
    print(f"Performing payload analysis for files on {domainName}...")
    payloadHTML = f"""<h2>Payload analysis for files on {domainName}</h2>
                        <table class="table table-striped table-bordered table-dark">
                            <tr>
                                <th>File Name</th>
                                <th>Network Connections</th>
                                <th>Verdict</th>
                                <th>AV Detection</th>
                                <th>File Type</th>
                                <th>Malware Behavior</th>
                                <th>Signature Analysis</th>
                            </tr>"""

    asciiDomain = domainName.encode('idna').decode('utf-8')
    URL = f"https://{asciiDomain}"
    analysisResults = payload_scan(URL)

    if analysisResults:
        for result in analysisResults:
            payloadHTML += f"""<tr>
                                    <td>{result[0]}</td>
                                    <td>{result[1]}</td>
                                    <td>{result[2]}</td>
                                    <td>{result[3]}</td>
                                    <td>{result[4]}</td>
                                    <td>{result[5]}</td>
                                    <td>{result[6]}</td>
                                </tr>"""

        payloadHTML += "</table>"

    else:
        payloadHTML = f"""<h2>Payload analysis for files on {domainName}</h2>
                            <table class="table table-striped table-bordered table-dark">
                                <tr>
                                    <th>No files found</th>
                                </tr>
                            </table>"""

    return payloadHTML

def genWhoisTable(domainName):
    print(f"Querying whois information for {domainName}...")
    whoisHTML = f"""<h2>Whois information for {domainName}</h2>
                    <table class="table table-striped table-bordered table-dark">
                        <tr>
                            <th>Creation Date</th>
                            <th>Expiration Date</th>
                        </tr>"""
    
    whois_info = query_whois(domainName)

    if whois_info:
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date

        whoisHTML += f"""<tr>
                            <td>{creation_date}</td>
                            <td>{expiration_date}</td>
                        </tr>"""
    else:
        whoisHTML = f"""<h2>Whois information for {domainName}</h2>
                        <table class="table table-striped table-bordered table-dark">
                            <tr>
                                <th>Domain is no longer in use</th>
                            </tr>"""
    
    whoisHTML += "</table>"
    return whoisHTML


def genDomainTable(domainName):
    print(f"Generating domains for {domainName}...")
    domainsHTML = """<h2>Domains Generated</h2>
                        <table class="table table-striped table-bordered table-dark">
                            <tr>
                                <th>Domain</th>
                                <th>Similarity Score</th>
                            </tr>"""

    domainsGenerated = genDomain(domainName)

    for homoglyph, similarity in domainsGenerated:
        domainsHTML += f"""<tr>
                                <td>{homoglyph}</td>
                                <td>{similarity:.2f}</td>
                            </tr>"""

    domainsHTML += "</table>"

    return domainsHTML, domainsGenerated


def genIPScanTable(domainName):
    print(f"Scanning IP addresses for {domainName}...")
    ipHTML = f"""<h2>IP Addresses belonging to {domainName}</h2>
                    <table class="table table-striped table-bordered table-dark">
                        <tr>
                            <th>IP Address</th>
                            <th>Abuse Score</th>
                        </tr>"""

    ip_list = get_domain_ip(domainName)
    ipdb_result = check_ipdb_reputation(ip_list)
    ipdb_score_percentage = calculate_ipdb_score(ipdb_result)

    for address in ipdb_result:
        if "error" in address:
            ipHTML = f"""<h2>IP Addresses belonging to {domainName}</h2>
                            <table class="table table-striped table-bordered table-dark">
                                <tr>
                                    <th>Domain name is no longer in use</th>
                                </tr>
                            </table>"""
            return ipHTML

        else:
            ipHTML += f"""<tr>
                                <td>{address[0]}</td>
                                <td>{address[1]}</td>
                            </tr>"""

    ipHTML += f"""   <tr>
                        <td colspan="2">IPDB Abuse Score Percentage: {ipdb_score_percentage}%</td>
                    </tr>
                </table>"""
    return ipHTML


def genVTTable(domainName):
    print(f"Scanning VT for {domainName}...")
    vtHTML = f"""<h2>VT Results for {domainName}</h2>
                    <table class="table table-striped table-bordered table-dark">
                        <tr>
                            <th>Evaluation</th>
                            <th>Count</th>
                        </tr>"""
    try:
        vt_result = scan_url_vt(domainName)

        final_stats = retrieve_vt_score(vt_result)
        for result, count in final_stats.items():
            vtHTML += f"""<tr>
                                <td>{result}</td>
                                <td>{count}</td>
                            </tr>"""

    except KeyError as e:
        vtHTML = f"""<h2>VT Results for {domainName}</h2>
                        <table class="table table-striped table-bordered table-dark">
                            <tr>
                                <th>Domain has not been reported</th>
                            </tr>
                        </table>"""

    vtHTML += "</table>"
    return vtHTML


def genAbuseIPDBTable(domainName):
    print(f"Scanning AbuseIPDB for {domainName}...")
    ipdbHTML = f"""<h2>AbuseIPDB Results for {domainName}</h2>
                    <table class="table table-striped table-bordered table-dark">
                        <tr>
                            <th>Domain Score</th>
                            <th>Malicious state</th>
                        </tr>"""

    try:
        uuid = submit_url_scan(domainName)
        if uuid and not isinstance(uuid, dict):
            time.sleep(60)

        response = get_scan_results(uuid)
        scan_results = analyze_results(response)
        score = scan_results["score"]
        verdict = scan_results["malicious"]

        ipdbHTML += f"""<tr>
                            <td>{score}</td>
                            <td>{verdict}</td>
                        </tr>"""

    except KeyError as e:
        ipdbHTML = f"""<h2>AbuseIPDB Results for {domainName}</h2>
                        <table class="table table-striped table-bordered table-dark">
                            <tr>
                                <th>Domain has not been reported</th>
                            </tr>"""

    ipdbHTML += "</table>"
    return ipdbHTML


def write_output(domainName, htmlBody):
    output_file = f"{domainName}_ScanReport.html"

    htmlHeader = """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                        <title>MyLittlePuny</title>
                    
                        <style>
                            * {
                                box-sizing: border-box;
                                font-family: Roboto, sans-serif;
                            }
                            
                            body {
                                display: flex;
                                flex-direction: column;
                                margin: 20px;
                                background-color: #f4f4f4;
                            }
                            
                            .container {
                                width: 98%;
                                margin: 0 auto;
                                overflow-x: auto;
                            }
                            
                            .column {
                                flex: 1;
                                float: left;
                                width: 60%;
                                padding: 5px;
                            }

                            .row {
                                display: flex;
                                flex-wrap: wrap;
                                justify-content: center;
                                padding: 5px;
                                margin: 5px;
                                gap: 5px;
                            }

                            .nested-container {
                                display: flex;
                                flex-direction: column;
                            }

                            .nested-item {
                                margin-bottom: 10px;
                            }
                        </style>
                        
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
                    </head>
                """

    htmlMain = htmlHeader + htmlBody + "</div></body></html>"

    try:
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(htmlMain)

        print(f"Output saved to {output_file}")
    except Exception as e:
        print(f"Error saving output: {e}")


if __name__ == "__main__":
    main()
