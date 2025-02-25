import sys
import requests
import whois
import dns.resolver
import time
import io

# Force stdout and stderr to use UTF-8
sys.stdout = io.TextIOWrapper(
    sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(
    sys.stderr.buffer, encoding="utf-8", errors="replace")

API_KEY = '3fdac1f4b890062d1a2319409e02ab8b404fae9b7ac419fe12aa209c5a80a633433b25a849b3b504'


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <domain_name>")
        return

    domain_name = sys.argv[1]
    # domain_name = "example.com"  # domain to be scanned

    ip_result = get_domain_ip(domain_name)  # get ip addresses linked to domain

    if ip_result != []:
        result = check_ip_reputation(ip_result)
        # use ipdb api to check the abuse score of each IP Address

        total_abuse_score = 0
        for i in result:
            print(f"IP: {i[0]}, Abuse Score: {i[1]}")
            total_abuse_score += i[1]
        print(f"Total Score: {total_abuse_score} / {len(result) * 100}")
    else:
        print("No IP Addresses found for the given domain.")


def get_domain_ip(domain):
    try:
        # Perform WHOIS lookup
        w = whois.whois(domain)

        # If WHOIS lookup fails (domain not found), return an empty list
        if isinstance(w, dict) and not w.get("domain_name"):
            print(f"WHOIS lookup failed for {domain}")
            return []

        # Resolve the domain to an IP address using A records
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [answer.to_text() for answer in answers]
        return ip_addresses  # returns list of IP Addresses

    except (whois.parser.PywhoisError, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"Domain {domain} does not exist or has no A records.")
        return []

    except Exception as e:
        # print(f"Error resolving domain {domain}: {e}")
        print(f"Im a dumbass")
        return []


def check_ip_reputation(ip_addr_list, max_age=90):
    result_list = []
    url = 'https://api.abuseipdb.com/api/v2/check'

    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    print("IP Addresses under given domain: \n")
    # If ip_addr_list is not list, there is most likely an error message
    if isinstance(ip_addr_list, list):
        time.sleep(0.5)
        for ip_addr in ip_addr_list:
            querystring = {
                'ipAddress': ip_addr,
                'maxAgeInDays': str(max_age)
            }
            try:
                response = requests.get(
                    url, headers=headers, params=querystring)
                response.raise_for_status()  # Raise an error for bad responses
                response = response.json()
                ip_address = response['data'].get('ipAddress', 'N/A')
                abuse_score = response['data'].get(
                    'abuseConfidenceScore', 'N/A')  # Get Abuse Score
                result = [ip_address, abuse_score]
                result_list.append(result)

            except requests.exceptions.RequestException as e:
                # Return error message in case of failure
                return {'error': str(e)}
        return result_list
    else:
        print("Invalid Entry provided.")
        return False


if __name__ == "__main__":
    main()
