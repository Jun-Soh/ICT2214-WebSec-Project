import requests
import whois
import dns.resolver
import time

IPDB_API_KEY = '3fdac1f4b890062d1a2319409e02ab8b404fae9b7ac419fe12aa209c5a80a633433b25a849b3b504'

def check_ipdb_reputation(ip_addr_list, max_age=90):
    """
    Checks the IP reputation using the AbuseIPDB API.
    
    :param ip_addr_list: List of IP addresses to check.
    :param max_age: The maximum age of reports in days.
    :return: A list of IPs and their abuse scores or an error message.
    """
    result_list = []
    url = 'https://api.abuseipdb.com/api/v2/check'

    headers = {
        'Accept': 'application/json',
        'Key': IPDB_API_KEY
    }

    if isinstance(ip_addr_list, list):  # Ensure input is a list
        time.sleep(0.5)
        for ip_addr in ip_addr_list:
            querystring = {
                'ipAddress': ip_addr,
                'maxAgeInDays': str(max_age)
            }
            try:
                response = requests.get(url, headers=headers, params=querystring)
                response.raise_for_status()  # Raise an error for bad responses
                response = response.json()

                ip_address = response['data'].get('ipAddress', 'N/A')
                abuse_score = response['data'].get('abuseConfidenceScore', 'N/A')
                
                result = [ip_address, abuse_score]
                result_list.append(result)

            except requests.exceptions.RequestException as e:
                return {'error': str(e)}  # Return error message on failure

        return result_list
    else:
        return {"error": "Invalid Entry provided."}

def get_domain_ip(domain):
    """
    Resolves a domain to its IP address using A records.

    :param domain: The domain to resolve.
    :return: A list of IP addresses or an error message.
    """
    try:
        # Perform WHOIS lookup
        whois.whois(domain)

        # Resolve domain to an IP address
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [answer.to_text() for answer in answers]
        
        return ip_addresses  # Returns a list of IP addresses
    except Exception as e:
        return {"error": str(e)}

def calculate_ipdb_score(result):
    """
    Calculates the abuse score percentage based on AbuseIPDB scores.

    :param result: List of results containing IPs and their abuse scores.
    :return: Abuse score percentage.
    """
    if not result or isinstance(result, dict):  # If result is an error message
        return {"error": "Invalid input for abuse score calculation."}

    abuse_score = sum(i[1] for i in result)
    total_abuse_score = len(result) * 100

    if total_abuse_score == 0:
        return 0

    abuse_percentage = (abuse_score / total_abuse_score) * 100
    return abuse_percentage
