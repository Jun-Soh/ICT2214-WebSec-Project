import whois
import requests
import dns.resolver


def check_a_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        # List comprehension to extract IPs
        ip_addresses = [rdata.address for rdata in answers]
        print(f"A records for {domain}: {', '.join(ip_addresses)}")
        return ip_addresses
    except dns.resolver.NoAnswer:
        print(f"No A records found for {domain}.")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist.")
        return None
    except dns.resolver.Timeout:
        print(f"DNS query timed out for {domain}.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def query_whois(domain):
    try:
        w = whois.whois(domain)
        print("Creation Date:", w.creation_date)
        print("Expiration Date:", w.expiration_date)
        print("Registrant:", w.registrant)
        print("Registrar:", w.registrar)
        print("Name Servers:", w.name_servers)
        print("Contact Email:", w.emails)
        print("Country:", w.country)
        print("City:", w.city)
        return w

    except whois.parser.PywhoisError:
        return None


if __name__ == "__main__":
    domain = input("Enter domain to query: ")
