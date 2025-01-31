import requests
import os
import socket
from dotenv import dotenv_values

# Load API keys from ~/.threat_lookup_env
env_path = os.path.expanduser("~/.threat_lookup_env")
config = dotenv_values(env_path)

VIRUSTOTAL_API_KEY = config.get("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = config.get("ABUSEIPDB_API_KEY")

def resolve_domain_to_ip(domain):
    """Convert a domain name to an IP address."""
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"[INFO] Resolved {domain} to IP: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"[ERROR] Could not resolve {domain} to an IP.")
        return None

def check_virustotal(query):
    """Check if an IP, domain, or file hash is flagged in VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/search?query={query}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            print(f"\n[✅ VirusTotal] {query} found in database!")
            for item in data['data']:
                analysis = item['attributes']['last_analysis_stats']
                print(f" - Type: {item['type']}")
                print(f" - Malicious: {analysis['malicious']}, Suspicious: {analysis['suspicious']}")
                print(f" - Harmless: {analysis['harmless']}, Undetected: {analysis['undetected']}")
        else:
            print(f"[✅ VirusTotal] No threats found for {query}.")
    else:
        print(f"[❌ VirusTotal] Error {response.status_code}: {response.text}")

def check_abuseipdb(ip):
    """Check if an IP is reported as malicious in AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        print(f"\n[✅ AbuseIPDB] {ip} Report Summary:")
        print(f" - Reports: {data['data']['totalReports']}")
        print(f" - Confidence Score: {data['data']['abuseConfidenceScore']}%")
    else:
        print(f"[❌ AbuseIPDB] Error {response.status_code}: {response.text}")

def main():
    query = input("Enter an IP, domain, or hash: ").strip()
    
    # If input starts with "http", extract domain name
    if query.startswith("http://") or query.startswith("https://"):
        query = query.split("//")[1].split("/")[0]

    check_virustotal(query)
    
    # If it's a domain, resolve to IP
    if "." in query and not query.replace(".", "").isdigit():
        ip_address = resolve_domain_to_ip(query)
        if ip_address:
            check_abuseipdb(ip_address)
    elif query.replace(".", "").isdigit() or ":" in query:  # IPv4 or IPv6
        check_abuseipdb(query)
    else:
        print("\n[INFO] Skipping AbuseIPDB check (only valid for IPs).")

if __name__ == "__main__":
    main()
