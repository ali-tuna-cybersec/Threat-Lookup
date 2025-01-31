🎯 Usage Guide: Threat Intelligence Lookup Tool

This guide explains how to use the tool to check IPs, domains, and file hashes.
1️⃣ Running the Tool

Open a terminal and run:

python3 threat_lookup.py

You'll be prompted to enter an IP address, domain, or file hash.
2️⃣ Input Examples

✅ Check an IP Address:
Enter an IP, domain, or hash: 8.8.8.8
✔️ VirusTotal Check
✔️ AbuseIPDB Check

✅ Check a Domain (automatically resolves to an IP for AbuseIPDB):
Enter an IP, domain, or hash: example.com
✔️ VirusTotal Check
✔️ Resolves Domain to IP
✔️ AbuseIPDB Check on Resolved IP

✅ Check a URL (extracts domain and resolves IP):
Enter an IP, domain, or hash: https://malicious-site.com
✔️ VirusTotal Check
✔️ Resolves Domain to IP
✔️ AbuseIPDB Check on Resolved IP

✅ Check a File Hash:
Enter an IP, domain, or hash: d41d8cd98f00b204e9800998ecf8427e
✔️ VirusTotal Check
❌ (AbuseIPDB Skipped – Only for IPs)
3️⃣ Example Output

Enter an IP, domain, or hash: https://malicious-site.com

[✅ VirusTotal] malicious-site.com found in database!

    Type: url
    Malicious: 5, Suspicious: 2
    Harmless: 60, Undetected: 25

[INFO] Resolved malicious-site.com to IP: 192.168.1.100

[✅ AbuseIPDB] 192.168.1.100 Report Summary:

    Reports: 10
    Confidence Score: 75%

4️⃣ Troubleshooting

❌ Error 422 from AbuseIPDB?

    You entered a domain name, and AbuseIPDB only accepts IPs.
    This tool now automatically resolves domain names to IPs.

❌ Error 403 from VirusTotal?

    Your API key might have exceeded rate limits.
    Check VirusTotal API Limits.