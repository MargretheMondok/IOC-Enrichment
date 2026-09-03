# IOC Enrichment / Triage-scrips

Python tool tthat automatically enrich IP-addresses and file hashes agains VirusTotal and AbuseIPDB

## Whar it does
- look up an IP or SHA256-hash against VirusTotal's API
- Look up IP's against AbuseIPDB to get a confidence score
- Combines the results to one verdict: CLEAN, SUSPICIOUS or Maclicious, based on the score

## Setup
Demands own API-keys from Virustotal an AbuseIPDB (both free), saved in a '.env'-file

##Results
the results should look something like this:
- Results for 8.8.8.8
VirusTotal: 0 malicious / 0 suspicious
AbuseIPDB: 0% abuse confidence, 200 reports
Verdict: CLEAN
