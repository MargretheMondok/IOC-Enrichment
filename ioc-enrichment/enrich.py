import os
import sys
import time
import argparse
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def check_virustotal_ip(ip):
	url = f"{VT_BASE_URL}/ip_addresses/{ip}"
	headers = {"x-apikey": VT_API_KEY}
	response = requests.get(url, headers=headers)
	if response.status_code == 200:
		stats = response.json()["data"]["attributes"]["last_analysis_stats"]
		return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious",0)}
	print(f"[VirusTotal] Failiure: {response.status_code}")
	return None

def check_abuseipdb(ip):
	headers = {"Key" : ABUSEIPDB_API_KEY, "Accept": "application/json"}
	params = {"ipAddress": ip, "maxAgeInDays": 90}
	response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
	if response.status_code == 200:
		data = response.json() ["data"]
		return {"score": data.get("abuseConfidenceScore", 0), "reports": data.get("totalReports", 0)}
	print(f"[AbuseIPDB] Failiure: {response.status_code}")
	return None
	
def check_virustotal_hash(file_hash):
	url = f"{VT_BASE_URL}/files/{file_hash}"
	headers = {"x-apikey": VT_API_KEY}
	response = requests.get(url, headers=headers)
	if response.status_code == 200:
        	stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        	return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
	print(f"[VirusTotal] Failure: {response.status_code}")
	return None

def verdict_for(malicious_votes, abuse_score):
	if malicious_votes >= 5 or abuse_score >= 75:
		return "MALICIOUS"
	elif malicious_votes >= 1 or abuse_score >= 25:
		return "SUSPICIOUS"
	return "CLEAN"

def enrich_ip(ip):
	vt = check_virustotal_ip(ip)
	time.sleep(15)
	abuse = check_abuseipdb(ip)

	malicious = vt["malicious"] if vt else 0
	score = abuse["score"] if abuse else 0

	print (f"\n- Results for {ip}")
	if vt:
		print(f"VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious")
	if abuse:
		print(f"AbuseIPDB: {abuse['score']}% abuse confidence, {abuse['reports']} reports")
	print(f"Verdict: {verdict_for(malicious, score)}")

def enrich_hash(file_hash):
	vt = check_virustotal_hash(file_hash)
	malicious = vt["malicious"] if vt else 0

	print(f"\n- Results for {file_hash}")
	if vt:
		print(f"VirusTotal: {vt['malicious']} malicious / {vt['suspicious']} suspicious")
	print(f"Verdict: {verdict_for(malicious, 0)}")

def main():
	parser = argparse.ArgumentParser(description="IOC enrichment/triage-tool")
	parser.add_argument("--ip", help="IP-address to check")
	parser.add_argument("--hash", help="SHA256-hash to check")
	args = parser.parse_args()

	if not args.ip and not args.hash:
		parser.print_help()
		sys.exit(1)
	if args.ip:
		enrich_ip(args.ip)
	if args.hash:
		enrich_hash(args.hash)

if __name__ == "__main__":
	main()
