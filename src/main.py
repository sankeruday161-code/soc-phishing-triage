import sys
import os

# Ensure Python looks in the current script directory (src/) for local modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser import parse_eml
from enrichment import check_abuseipdb, check_virustotal_hash
from reporter import generate_reports

def run_triage(eml_path):
    print(f"[*] Analyzing artifact: {eml_path}...\n")
    
    # Step 1: Parse the email
    parsed_data = parse_eml(eml_path)
    
    print("--- 📧 EMAIL METADATA ---")
    print(f"Subject : {parsed_data['subject']}")
    print(f"Sender  : {parsed_data['sender']}")
    print(f"Source IP: {parsed_data['source_ip']}")
    print(f"URLs Found: {len(parsed_data['urls'])}\n")
    
    for url in parsed_data['urls']:
        print(f"  - {url}")
        
    print("\n--- 🔍 THREAT INTEL ENRICHMENT ---")
    
    # Step 2: Enrich Source IP with AbuseIPDB
    ip = parsed_data['source_ip']
    print(f"[*] Querying AbuseIPDB for IP: {ip}...")
    ip_result = check_abuseipdb(ip)
    print(f"    Result: {ip_result}\n")
    
    # Step 3: Enrich Attachments with VirusTotal
    if parsed_data['attachments']:
        for att in parsed_data['attachments']:
            print(f"[*] Querying VirusTotal for attachment hash ({att['filename']}): {att['sha256']}...")
            vt_result = check_virustotal_hash(att['sha256'])
            print(f"    Result: {vt_result}\n")
    else:
        print("[*] No attachments found in this email sample.\n")

    print("[*] Triage complete!")

    # Step 4: Generate automated incident reports
    generate_reports(parsed_data, ip_result)
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 src/main.py <path_to_eml>")
        sys.exit(1)
    
    eml_file = sys.argv[1]
    run_triage(eml_file)
