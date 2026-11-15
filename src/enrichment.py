import requests
import os

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "fd35dc7f94793377bee06fef5f5d4af53f7f3364ab056131827fd028889c2582fd3b71e0c26285a6")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "d858a4d4c30ba0ffacb1b8dd81e644232d36a91f35743db8da9176ae9392f384")

def check_abuseipdb(ip_address):
    """Queries AbuseIPDB to check the malicious reputation score of an IP address."""
    if ip_address in ["Unknown", "127.0.0.1", "10.0.0.1", "192.168.1.1"]:
        return {"score": 0, "status": "Skipped (Private or Local IP)"}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "score": score,
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "country": data.get("countryCode", "Unknown"),
                "status": "Malicious" if score > 25 else "Clean/Low Risk"
            }
        else:
            return {"error": f"API Error: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_hash(file_hash):
    """Queries VirusTotal to check if an attachment's SHA256 hash is flagged as malware."""
    if not file_hash:
        return {"status": "No hash provided"}
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            return {
                "malicious_count": malicious_count,
                "status": "Malicious" if malicious_count > 0 else "Clean"
            }
        elif response.status_code == 404:
            return {"status": "Not Found on VirusTotal (New or Custom Payload)"}
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
