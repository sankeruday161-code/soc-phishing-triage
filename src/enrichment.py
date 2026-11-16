import requests
import os
import base64
import ipaddress

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def is_private_ip(ip_str):
    """Checks if an IP address is private, loopback, or invalid."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return True

def check_abuseipdb(ip_address):
    """Queries AbuseIPDB to check the malicious reputation score of a public IP."""
    if not ip_address or is_private_ip(ip_address):
        return {"score": 0, "status": "Skipped (Private, Local, or Invalid IP)"}
    
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
                "isp": data.get("isp", "Unknown"),
                "status": "Malicious" if score > 25 else "Clean/Low Risk"
            }
        else:
            return {"error": f"API Error: {response.status_code} - {response.text}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_hash(file_hash, file_path=None):
    """Queries VirusTotal for a SHA256 hash with detailed vendor analysis."""
    if not file_hash:
        return {"status": "No hash provided"}
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            
            malicious_count = stats.get("malicious", 0)
            total_vendors = sum(stats.values())
            flagged_by = [
                f"{vendor} ({details.get('result')})"
                for vendor, details in results.items()
                if details.get("category") == "malicious"
            ]
            
            return {
                "malicious_count": malicious_count,
                "total_vendors": total_vendors,
                "detection_ratio": f"{malicious_count}/{total_vendors}",
                "file_type": attrs.get("type_description", "Unknown"),
                "flagged_by": flagged_by[:5],
                "status": "Malicious" if malicious_count > 0 else "Clean"
            }
        elif response.status_code == 404:
            if file_path and os.path.exists(file_path):
                return upload_file_to_virustotal(file_path)
            return {"status": "Not Found on VirusTotal (New or Custom Payload)"}
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def upload_file_to_virustotal(file_path):
    """Uploads a new/unknown attachment to VirusTotal for scanning."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files, timeout=30)
        if response.status_code == 200:
            return {"status": "Uploaded to VirusTotal for analysis (Re-check shortly)"}
        return {"error": f"Upload failed: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_url(target_url):
    """Checks a URL's reputation on VirusTotal and extracts full overview metadata."""
    if not target_url:
        return {"status": "No URL provided"}
        
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            
            malicious_count = stats.get("malicious", 0)
            total_vendors = sum(stats.values())
            
            # Extract names of vendors that flagged the URL
            flagged_by = [
                f"{vendor} ({details.get('result')})"
                for vendor, details in results.items()
                if details.get("category") == "malicious"
            ]
            
            return {
                "url": target_url,
                "final_url": attrs.get("last_final_url", target_url),
                "status_code": attrs.get("last_http_response_code", "N/A"),
                "malicious_count": malicious_count,
                "total_vendors": total_vendors,
                "detection_ratio": f"{malicious_count}/{total_vendors}",
                "categories": list(set(attrs.get("categories", {}).values())),
                "tags": attrs.get("tags", []),
                "flagged_by": flagged_by[:5],  # Top 5 vendors
                "status": "Malicious" if malicious_count > 0 else "Clean"
            }
        elif response.status_code == 404:
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": target_url},
                timeout=10
            )
            if submit_resp.status_code == 200:
                return {"url": target_url, "status": "Submitted to VirusTotal for scanning"}
            return {"url": target_url, "error": f"Submit Error: {submit_resp.status_code}"}
        else:
            return {"url": target_url, "error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"url": target_url, "error": str(e)}
