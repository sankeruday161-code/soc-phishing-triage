import os
import re
import html
import hashlib
import ipaddress
from email import policy
from email.parser import BytesParser

def is_public_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
    except ValueError:
        return False

def parse_eml(eml_path):
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = msg.get('Subject', 'No Subject')
    sender = msg.get('From', 'Unknown Sender')
    
    # Extract first public source IP from Received headers
    source_ip = "Unknown"
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    received_headers = msg.get_all('Received', [])
    for header in received_headers:
        for ip_match in ip_pattern.findall(header):
            if is_public_ip(ip_match):
                source_ip = ip_match
                break
        if source_ip != "Unknown":
            break

    # Extract email body (text/plain and text/html)
    body = ""
    if msg.is_multipart():
        for part in msg.iter_parts():
            ctype = part.get_content_type()
            if ctype in ["text/plain", "text/html"]:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += " " + payload.decode('utf-8', errors='ignore')
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            body = payload.decode('utf-8', errors='ignore') if payload else str(msg.get_payload())
        except Exception:
            body = str(msg.get_payload())

    body = html.unescape(body)
    
    # Extract clean URLs and ignore standard XML namespace schemas
    url_pattern = re.compile(r'https?://[^\s<>"\'\)]+')
    raw_urls = set(url_pattern.findall(body))
    ignore_domains = ("w3.org", "schemas.microsoft.com", "purl.org")
    urls = [u.rstrip('.,;:') for u in raw_urls if not any(d in u for d in ignore_domains)]

    # Extract attachments, save temporarily for VT upload, and compute SHA-256
    attachments = []
    temp_att_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "attachments")
    os.makedirs(temp_att_dir, exist_ok=True)

    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            file_data = part.get_payload(decode=True)
            if file_data:
                sha256_hash = hashlib.sha256(file_data).hexdigest()
                saved_path = os.path.join(temp_att_dir, filename)
                with open(saved_path, "wb") as att_file:
                    att_file.write(file_data)
                attachments.append({
                    "filename": filename,
                    "sha256": sha256_hash,
                    "filepath": saved_path
                })

    return {
        "subject": subject,
        "sender": sender,
        "source_ip": source_ip,
        "urls": urls,
        "attachments": attachments
    }
