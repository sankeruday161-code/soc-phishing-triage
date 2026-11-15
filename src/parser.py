import re
import html
from email import policy
from email.parser import BytesParser

def parse_eml(eml_path):
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Extract headers
    subject = msg.get('Subject', '')
    sender = msg.get('From', '')
    
    # Extract source IP from headers (Received headers)
    source_ip = "Unknown"
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    
    received_headers = msg.get_all('Received', [])
    for header in received_headers:
        match = ip_pattern.search(header)
        if match:
            source_ip = match.group()
            break
            
    if source_ip == "Unknown":
        fallback_match = ip_pattern.search(str(msg))
        if fallback_match:
            source_ip = fallback_match.group()

    # Extract body and find URLs
    body = ""
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='ignore')
            else:
                body = msg.get_payload()
        except Exception:
            body = str(msg.get_payload())

    body = html.unescape(body)
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    urls = list(set(url_pattern.findall(body + " " + str(msg))))

    # Extract attachments and calculate hashes
    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            file_data = part.get_payload(decode=True)
            if file_data:
                import hashlib
                sha256_hash = hashlib.sha256(file_data).hexdigest()
                attachments.append({"filename": filename, "sha256": sha256_hash})

    return {
        "subject": subject,
        "sender": sender,
        "source_ip": source_ip,
        "urls": urls,
        "attachments": attachments
    }
