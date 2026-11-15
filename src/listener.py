import os
import time
import imaplib
from dotenv import load_dotenv

# Import the main orchestration function directly
from main import run_triage

load_dotenv()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def process_email_bytes(email_bytes, mail_id):
    """Saves incoming email bytes as an .eml sample and executes main.run_triage()."""
    os.makedirs("samples", exist_ok=True)
    sample_path = f"samples/auto_received_{mail_id}.eml"
    
    with open(sample_path, "wb") as f:
        f.write(email_bytes)
    print(f"[+] Saved incoming email artifact to {sample_path}")
    
    print("[*] Running full SOC triage pipeline...")
    try:
        run_triage(sample_path)
        print("[+] Triage complete! Reports successfully generated in 'reports/' folder.\n")
    except Exception as err:
        print(f"[-] Error during triage execution: {err}")

def poll_mailbox():
    if not EMAIL_USER or not EMAIL_PASS:
        print("[-] Error: EMAIL_USER or EMAIL_PASS not configured in .env file!")
        return

    print(f"[*] Connecting to IMAP server {IMAP_SERVER}:{IMAP_PORT}...")
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("inbox")
        
        print("[*] Listening for new phishing reports... (Press Ctrl+C to stop)")
        
        while True:
            status, messages = mail.search(None, 'UNSEEN')
            if status == 'OK':
                email_ids = messages[0].split()
                if email_ids:
                    print(f"\n[+] Detected {len(email_ids)} new unread email(s)!")
                    
                    for e_id in email_ids:
                        res, msg_data = mail.fetch(e_id, '(RFC822)')
                        for response_part in msg_data:
                            if isinstance(response_part, tuple):
                                mail_id_str = e_id.decode()
                                process_email_bytes(response_part[1], mail_id_str)
                                mail.store(e_id, '+FLAGS', '\\Seen')
                                
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n[*] Stopping IMAP Listener. Shutting down safely...")
    except Exception as e:
        print(f"[-] IMAP Connection Error: {e}")

if __name__ == "__main__":
    poll_mailbox()
