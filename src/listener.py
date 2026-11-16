import os
import sys
import time
import imaplib
from dotenv import load_dotenv
from rich.console import Console

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(base_dir, ".env"))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from main import run_triage

console = Console()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def process_email_bytes(email_bytes, mail_id):
    """Saves incoming email bytes as an .eml sample and executes main.run_triage()."""
    samples_dir = os.path.join(base_dir, "samples")
    os.makedirs(samples_dir, exist_ok=True)
    timestamp = int(time.time())
    sample_path = os.path.join(samples_dir, f"auto_received_{mail_id}_{timestamp}.eml")
    
    with open(sample_path, "wb") as f:
        f.write(email_bytes)
    console.print(f"\n[bold green][+] Saved incoming email artifact to:[/bold green] [cyan]{sample_path}[/cyan]\n")
    
    try:
        run_triage(sample_path)
    except Exception as err:
        console.print(f"[bold red][-] Error during triage execution:[/bold red] {err}")

def poll_mailbox():
    if not EMAIL_USER or not EMAIL_PASS:
        console.print("[bold red][-] Error: EMAIL_USER or EMAIL_PASS not configured in .env file![/bold red]")
        return

    console.print(f"[bold cyan][*] Connecting to IMAP server {IMAP_SERVER}:{IMAP_PORT}...[/bold cyan]")
    
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("inbox")
        
        status, initial_msgs = mail.search(None, 'UNSEEN')
        seen_ids = set(initial_msgs[0].split()) if status == 'OK' else set()
        
        console.print(f"[green][*] Connected![/green] Ignoring [yellow]{len(seen_ids)}[/yellow] old unread email(s).\n")
        
        with console.status("[bold bright_green]Actively monitoring inbox for NEW phishing reports... (Press Ctrl+C to stop)[/bold bright_green]", spinner="earth") as status_spinner:
            while True:
                try:
                    mail.noop()
                    status, messages = mail.search(None, 'UNSEEN')
                    
                    if status == 'OK':
                        current_unseen = set(messages[0].split())
                        new_email_ids = sorted(list(current_unseen - seen_ids), key=int)
                        
                        if new_email_ids:
                            status_spinner.stop()
                            console.print(f"\n[bold yellow on red] ⚡ ALERT: Detected {len(new_email_ids)} NEW email(s) arrived! [/bold yellow on red]")
                            
                            for e_id in new_email_ids:
                                res, msg_data = mail.fetch(e_id, '(RFC822)')
                                for response_part in msg_data:
                                    if isinstance(response_part, tuple):
                                        mail_id_str = e_id.decode()
                                        process_email_bytes(response_part[1], mail_id_str)
                                        mail.store(e_id, '+FLAGS', '\\Seen')
                                seen_ids.add(e_id)
                            
                            console.print("\n[dim]Resuming inbox monitoring...[/dim]")
                            status_spinner.start()
                                
                except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError) as conn_err:
                    status_spinner.update(f"[bold yellow]Connection interrupted ({conn_err}). Reconnecting...[/bold yellow]")
                    time.sleep(5)
                    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
                    mail.login(EMAIL_USER, EMAIL_PASS)
                    mail.select("inbox")
                    status_spinner.update("[bold bright_green]Actively monitoring inbox for NEW phishing reports... (Press Ctrl+C to stop)[/bold bright_green]")
                    
                time.sleep(5)
            
    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] Stopping IMAP Listener. Shutting down safely...[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red][-] Fatal IMAP Error:[/bold red] {e}")

if __name__ == "__main__":
    poll_mailbox()
