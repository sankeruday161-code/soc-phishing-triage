import sys
import os
import time
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Load environment variables
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(base_dir, ".env"))

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser import parse_eml
from enrichment import check_abuseipdb, check_virustotal_hash, check_virustotal_url
from reporter import generate_reports

console = Console()

def print_banner():
    banner_text = (
        "[bold cyan]SOC PHISHING TRIAGE & MALWARE SANDBOX PIPELINE[/bold cyan]\n"
        "[dim]Automated Email Artifact Extraction & Threat Intelligence Enrichment[/dim]"
    )
    console.print(Panel(banner_text, box=box.DOUBLE, border_style="bright_blue", expand=False))

def run_triage(eml_path):
    print_banner()
    
    # Step 1: Parse the email with a spinner animation
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold yellow]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description=f"Parsing email artifact: {os.path.basename(eml_path)}...", total=None)
        time.sleep(0.6)
        parsed_data = parse_eml(eml_path)

    # Display Email Metadata Table
    meta_table = Table(title="📧 Email Artifact Metadata", box=box.ROUNDED, border_style="cyan", show_header=False)
    meta_table.add_column("Field", style="bold white", width=15)
    meta_table.add_column("Value", style="bright_cyan")
    
    meta_table.add_row("Subject", str(parsed_data['subject']))
    meta_table.add_row("Sender", str(parsed_data['sender']))
    meta_table.add_row("Source IP", str(parsed_data['source_ip']))
    meta_table.add_row("URLs Found", str(len(parsed_data['urls'])))
    meta_table.add_row("Attachments", str(len(parsed_data['attachments'])))
    console.print(meta_table)
    console.print()

    # Step 2: Threat Intelligence Enrichment with Live Spinner
    ip_result = {}
    url_results = []
    attachment_results = []

    with Progress(
        SpinnerColumn(spinner_name="bouncingBar"),
        TextColumn("[bold magenta]{task.description}"),
        transient=True,
    ) as progress:
        # Query AbuseIPDB
        ip = parsed_data['source_ip']
        t1 = progress.add_task(description=f"Querying AbuseIPDB for Source IP ({ip})...", total=None)
        ip_result = check_abuseipdb(ip)
        progress.remove_task(t1)

        # Query VirusTotal URLs
        for url in parsed_data['urls']:
            t2 = progress.add_task(description=f"Scanning URL on VirusTotal: {url[:45]}...", total=None)
            vt_url_res = check_virustotal_url(url)
            url_results.append(vt_url_res)
            progress.remove_task(t2)

        # Query VirusTotal Attachments
        for att in parsed_data['attachments']:
            t3 = progress.add_task(description=f"Analyzing Attachment Hash: {att['filename']}...", total=None)
            vt_att_res = check_virustotal_hash(att['sha256'], att.get('filepath'))
            vt_att_res["filename"] = att["filename"]
            attachment_results.append(vt_att_res)
            progress.remove_task(t3)

    # Display Threat Intel Summary Table
    intel_table = Table(title="🔍 Threat Intelligence Enrichment Results", box=box.HEAVY_EDGE, border_style="blue")
    intel_table.add_column("Indicator Type", style="bold white", width=16)
    intel_table.add_column("Target / Artifact", style="cyan", max_width=40)
    intel_table.add_column("Verdict", justify="center", width=16)
    intel_table.add_column("Analysis Details", style="white")

    # Add IP Row
    ip_status = ip_result.get("status", "Unknown")
    ip_color = "bold red" if "Malicious" in ip_status else "bold green"
    ip_details = f"Score: {ip_result.get('score', 0)}/100 | ISP: {ip_result.get('isp', 'N/A')} ({ip_result.get('country', 'N/A')})"
    intel_table.add_row("Source IP", ip, f"[{ip_color}]{ip_status}[/{ip_color}]", ip_details)

    # Add URL Rows
    for res in url_results:
        u_status = res.get("status", "Unknown")
        u_color = "bold red" if u_status == "Malicious" else "bold green"
        ratio = res.get("detection_ratio", "N/A")
        cats = ", ".join(res.get("categories", [])[:2]) or "Uncategorized"
        flagged = ", ".join(res.get("flagged_by", [])[:2])
        u_details = f"Detections: {ratio} | Category: {cats}"
        if flagged:
            u_details += f"\n[dim]Flagged by: {flagged}[/dim]"
        intel_table.add_row("URL", res.get("url", ""), f"[{u_color}]{u_status}[/{u_color}]", u_details)

    # Add Attachment Rows
    for res in attachment_results:
        a_status = res.get("status", "Unknown")
        a_color = "bold red" if a_status == "Malicious" else "bold green"
        ratio = res.get("detection_ratio", "N/A")
        a_details = f"Detections: {ratio} | Type: {res.get('file_type', 'Unknown')}"
        intel_table.add_row("Attachment", res.get("filename", ""), f"[{a_color}]{a_status}[/{a_color}]", a_details)

    console.print(intel_table)
    console.print()

    # Final Risk Assessment Banner
    is_high_risk = (
        (ip_result.get("score", 0) > 25)
        or any(u.get("status") == "Malicious" for u in url_results)
        or any(a.get("status") == "Malicious" for a in attachment_results)
    )

    if is_high_risk:
        console.print(Panel(
            "[bold white on red] 🚨 HIGH RISK - MALICIOUS INDICATOR DETECTED 🚨 [/bold white on red]\n"
            "[yellow]Immediate containment recommended. Automated incident reports generated.[/yellow]",
            border_style="red",
            box=box.HEAVY
        ))
    else:
        console.print(Panel(
            "[bold black on green] ✅ LOW RISK / CLEAN ARTIFACT ✅ [/bold black on green]\n"
            "[green]No malicious indicators detected across Threat Intelligence feeds.[/green]",
            border_style="green",
            box=box.ROUNDED
        ))

    # Step 5: Generate automated incident reports
    generate_reports(parsed_data, ip_result, url_results, attachment_results)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python3 src/main.py <path_to_eml>")
        sys.exit(1)
    
    run_triage(sys.argv[1])
