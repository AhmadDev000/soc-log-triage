import re
from collections import Counter
from pathlib import Path
from rich.console import Console
from rich.table import Table
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

console = Console()

# Regex for Linux auth logs
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_windows_evtx(file_path: str):
    """Parses a Windows Security .evtx file for Event ID 4625 (Failed Logon)."""
    console.print(f"[bold blue][*] Parsing Windows EVTX file:[/bold blue] {file_path}")
    failed_attempts = Counter()
    total_logs = 0

    try:
        with Evtx(file_path) as evtx:
            for record in evtx.records():
                total_logs += 1
                xml_content = record.xml()
                
                # Simple check for Event ID 4625 (Failed Logon)
                if "EventID>4625<" in xml_content:
                    total_logs += 1
                    # Extract IP address from XML Data Name='IpAddress'
                    try:
                        root = ET.fromstring(xml_content)
                        # Namespace handling for Windows Event logs can be tricky, 
                        # so we use a simple regex search inside the XML string for reliability
                        ip_match = re.search(r"<Data Name='IpAddress'>([^<]+)</Data>", xml_content)
                        if ip_match:
                            ip = ip_match.group(1)
                            if ip and ip != "-" and ip != "::1" and ip != "127.0.0.1":
                                failed_attempts[ip] += 1
                    except Exception:
                        continue
                        
        console.print(f"[green][+] Scanned {total_logs} records successfully.[/green]\n")
        return failed_attempts

    except Exception as e:
        console.print(f"[bold red][!] Error parsing EVTX file: {e}[/bold red]")
        return Counter()

def analyze_linux_log(file_path: str):
    """Parses a Linux auth.log file for failed SSH attempts."""
    console.print(f"[bold blue][*] Analyzing Linux log file:[/bold blue] {file_path}")
    path = Path(file_path)
    if not path.exists():
        console.print(f"[bold red][!] Error: File '{file_path}' not found![/bold red]")
        return Counter()

    failed_attempts = Counter()
    total_logs = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_logs += 1
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group("ip")
                failed_attempts[ip] += 1

    console.print(f"[green][+] Scanned {total_logs} log lines successfully.[/green]\n")
    return failed_attempts

def display_report(failed_attempts: Counter, threshold: int = 3):
    """Displays a Rich table summarizing potential brute-force sources."""
    table = Table(title="🚨 Security Alert: Potential Brute-Force Sources")
    table.add_column("Source IP", style="cyan", no_wrap=True)
    table.add_column("Failed Count", style="magenta", justify="right")
    table.add_column("Risk Level", style="bold", justify="center")

    alert_found = False
    for ip, count in failed_attempts.items():
        if count >= threshold:
            alert_found = True
            risk = "[red]CRITICAL[/red]" if count >= 5 else "[yellow]WARNING[/yellow]"
            table.add_row(ip, str(count), risk)
        else:
            table.add_row(ip, str(count), "[green]LOW[/green]")

    console.print(table)

    if not alert_found:
        console.print("[green][✓] No high-frequency brute-force IPs detected above threshold.[/green]")

if __name__ == "__main__":
    # Test with our existing mock Linux log first
    log_file = "sample_auth.log"
    if Path(log_file).exists():
        results = analyze_linux_log(log_file)
        display_report(results, threshold=3)
    else:
        console.print("[yellow][-] sample_auth.log not found, skipping Linux test.[/yellow]")