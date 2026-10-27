import re
from collections import Counter
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

# Regex pattern to match typical Linux SSH failed login attempts
# Example: "Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def analyze_auth_log(file_path: str, threshold: int = 3):
    console.print(f"\n[bold blue][*] Analyzing log file:[/bold blue] {file_path}")
    
    path = Path(file_path)
    if not path.exists():
        console.print(f"[bold red][!] Error: File '{file_path}' not found![/bold red]")
        return

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

    # Build a Rich Table for professional output
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
    # Test it against a mock log file we will create next
    analyze_auth_log("sample_auth.log", threshold=3)