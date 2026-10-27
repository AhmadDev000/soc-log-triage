# 🛡️ Automated SOC Log Triage & Brute-Force Detection Engine

A lightweight, dual-mode Python security utility built to parse, analyze, and triage raw authentication telemetry from both Linux systems (`auth.log`) and Windows Event Logs (`.evtx`). Designed to automate initial tier-1 SOC alert generation and highlight potential brute-force attacks.

---

## 🚀 Features
* **Dual-Format Support:** Automatically parses standard Linux SSH authentication logs via Regex and binary Windows Security Event Logs (`.evtx`) for Event ID 4625 (Failed Logon).
* **Automated Risk Scoring:** Aggregates failed authentication attempts per source IP and categorizes threats into `LOW`, `WARNING`, and `CRITICAL` risk tiers based on customizable thresholds.
* **Professional Terminal Reporting:** Leverages the `rich` library to output color-coded, structured incident triage tables directly to the console.
* **Zero-Heavy Dependencies:** Runs cleanly in local Python environments without requiring massive SIEM infrastructure for fast analysis.

---

## 🛠️ Tech Stack
* **Language:** Python 3.12+
* **Libraries:** `python-evtx`, `rich`, `pydantic`
* **Core Concepts:** Log Parsing, Regex Pattern Matching, XML Tree Element Extraction, SOC Tier-1 Triage Logic.

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/AhmadDev000/soc-log-triage.git](https://github.com/AhmadDev000/soc-log-triage.git)
   cd soc-log-triage
   
1. Create and activate a virtual environment:
Bash
python -m venv venv
.\venv\Scripts\Activate.ps1  # On Windows PowerShell
2. Install dependencies:
Bash
pip install python-evtx rich pydantic
💻 Usage
Run the triage engine against sample logs:
python triage.py
📊 Example Output:
[*] Analyzing log file: sample_auth.log
[+] Scanned 5 log lines successfully.

 🚨 Security Alert: Potential Brute-Force Sources 
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Source IP     ┃ Failed Count ┃ Risk Level ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 192.168.1.100 │            3 │    WARNING │
│ 45.33.22.11   │            1 │        LOW │
└───────────────┴──────────────┴────────────┘

👨‍💻 Author
Muhammad Ahmad Hassan Khan
Computer Science Graduate | Cybersecurity & Software Development