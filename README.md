# 🛡️ Automated SOC Phishing Triage & Malware Sandbox Pipeline

An automated Security Operations Center (SOC) utility built in Python (Kali Linux environment) designed to rapidly ingest, parse, enrich, and triage suspicious phishing emails and attachments. This tool minimizes manual analysis overhead by automating header inspection, threat intelligence lookups, and structured incident report generation.

---

## 🚀 Key Features

* **📥 Automated Email Parsing (`parser.py`):** Extracts core email metadata (Sender, Recipient, Subject, Timestamp, Source IP) and parses embedded URLs and file attachments.
* **🔍 Threat Intelligence Enrichment (`enrichment.py`):** Automatically queries external security APIs (such as VirusTotal and AbuseIPDB) to check sender reputation and IP safety scores.
* **🎭 Privacy & Anonymization (`reporter.py`):** Automatically masks sensitive personal email addresses and user data before generating public-ready incident reports, ensuring strict GitHub hygiene.
* **📊 Dual Incident Reporting:** Generates structured, human-readable **Markdown (`.md`)** and machine-readable **JSON (`.json`)** reports for every triaged email.
* **🎨 Rich CLI Interface:** Features modern terminal progress bars, spinners, and clean formatting using Python's `rich` library.

---

## 🛠️ Project Architecture

```text
soc-phishing-triage/
│
├── src/
│   ├── main.py          # Main orchestration script
│   ├── listener.py      # Email polling / ingestion module
│   ├── parser.py        # EML parser & artifact extractor
│   ├── enrichment.py    # Threat intelligence API integration
│   └── reporter.py      # Report generator & anonymizer
│
├── samples/             # Sample EML files (ignored in git for privacy)
├── reports/             # Generated incident reports (ignored in git)
├── .env                 # API keys & sensitive configurations (git-ignored)
├── .gitignore           # Git exclusion rules
├── requirements.txt     # Python package dependencies
└── README.md            # Project documentation

1. Clone the Repository

Bash
git clone [https://github.com/sankeruday161-code/soc-phishing-triage.git](https://github.com/sankeruday161-code/soc-phishing-triage.git)
cd soc-phishing-triage

2. Create and Activate Virtual Environment

Bash
python3 -m venv venv
source venv/bin/activate

3. Install Dependencies

Bash
pip install -r requirements.txt

4. Configure Environment Variables

Create a .env file in the root directory and add your API keys:

Code snippet
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

💻 Usage

To run the triage pipeline on a sample phishing email:

Bash
python3 src/main.py samples/your_sample_email.eml

Once executed, check the reports/ folder for the newly generated .md and .json incident reports.

🔒 Security & Privacy Notice

All runtime data (samples/, reports/) and virtual environments (venv/) are strictly excluded via .gitignore.

Built-in masking functions automatically anonymize personal email addresses to ensure safe open-source sharing.


👨‍💻 Author
Uday Sanker C

Cybersecurity Student & Python Developer
