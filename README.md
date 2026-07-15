# OSINT Automation Tool

A Python-based CLI tool for gathering publicly available information for cybersecurity investigations and OSINT research.

## Features

- **WHOIS Lookup** - Get domain registration information
- **DNS Record Fetcher** - Retrieve A, MX, NS, TXT records
- **Subdomain Enumerator** - Find subdomains of target domain
- **Username Checker** - Check if username exists on social platforms
- **Report Generator** - Save all results to PDF or HTML report
- **Clean CLI Interface** - Colored output using the Rich library

## Installation

1. Clone or download this project
2. Navigate to the project directory:
   ```bash
   cd osint-tool
   ```
3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
# WHOIS lookup for a domain
python main.py --domain google.com

# Check if username exists on platforms
python main.py --username sandesh009

# Gather all information and generate a report
python main.py --domain google.com --report
```

## Project Structure

```
osint-tool/
├── main.py                  # Main entry point
├── modules/
│   ├── whois_lookup.py      # Domain registration info
│   ├── dns_lookup.py        # DNS records
│   ├── subdomain_enum.py    # Subdomain enumeration
│   ├── username_checker.py  # Social media username checker
│   └── report_generator.py  # PDF/HTML report generation
├── reports/                 # Generated reports saved here
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Tech Stack

- **Language:** Python 3
- **CLI Framework:** argparse
- **HTTP Requests:** requests
- **WHOIS Data:** python-whois
- **DNS Queries:** dnspython
- **Colored Output:** rich
- **PDF Generation:** fpdf

## Legal & Ethical Notice

This tool is designed for authorized security testing and OSINT research only. Always ensure you have proper authorization before investigating any target. Unauthorized access to systems or information is illegal.

## Author Notes

Built as a portfolio project for cybersecurity studies.
