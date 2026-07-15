#!/usr/bin/env python3
"""
Report Generator Module
Generates comprehensive OSINT reports in HTML and PDF formats.
Combines data from all modules into professional reports.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import json
import os

class ReportGenerator:
    """
    A class to generate OSINT investigation reports in HTML and PDF formats.
    Aggregates data from all OSINT modules into professional documentation.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir (str): Directory to save generated reports (default: 'reports')
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize data containers for each section
        self.investigation_title = "OSINT Investigation Report"
        self.target = None
        self.investigation_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report_data = {
            "whois": {},
            "dns": {},
            "subdomains": [],
            "usernames": {}
        }
    
    def set_title(self, title: str):
        """
        Set the report title.
        
        Args:
            title (str): Title of the investigation report
        """
        self.investigation_title = title
    
    def set_target(self, target: str):
        """
        Set the target being investigated.
        
        Args:
            target (str): Domain or username being investigated
        """
        self.target = target
    
    def add_whois_data(self, whois_results: Dict[str, str]):
        """
        Add WHOIS lookup results to the report.
        
        Args:
            whois_results (dict): WHOIS data from whois_lookup module
        """
        self.report_data["whois"] = whois_results
    
    def add_dns_data(self, dns_results: Dict[str, List[str]]):
        """
        Add DNS lookup results to the report.
        
        Args:
            dns_results (dict): DNS data from dns_lookup module
        """
        self.report_data["dns"] = dns_results
    
    def add_subdomain_data(self, subdomains: List[str]):
        """
        Add subdomain enumeration results to the report.
        
        Args:
            subdomains (list): List of found subdomains
        """
        self.report_data["subdomains"] = subdomains
    
    def add_username_data(self, username_results: Dict[str, list]):
        """
        Add username checking results to the report.
        
        Args:
            username_results (dict): Username data with found/not_found accounts
        """
        self.report_data["usernames"] = username_results
    
    def _generate_html_content(self) -> str:
        """
        Generate HTML content for the report.
        
        Returns:
            str: HTML content as a string
        """
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.investigation_title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f4f4f4;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        
        .header {{
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .meta {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        
        h2 {{
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-top: 30px;
            margin-bottom: 15px;
            font-size: 1.8em;
        }}
        
        .section {{
            margin-bottom: 30px;
        }}
        
        .no-data {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            color: #7f8c8d;
            font-style: italic;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        
        th {{
            background: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        tr:hover {{
            background: #f8f9fa;
        }}
        
        .record-item {{
            background: #ecf0f1;
            padding: 10px 15px;
            margin: 8px 0;
            border-left: 3px solid #3498db;
            border-radius: 3px;
            word-break: break-word;
        }}
        
        .found {{
            background: #d5f4e6;
            color: #27ae60;
        }}
        
        .not-found {{
            background: #fadbd8;
            color: #e74c3c;
        }}
        
        .success {{
            color: #27ae60;
            font-weight: bold;
        }}
        
        .error {{
            color: #e74c3c;
            font-weight: bold;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .stat-box h3 {{
            font-size: 2em;
            margin-bottom: 5px;
        }}
        
        .stat-box p {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        
        .url {{
            color: #3498db;
            text-decoration: none;
            word-break: break-all;
        }}
        
        .url:hover {{
            text-decoration: underline;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔍 {self.investigation_title}</h1>
            <div class="meta">
                <p><strong>Target:</strong> {self.target or 'Not specified'}</p>
                <p><strong>Generated:</strong> {self.investigation_date}</p>
            </div>
        </div>
"""
        
        # WHOIS Section
        if self.report_data["whois"]:
            html += self._generate_whois_section()
        
        # DNS Section
        if self.report_data["dns"]:
            html += self._generate_dns_section()
        
        # Subdomains Section
        if self.report_data["subdomains"]:
            html += self._generate_subdomains_section()
        
        # Username Section
        if self.report_data["usernames"]:
            html += self._generate_username_section()
        
        # Footer
        html += """
        <div class="footer">
            <p>This report was automatically generated by OSINT Automation Tool</p>
            <p>For authorized security testing and OSINT research only</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_whois_section(self) -> str:
        """Generate WHOIS section HTML."""
        html = "<h2>📋 WHOIS Information</h2>\n<div class='section'>\n"
        
        whois = self.report_data["whois"]
        
        if "error" in whois:
            html += f"<div class='no-data'>{whois['error']}</div>\n"
        else:
            html += "<table>\n<thead><tr><th>Field</th><th>Value</th></tr></thead>\n<tbody>\n"
            for key, value in whois.items():
                if key != "error":
                    html += f"<tr><td><strong>{key}</strong></td><td>{value}</td></tr>\n"
            html += "</tbody>\n</table>\n"
        
        html += "</div>\n"
        return html
    
    def _generate_dns_section(self) -> str:
        """Generate DNS section HTML."""
        html = "<h2>🌐 DNS Records</h2>\n<div class='section'>\n"
        
        dns = self.report_data["dns"]
        
        for record_type, records in dns.items():
            if records:
                html += f"<h3>{record_type} Records</h3>\n"
                for record in records:
                    html += f"<div class='record-item'>{record}</div>\n"
            else:
                html += f"<p><em>No {record_type} records found</em></p>\n"
        
        html += "</div>\n"
        return html
    
    def _generate_subdomains_section(self) -> str:
        """Generate Subdomains section HTML."""
        html = "<h2>🔗 Subdomains</h2>\n<div class='section'>\n"
        
        subdomains = self.report_data["subdomains"]
        
        if subdomains:
            html += f"<div class='stats'>\n"
            html += f"<div class='stat-box'><h3>{len(subdomains)}</h3><p>Subdomains Found</p></div>\n"
            html += f"</div>\n"
            
            html += "<ul>\n"
            for subdomain in subdomains:
                html += f"<li><code>{subdomain}</code></li>\n"
            html += "</ul>\n"
        else:
            html += "<div class='no-data'>No subdomains found</div>\n"
        
        html += "</div>\n"
        return html
    
    def _generate_username_section(self) -> str:
        """Generate Username findings section HTML."""
        html = "<h2>👤 Username Findings</h2>\n<div class='section'>\n"
        
        username_data = self.report_data["usernames"]
        
        if username_data:
            found = username_data.get("found", [])
            not_found = username_data.get("not_found", [])
            errors = username_data.get("errors", [])
            
            # Stats
            html += f"<div class='stats'>\n"
            html += f"<div class='stat-box found' style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);'><h3>{len(found)}</h3><p>Accounts Found</p></div>\n"
            html += f"<div class='stat-box' style='background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);'><h3>{len(not_found)}</h3><p>Not Found</p></div>\n"
            html += f"<div class='stat-box' style='background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);'><h3>{len(errors)}</h3><p>Errors</p></div>\n"
            html += f"</div>\n"
            
            # Found accounts
            if found:
                html += "<h3 class='success'>✅ Found Accounts</h3>\n"
                html += "<table>\n<thead><tr><th>Platform</th><th>URL</th></tr></thead>\n<tbody>\n"
                for account in found:
                    html += f"<tr><td>{account['platform']}</td><td><a class='url' href='{account['url']}' target='_blank'>{account['url']}</a></td></tr>\n"
                html += "</tbody>\n</table>\n"
            
            # Not found
            if not_found:
                html += f"<h3 class='error'>❌ Not Found ({len(not_found)} platforms)</h3>\n"
                platforms = [acc['platform'] for acc in not_found]
                html += f"<p>{', '.join(platforms)}</p>\n"
            
            # Errors
            if errors:
                html += f"<h3>⚠️ Errors ({len(errors)} platforms)</h3>\n"
                for error in errors:
                    html += f"<p><strong>{error['platform']}:</strong> {error.get('error', 'Unknown')}</p>\n"
        else:
            html += "<div class='no-data'>No username data available</div>\n"
        
        html += "</div>\n"
        return html
    
    def generate_html_report(self, filename: Optional[str] = None) -> str:
        """
        Generate an HTML report.
        
        Args:
            filename (str, optional): Custom filename. Auto-generated if None
            
        Returns:
            str: Path to generated HTML file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self.target.replace(".", "_") if self.target else "report"
            filename = f"{target_name}_{timestamp}.html"
        
        # Ensure .html extension
        if not filename.endswith(".html"):
            filename += ".html"
        
        filepath = self.output_dir / filename
        
        # Generate HTML content
        html_content = self._generate_html_content()
        
        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"✅ HTML Report generated: {filepath}")
        return str(filepath)
    
    def generate_pdf_report(self, filename: Optional[str] = None) -> Optional[str]:
        """
        Generate a PDF report.
        Note: Requires fpdf library. Falls back to HTML if PDF generation fails.
        
        Args:
            filename (str, optional): Custom filename. Auto-generated if None
            
        Returns:
            str: Path to generated PDF file, or None if PDF generation failed
        """
        try:
            from fpdf import FPDF
            
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                target_name = self.target.replace(".", "_") if self.target else "report"
                filename = f"{target_name}_{timestamp}.pdf"
            
            # Ensure .pdf extension
            if not filename.endswith(".pdf"):
                filename += ".pdf"
            
            filepath = self.output_dir / filename
            
            # Create PDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            
            # Title
            pdf.cell(0, 10, self.investigation_title, 0, 1, "C")
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 10, f"Target: {self.target or 'Not specified'}", 0, 1)
            pdf.cell(0, 10, f"Generated: {self.investigation_date}", 0, 1)
            pdf.ln(5)
            
            # WHOIS Section
            if self.report_data["whois"] and "error" not in self.report_data["whois"]:
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, "WHOIS Information", 0, 1)
                pdf.set_font("Arial", "", 9)
                for key, value in self.report_data["whois"].items():
                    # Wrap long text
                    value_str = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
                    pdf.cell(0, 5, f"{key}: {value_str}", 0, 1)
                pdf.ln(3)
            
            # DNS Section
            if self.report_data["dns"]:
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, "DNS Records", 0, 1)
                pdf.set_font("Arial", "", 9)
                for record_type, records in self.report_data["dns"].items():
                    if records:
                        pdf.cell(0, 5, f"{record_type}: {', '.join(records[:2])}", 0, 1)
                pdf.ln(3)
            
            # Subdomains Section
            if self.report_data["subdomains"]:
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, f"Subdomains ({len(self.report_data['subdomains'])} found)", 0, 1)
                pdf.set_font("Arial", "", 9)
                pdf.cell(0, 5, ", ".join(self.report_data["subdomains"][:5]), 0, 1)
                if len(self.report_data["subdomains"]) > 5:
                    pdf.cell(0, 5, f"... and {len(self.report_data['subdomains'])-5} more", 0, 1)
                pdf.ln(3)
            
            # Username Section
            if self.report_data["usernames"]:
                pdf.set_font("Arial", "B", 12)
                found = len(self.report_data["usernames"].get("found", []))
                pdf.cell(0, 10, f"Username Findings ({found} accounts found)", 0, 1)
                pdf.set_font("Arial", "", 9)
                for account in self.report_data["usernames"].get("found", [])[:5]:
                    pdf.cell(0, 5, f"- {account['platform']}: {account['url'][:50]}", 0, 1)
            
            # Save PDF
            pdf.output(str(filepath))
            print(f"✅ PDF Report generated: {filepath}")
            return str(filepath)
        
        except ImportError:
            print("⚠️  FPDF not available. Generating HTML report instead.")
            return self.generate_html_report(filename)
        except Exception as e:
            print(f"❌ Error generating PDF: {e}. Generating HTML instead.")
            return self.generate_html_report(filename)
    
    def generate_json_report(self, filename: Optional[str] = None) -> str:
        """
        Generate a JSON report for easy parsing and data exchange.
        
        Args:
            filename (str, optional): Custom filename. Auto-generated if None
            
        Returns:
            str: Path to generated JSON file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = self.target.replace(".", "_") if self.target else "report"
            filename = f"{target_name}_{timestamp}.json"
        
        # Ensure .json extension
        if not filename.endswith(".json"):
            filename += ".json"
        
        filepath = self.output_dir / filename
        
        # Create JSON data
        json_data = {
            "report_info": {
                "title": self.investigation_title,
                "target": self.target,
                "generated": self.investigation_date
            },
            "data": self.report_data
        }
        
        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        
        print(f"✅ JSON Report generated: {filepath}")
        return str(filepath)


# Example usage / Testing function
def example_report_generation():
    """
    Example function showing how to use the ReportGenerator class.
    """
    print("\n📄 Report Generator Module - Example\n")
    
    # Create report generator
    report = ReportGenerator(output_dir="reports")
    report.set_title("OSINT Investigation - google.com")
    report.set_target("google.com")
    
    # Add sample WHOIS data
    whois_data = {
        "Domain": "google.com",
        "Registrar": "MarkMonitor, Inc.",
        "Created Date": "1997-09-15",
        "Expiration Date": "2028-09-14",
        "Updated Date": "2019-09-09",
        "Name Servers": "NS1.GOOGLE.COM, NS2.GOOGLE.COM"
    }
    report.add_whois_data(whois_data)
    
    # Add sample DNS data
    dns_data = {
        "A": ["142.250.182.238"],
        "MX": ["10 smtp.google.com"],
        "NS": ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"],
        "TXT": [],
        "CNAME": [],
        "SOA": ["ns1.google.com. dns-admin.google.com. 917729926 900 900 1800 60"]
    }
    report.add_dns_data(dns_data)
    
    # Add sample subdomain data
    subdomains = [
        "www.google.com",
        "mail.google.com",
        "api.google.com",
        "docs.google.com",
        "drive.google.com"
    ]
    report.add_subdomain_data(subdomains)
    
    # Add sample username data
    username_data = {
        "found": [
            {"platform": "GitHub", "url": "https://github.com/google"},
            {"platform": "Twitter", "url": "https://twitter.com/google"}
        ],
        "not_found": [
            {"platform": "Custom Username"}
        ],
        "errors": []
    }
    report.add_username_data(username_data)
    
    # Generate reports
    print("="*70)
    print("Generating OSINT Reports")
    print("="*70 + "\n")
    
    html_path = report.generate_html_report()
    json_path = report.generate_json_report()
    pdf_path = report.generate_pdf_report()
    
    print(f"\n✅ All reports generated successfully!")
    print(f"\nReports saved in: {report.output_dir}")


if __name__ == "__main__":
    # Run example when module is executed directly
    example_report_generation()
