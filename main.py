#!/usr/bin/env python3
"""
OSINT Automation Tool - Main Entry Point
A Python-based CLI tool for gathering publicly available information for cybersecurity investigations.

Usage:
    python main.py --domain google.com
    python main.py --username sandesh009
    python main.py --domain google.com --report
    python main.py --domain github.com --report --all
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

# Import all OSINT modules
from modules.whois_lookup import WHOISLookup
from modules.dns_lookup import DNSLookup
from modules.subdomain_enum import SubdomainEnumerator
from modules.username_checker import UsernameChecker
from modules.report_generator import ReportGenerator

# Rich console for beautiful output
console = Console()

def print_banner():
    """Print a beautiful banner for the tool"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                   🔍 OSINT AUTOMATION TOOL 🔍             ║
    ║     Gather Public Intelligence for Cybersecurity          ║
    ║                                                           ║
    ║  WHOIS Lookup • DNS Records • Subdomain Enum             ║
    ║  Username Checker • Report Generator                      ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")

def investigate_domain(domain: str, generate_report: bool = False, all_modules: bool = False):
    """
    Perform complete domain investigation using all modules.
    
    Args:
        domain (str): Domain to investigate
        generate_report (bool): Whether to generate a report
        all_modules (bool): Run all modules (default is quick mode)
    """
    console.print(f"\n[bold cyan]🔍 Starting Domain Investigation for: {domain}[/bold cyan]\n")
    
    # Initialize report generator if needed
    report = None
    if generate_report:
        report = ReportGenerator(output_dir="reports")
        report.set_title(f"OSINT Investigation Report - {domain}")
        report.set_target(domain)
    
    # ===== WHOIS Lookup =====
    console.print("[bold yellow]1️⃣  WHOIS Lookup[/bold yellow]")
    try:
        whois = WHOISLookup(domain)
        if whois.lookup():
            whois_results = whois.get_formatted_results()
            whois.print_results()
            if report:
                report.add_whois_data(whois_results)
        else:
            console.print(f"[red]❌ WHOIS lookup failed: {whois.error}[/red]\n")
    except Exception as e:
        console.print(f"[red]❌ Error during WHOIS lookup: {str(e)}[/red]\n")
    
    # ===== DNS Lookup =====
    console.print("[bold yellow]2️⃣  DNS Records Lookup[/bold yellow]")
    try:
        dns = DNSLookup(domain)
        if dns.lookup_all():
            dns.print_results()
            if report:
                report.add_dns_data(dns.get_formatted_results())
        else:
            console.print(f"[red]❌ DNS lookup had issues[/red]\n")
    except Exception as e:
        console.print(f"[red]❌ Error during DNS lookup: {str(e)}[/red]\n")
    
    # ===== Subdomain Enumeration =====
    console.print("[bold yellow]3️⃣  Subdomain Enumeration[/bold yellow]")
    try:
        # Use fewer threads for faster results in quick mode
        threads = 10 if all_modules else 10
        enum = SubdomainEnumerator(domain, threads=threads)
        subdomains = enum.enumerate(show_progress=True)
        enum.print_results()
        if report:
            report.add_subdomain_data(subdomains)
    except Exception as e:
        console.print(f"[red]❌ Error during subdomain enumeration: {str(e)}[/red]\n")
    
    # ===== Report Generation =====
    if generate_report:
        console.print("[bold yellow]4️⃣  Generating Reports[/bold yellow]\n")
        try:
            html_path = report.generate_html_report()
            json_path = report.generate_json_report()
            pdf_path = report.generate_pdf_report()
            
            console.print("\n[green]✅ Reports Generated Successfully![/green]")
            console.print(f"[cyan]📁 Reports Location: reports/[/cyan]\n")
        except Exception as e:
            console.print(f"[red]❌ Error generating reports: {str(e)}[/red]\n")

def investigate_username(username: str, generate_report: bool = False):
    """
    Check if username exists on social platforms.
    
    Args:
        username (str): Username to investigate
        generate_report (bool): Whether to generate a report
    """
    console.print(f"\n[bold cyan]🔍 Starting Username Investigation for: {username}[/bold cyan]\n")
    
    try:
        checker = UsernameChecker(username, threads=5)
        results = checker.check_all(show_progress=True)
        checker.print_results()
        
        if generate_report:
            console.print("\n[bold yellow]📄 Generating Report[/bold yellow]\n")
            report = ReportGenerator(output_dir="reports")
            report.set_title(f"Username Investigation Report - {username}")
            report.set_target(username)
            report.add_username_data(results)
            
            html_path = report.generate_html_report()
            json_path = report.generate_json_report()
            pdf_path = report.generate_pdf_report()
            
            console.print("\n[green]✅ Reports Generated Successfully![/green]")
            console.print(f"[cyan]📁 Reports Location: reports/[/cyan]\n")
    
    except Exception as e:
        console.print(f"[red]❌ Error during username investigation: {str(e)}[/red]\n")

def main():
    """Main function to parse arguments and execute OSINT modules"""
    parser = argparse.ArgumentParser(
        description='OSINT Automation Tool - Gather public intelligence for investigations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic domain investigation
  python main.py --domain google.com
  
  # Domain investigation with report
  python main.py --domain google.com --report
  
  # Username search
  python main.py --username sandesh009
  
  # Username search with report
  python main.py --username sandesh009 --report
  
  # Full investigation with all features
  python main.py --domain github.com --report --all

SUPPORTED MODULES:
  • WHOIS Lookup - Domain registration info
  • DNS Records - A, MX, NS, TXT, SOA records
  • Subdomain Enumeration - Find subdomains
  • Username Checker - Check 16+ social platforms
  • Report Generator - HTML, PDF, JSON reports
        """,
        prog='OSINT Tool'
    )
    
    parser.add_argument(
        '--domain',
        type=str,
        metavar='DOMAIN',
        help='Domain name to investigate (e.g., google.com)'
    )
    
    parser.add_argument(
        '--username',
        type=str,
        metavar='USERNAME',
        help='Username to check across social platforms'
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate HTML, PDF, and JSON reports'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all available modules (default: quick mode)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='OSINT Automation Tool v1.0'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Validate input
    if not args.domain and not args.username:
        parser.print_help()
        return 1
    
    if args.domain and args.username:
        console.print("[yellow]⚠️  Warning: Both --domain and --username provided. Running both investigations.\n[/yellow]")
    
    # Run investigations
    try:
        if args.domain:
            investigate_domain(args.domain, generate_report=args.report, all_modules=args.all)
        
        if args.username:
            investigate_username(args.username, generate_report=args.report)
        
        # Success message
        console.print("\n[bold green]✨ OSINT Investigation Complete![/bold green]")
        if args.report:
            console.print("[cyan]📊 Check the 'reports' directory for generated files[/cyan]\n")
        
        return 0
    
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Investigation interrupted by user[/yellow]\n")
        return 130
    except Exception as e:
        console.print(f"\n[red]❌ Fatal Error: {str(e)}[/red]\n")
        return 1

if __name__ == '__main__':
    sys.exit(main())
