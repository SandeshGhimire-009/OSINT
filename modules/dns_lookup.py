#!/usr/bin/env python3
"""
DNS Lookup Module
Retrieves DNS records including A, MX, NS, TXT, CNAME, and SOA records.
"""

import dns.resolver
import dns.exception
from typing import Dict, List, Optional

class DNSLookup:
    """
    A class to query DNS records for a domain.
    DNS (Domain Name System) translates domain names to IP addresses and stores other information.
    """
    
    def __init__(self, domain: str):
        """
        Initialize DNS lookup with a domain name.
        
        Args:
            domain (str): The domain name to query (e.g., 'google.com')
        """
        self.domain = domain.lower().strip()
        self.error = None
        self.records = {
            "A": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": [],
            "SOA": []
        }
    
    def query_record(self, record_type: str) -> bool:
        """
        Query a specific DNS record type.
        
        Args:
            record_type (str): Type of DNS record (A, MX, NS, TXT, CNAME, SOA)
            
        Returns:
            bool: True if successful, False if failed
        """
        try:
            # Create resolver with shorter timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3  # 3 second timeout per query
            resolver.lifetime = 6  # 6 second total lifetime
            
            # Query DNS servers for the specific record type
            answers = resolver.resolve(self.domain, record_type, raise_on_no_answer=False)
            
            # Extract record data
            for rdata in answers:
                self.records[record_type].append(str(rdata))
            
            return True
        
        except dns.exception.DNSException as e:
            # Handle DNS-specific errors (server issues, invalid domain, etc.)
            # Store error but don't fail - might succeed for other record types
            return False
        except Exception as e:
            # Catch any other unexpected errors
            return False
    
    def lookup_all(self) -> bool:
        """
        Perform DNS lookups for all common record types.
        
        Returns:
            bool: True if at least one record type was found
        """
        record_types = ["A", "MX", "NS", "TXT", "CNAME", "SOA"]
        found_any = False
        
        for record_type in record_types:
            if self.query_record(record_type):
                if self.records[record_type]:  # Only count if records were actually found
                    found_any = True
        
        return found_any
    
    def get_a_records(self) -> List[str]:
        """
        Get A records (IPv4 addresses pointing to the domain).
        
        Returns:
            list: List of IP addresses
        """
        return self.records.get("A", [])
    
    def get_mx_records(self) -> List[str]:
        """
        Get MX records (Mail Exchange servers for the domain).
        These servers handle incoming email.
        
        Returns:
            list: List of mail server records with priority
        """
        return self.records.get("MX", [])
    
    def get_ns_records(self) -> List[str]:
        """
        Get NS records (Nameservers that manage the domain's DNS).
        
        Returns:
            list: List of nameserver records
        """
        return self.records.get("NS", [])
    
    def get_txt_records(self) -> List[str]:
        """
        Get TXT records (Text records used for SPF, DKIM, DMARC, etc.).
        These records contain text-based information about the domain.
        
        Returns:
            list: List of TXT records
        """
        return self.records.get("TXT", [])
    
    def get_cname_records(self) -> List[str]:
        """
        Get CNAME records (Canonical Name - aliases for the domain).
        
        Returns:
            list: List of CNAME records
        """
        return self.records.get("CNAME", [])
    
    def get_soa_record(self) -> List[str]:
        """
        Get SOA record (Start of Authority - authoritative information about the domain).
        
        Returns:
            list: List of SOA records
        """
        return self.records.get("SOA", [])
    
    def get_formatted_results(self) -> Dict[str, list]:
        """
        Get all DNS records in a formatted dictionary.
        
        Returns:
            dict: Dictionary with all record types and their values
        """
        return self.records
    
    def print_results(self):
        """Pretty print all DNS records to console."""
        if self.error:
            print(f"❌ {self.error}")
            return
        
        print("\n" + "="*60)
        print(f"DNS Records for: {self.domain.upper()}")
        print("="*60)
        
        # A Records - IPv4 addresses
        print("\n📍 A RECORDS (IPv4 Addresses):")
        if self.get_a_records():
            for record in self.get_a_records():
                print(f"   ➜ {record}")
        else:
            print("   ➜ No A records found")
        
        # MX Records - Mail servers
        print("\n📧 MX RECORDS (Mail Exchange Servers):")
        if self.get_mx_records():
            for record in self.get_mx_records():
                print(f"   ➜ {record}")
        else:
            print("   ➜ No MX records found")
        
        # NS Records - Nameservers
        print("\n🔗 NS RECORDS (Nameservers):")
        if self.get_ns_records():
            for record in self.get_ns_records():
                print(f"   ➜ {record}")
        else:
            print("   ➜ No NS records found")
        
        # TXT Records - Text records (SPF, DKIM, DMARC)
        print("\n📝 TXT RECORDS (SPF, DKIM, DMARC, etc.):")
        if self.get_txt_records():
            for record in self.get_txt_records():
                # Truncate long TXT records for readability
                display_record = record[:80] + "..." if len(record) > 80 else record
                print(f"   ➜ {display_record}")
        else:
            print("   ➜ No TXT records found")
        
        # CNAME Records - Aliases
        print("\n🔄 CNAME RECORDS (Aliases):")
        if self.get_cname_records():
            for record in self.get_cname_records():
                print(f"   ➜ {record}")
        else:
            print("   ➜ No CNAME records found")
        
        # SOA Record - Authority info
        print("\n⚙️  SOA RECORD (Start of Authority):")
        if self.get_soa_record():
            for record in self.get_soa_record():
                display_record = record[:80] + "..." if len(record) > 80 else record
                print(f"   ➜ {display_record}")
        else:
            print("   ➜ No SOA record found")
        
        print("\n" + "="*60 + "\n")


# Example usage / Testing function
def example_dns_lookup():
    """
    Example function showing how to use the DNSLookup class.
    This demonstrates DNS querying for different domains.
    """
    print("\n🔍 DNS Lookup Module - Example\n")
    
    # Example 1: Lookup Google DNS records
    print("Example 1: Looking up DNS records for google.com...")
    dns_google = DNSLookup("google.com")
    
    if dns_google.lookup_all():
        dns_google.print_results()
        
        # Show how to access individual record types
        print("Direct access to A records:")
        for ip in dns_google.get_a_records():
            print(f"  IP: {ip}")
    else:
        print(f"❌ Lookup failed: {dns_google.error}")
    
    # Example 2: Lookup GitHub DNS records
    print("\nExample 2: Looking up DNS records for github.com...")
    dns_github = DNSLookup("github.com")
    
    if dns_github.lookup_all():
        dns_github.print_results()
    else:
        print(f"❌ Lookup failed: {dns_github.error}")
    
    # Example 3: Lookup invalid domain (error handling)
    print("\nExample 3: Looking up invalid domain (nonexistentdomain12345.com)...")
    dns_invalid = DNSLookup("nonexistentdomain12345.com")
    
    if dns_invalid.lookup_all():
        dns_invalid.print_results()
    else:
        print(f"❌ Lookup failed: {dns_invalid.error}")


if __name__ == "__main__":
    # Run example when module is executed directly
    example_dns_lookup()
