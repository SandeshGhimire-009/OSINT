#!/usr/bin/env python3
"""
WHOIS Lookup Module
Retrieves domain registration information including registrar, expiration dates, nameservers, etc.
"""

import whois
from datetime import datetime
from typing import Dict, Optional

class WHOISLookup:
    """
    A class to perform WHOIS lookups on domain names.
    WHOIS is a protocol that returns detailed information about domain registration.
    """
    
    def __init__(self, domain: str):
        """
        Initialize the WHOIS lookup with a domain name.
        
        Args:
            domain (str): The domain name to lookup (e.g., 'google.com')
        """
        self.domain = domain.lower().strip()
        self.whois_data = None
        self.error = None
    
    def lookup(self) -> bool:
        """
        Perform the WHOIS lookup for the domain.
        
        Returns:
            bool: True if lookup successful, False if failed
        """
        try:
            # Query WHOIS servers for domain information
            self.whois_data = whois.whois(self.domain)
            return True
        except whois.parser.PywhoisError as e:
            # Handles cases where domain doesn't exist or WHOIS server unavailable
            self.error = f"WHOIS Query Failed: Domain may not exist or WHOIS servers unreachable"
            return False
        except Exception as e:
            # Catch any other unexpected errors
            self.error = f"Error during WHOIS lookup: {str(e)}"
            return False
    
    def get_formatted_results(self) -> Dict[str, Optional[str]]:
        """
        Extract and format the most important WHOIS information.
        
        Returns:
            dict: Formatted WHOIS data with key information
        """
        if not self.whois_data:
            return {"error": self.error}
        
        # Helper function to convert lists to strings (WHOIS sometimes returns lists)
        def format_field(value):
            if isinstance(value, list):
                return value[0] if value else "Not available"
            return str(value) if value else "Not available"
        
        # Extract key information from WHOIS data
        results = {
            "Domain": format_field(self.whois_data.domain),
            "Registrar": format_field(self.whois_data.registrar),
            "Registrant Email": format_field(self.whois_data.registrant_email),
            "Registrant Country": format_field(self.whois_data.registrant_country),
            "Created Date": format_field(self.whois_data.creation_date),
            "Expiration Date": format_field(self.whois_data.expiration_date),
            "Updated Date": format_field(self.whois_data.updated_date),
            "Name Servers": ", ".join(self.whois_data.name_servers) if self.whois_data.name_servers else "Not available",
            "Status": ", ".join(self.whois_data.status) if self.whois_data.status else "Not available",
        }
        
        return results
    
    def is_expired(self) -> Optional[bool]:
        """
        Check if the domain has expired.
        
        Returns:
            bool: True if expired, False if active, None if cannot determine
        """
        try:
            expiration = self.whois_data.expiration_date
            if not expiration:
                return None
            
            # Handle case where expiration_date is a list
            if isinstance(expiration, list):
                expiration = expiration[0]
            
            return datetime.now() > expiration
        except:
            return None
    
    def print_results(self):
        """Pretty print the WHOIS results to console."""
        if self.error:
            print(f"❌ {self.error}")
            return
        
        results = self.get_formatted_results()
        
        print("\n" + "="*60)
        print(f"WHOIS Information for: {self.domain.upper()}")
        print("="*60)
        
        for key, value in results.items():
            print(f"{key:<20}: {value}")
        
        # Check expiration status
        if self.is_expired():
            print("\n⚠️  WARNING: This domain has EXPIRED!")
        elif self.is_expired() is False:
            print("\n✅ Domain is ACTIVE")
        
        print("="*60 + "\n")


# Example usage / Testing function
def example_whois_lookup():
    """
    Example function showing how to use the WHOISLookup class.
    This demonstrates the module functionality for testing.
    """
    print("\n🔍 WHOIS Lookup Module - Example\n")
    
    # Example 1: Lookup Google
    print("Example 1: Looking up google.com...")
    whois_google = WHOISLookup("google.com")
    
    if whois_google.lookup():
        whois_google.print_results()
    else:
        print(f"❌ Lookup failed: {whois_google.error}")
    
    # Example 2: Lookup GitHub
    print("\nExample 2: Looking up github.com...")
    whois_github = WHOISLookup("github.com")
    
    if whois_github.lookup():
        whois_github.print_results()
        results = whois_github.get_formatted_results()
        print(f"Registrar: {results['Registrar']}")
    else:
        print(f"❌ Lookup failed: {whois_github.error}")
    
    # Example 3: Non-existent domain (to show error handling)
    print("\nExample 3: Looking up invalid domain (nonexistentdomain12345.com)...")
    whois_invalid = WHOISLookup("nonexistentdomain12345.com")
    
    if whois_invalid.lookup():
        whois_invalid.print_results()
    else:
        print(f"❌ Lookup failed: {whois_invalid.error}")


if __name__ == "__main__":
    # Run example when module is executed directly
    example_whois_lookup()
