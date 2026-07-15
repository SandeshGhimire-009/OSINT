#!/usr/bin/env python3
"""
Subdomain Enumerator Module
Discovers subdomains of a target domain using DNS resolution and wordlist approach.
"""

import dns.resolver
import dns.exception
from typing import List, Dict, Optional
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class SubdomainEnumerator:
    """
    A class to enumerate subdomains of a target domain.
    This tool tries common subdomain names and checks if they resolve via DNS.
    """
    
    # Common subdomain wordlist (most frequently used subdomains)
    COMMON_SUBDOMAINS = [
        # Web services
        "www", "web", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        
        # Admin/Management
        "admin", "administrator", "administrator-access", "cp", "cpanel", "manager", "management",
        "backend", "dashboard", "control-panel",
        
        # API/Development
        "api", "api-v1", "api-v2", "api-v3", "api.v1", "rest", "json", "graphql", "dev", "develop",
        "development", "staging", "stage", "beta", "test", "testing", "qa", "sandbox",
        
        # CDN/Content Delivery
        "cdn", "cdn-cdn", "static", "staticfiles", "assets", "images", "media", "video", "videos",
        
        # Cloud Services
        "aws", "azure", "cloud", "backup", "storage", "s3",
        
        # Monitoring/Analytics
        "analytics", "monitoring", "monitor", "status", "stats", "logs", "log",
        
        # Mail/Communication
        "email", "mail", "smtp", "imap", "pop3", "exchange", "slack", "teams", "chat",
        
        # Database/Backend
        "db", "database", "mysql", "postgres", "sql", "redis", "mongo", "mongodb",
        
        # VPN/Remote Access
        "vpn", "proxy", "socks", "openvpn", "wireguard",
        
        # File Sharing
        "dropbox", "drive", "share", "shared", "files", "downloads", "upload", "uploads",
        
        # Support/Help
        "help", "support", "docs", "documentation", "wiki", "forum", "forums", "community",
        
        # Other common services
        "git", "svn", "jenkins", "docker", "kubernetes", "prometheus", "grafana",
        "elasticsearch", "kibana", "splunk", "jira", "confluence", "slack",
    ]
    
    def __init__(self, domain: str, wordlist: Optional[List[str]] = None, threads: int = 10):
        """
        Initialize the subdomain enumerator.
        
        Args:
            domain (str): The target domain (e.g., 'google.com')
            wordlist (list, optional): Custom wordlist of subdomains. Uses built-in if None
            threads (int): Number of parallel threads for faster enumeration (default: 10)
        """
        self.domain = domain.lower().strip()
        self.wordlist = wordlist if wordlist else self.COMMON_SUBDOMAINS
        self.threads = threads
        self.found_subdomains = []
        self.error = None
    
    def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """
        Check if a subdomain exists by attempting DNS resolution.
        This is run in parallel threads for speed.
        
        Args:
            subdomain (str): The subdomain to check (without domain)
            
        Returns:
            str: The subdomain if found, None if not found
        """
        try:
            # Build full subdomain name
            full_domain = f"{subdomain}.{self.domain}"
            
            # Create resolver with timeouts
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 4
            
            # Try to resolve the subdomain
            answers = resolver.resolve(full_domain, "A", raise_on_no_answer=False)
            
            # If we got answers, the subdomain exists
            if answers:
                return subdomain
        
        except (dns.exception.DNSException, Exception):
            # Subdomain doesn't exist or couldn't be resolved
            pass
        
        return None
    
    def enumerate(self, show_progress: bool = True) -> List[str]:
        """
        Perform subdomain enumeration using parallel DNS resolution.
        Uses multithreading to check multiple subdomains simultaneously.
        
        Args:
            show_progress (bool): Print progress during enumeration
            
        Returns:
            list: List of found subdomains
        """
        self.found_subdomains = []
        
        if show_progress:
            print(f"\n🔍 Enumerating subdomains for {self.domain}...")
            print(f"📋 Testing {len(self.wordlist)} common subdomains with {self.threads} threads\n")
        
        # Use ThreadPoolExecutor for parallel DNS queries
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all subdomain checks
            future_to_subdomain = {
                executor.submit(self._check_subdomain, subdomain): subdomain 
                for subdomain in self.wordlist
            }
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_subdomain):
                completed += 1
                result = future.result()
                
                if result:
                    self.found_subdomains.append(result)
                    if show_progress:
                        print(f"   ✅ Found: {result}.{self.domain}")
                
                if show_progress and completed % 10 == 0:
                    print(f"   ⏳ Progress: {completed}/{len(self.wordlist)} checked", end="\r")
        
        if show_progress:
            print(f"   ✨ Enumeration complete!                        ")
        
        return self.found_subdomains
    
    def get_found_subdomains(self) -> List[str]:
        """
        Get list of found subdomains.
        
        Returns:
            list: Found subdomains
        """
        return self.found_subdomains
    
    def get_full_domain_names(self) -> List[str]:
        """
        Get found subdomains with full domain names.
        
        Returns:
            list: Full domain names (subdomain.domain.com)
        """
        return [f"{sub}.{self.domain}" for sub in self.found_subdomains]
    
    def add_custom_wordlist(self, wordlist: List[str]):
        """
        Replace the wordlist with a custom one.
        
        Args:
            wordlist (list): New wordlist of subdomains to test
        """
        self.wordlist = wordlist
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get enumeration statistics.
        
        Returns:
            dict: Statistics about the enumeration
        """
        return {
            "total_tested": len(self.wordlist),
            "found": len(self.found_subdomains),
            "not_found": len(self.wordlist) - len(self.found_subdomains),
            "success_rate": f"{(len(self.found_subdomains) / len(self.wordlist) * 100):.1f}%" if self.wordlist else "0%"
        }
    
    def print_results(self):
        """Pretty print subdomain enumeration results."""
        if not self.found_subdomains:
            print(f"\n❌ No subdomains found for {self.domain}")
            return
        
        print("\n" + "="*60)
        print(f"Subdomain Enumeration Results for: {self.domain.upper()}")
        print("="*60)
        
        print(f"\n🎯 Found {len(self.found_subdomains)} subdomain(s):\n")
        
        for i, subdomain in enumerate(self.found_subdomains, 1):
            full_domain = f"{subdomain}.{self.domain}"
            print(f"   {i}. {full_domain}")
        
        # Print statistics
        stats = self.get_statistics()
        print(f"\n📊 Statistics:")
        print(f"   • Total Tested: {stats['total_tested']}")
        print(f"   • Found: {stats['found']}")
        print(f"   • Success Rate: {stats['success_rate']}")
        
        print("\n" + "="*60 + "\n")


# Example usage / Testing function
def example_subdomain_enumeration():
    """
    Example function showing how to use the SubdomainEnumerator class.
    """
    print("\n🔍 Subdomain Enumerator Module - Example\n")
    
    # Example 1: Enumerate subdomains for Google
    print("="*60)
    print("Example 1: Enumerating subdomains for google.com")
    print("="*60)
    
    enum_google = SubdomainEnumerator("google.com", threads=10)
    subdomains = enum_google.enumerate(show_progress=True)
    enum_google.print_results()
    
    # Example 2: Enumerate subdomains for GitHub
    print("\n" + "="*60)
    print("Example 2: Enumerating subdomains for github.com")
    print("="*60)
    
    enum_github = SubdomainEnumerator("github.com", threads=10)
    subdomains = enum_github.enumerate(show_progress=True)
    enum_github.print_results()
    
    # Example 3: Custom wordlist
    print("\n" + "="*60)
    print("Example 3: Using custom wordlist")
    print("="*60)
    
    custom_words = ["www", "mail", "ftp", "admin", "api", "dev"]
    enum_custom = SubdomainEnumerator("example.com", wordlist=custom_words, threads=5)
    subdomains = enum_custom.enumerate(show_progress=True)
    enum_custom.print_results()


if __name__ == "__main__":
    # Run example when module is executed directly
    example_subdomain_enumeration()
