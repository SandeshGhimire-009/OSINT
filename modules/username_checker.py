#!/usr/bin/env python3
"""
Username Checker Module
Checks if a username exists on various social media and online platforms.
Useful for OSINT investigations to find associated accounts.
"""

import requests
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class UsernameChecker:
    """
    A class to check if a username exists on multiple platforms.
    Uses HTTP requests to verify account existence across social media and websites.
    """
    
    # Platform database with URLs and detection patterns
    PLATFORMS = {
        # Social Media
        "Twitter": {
            "url": "https://twitter.com/{}",
            "status_code": 200,
            "note": "Check Twitter/X profile"
        },
        "Instagram": {
            "url": "https://instagram.com/{}/",
            "status_code": 200,
            "note": "Check Instagram profile"
        },
        "TikTok": {
            "url": "https://www.tiktok.com/@{}",
            "status_code": 200,
            "note": "Check TikTok profile"
        },
        "YouTube": {
            "url": "https://www.youtube.com/@{}",
            "status_code": 200,
            "note": "Check YouTube channel"
        },
        "LinkedIn": {
            "url": "https://www.linkedin.com/in/{}",
            "status_code": 200,
            "note": "Check LinkedIn profile"
        },
        "Facebook": {
            "url": "https://www.facebook.com/{}",
            "status_code": 200,
            "note": "Check Facebook profile"
        },
        
        # Developer Platforms
        "GitHub": {
            "url": "https://github.com/{}",
            "status_code": 200,
            "note": "Check GitHub profile"
        },
        "GitLab": {
            "url": "https://gitlab.com/{}",
            "status_code": 200,
            "note": "Check GitLab profile"
        },
        "Bitbucket": {
            "url": "https://bitbucket.org/{}",
            "status_code": 200,
            "note": "Check Bitbucket profile"
        },
        
        # Programming/Tech Communities
        "Stack Overflow": {
            "url": "https://stackoverflow.com/users/-1/{}",
            "status_code": 200,
            "note": "Check Stack Overflow profile"
        },
        "Reddit": {
            "url": "https://www.reddit.com/user/{}",
            "status_code": 200,
            "note": "Check Reddit profile"
        },
        "Dev.to": {
            "url": "https://dev.to/{}",
            "status_code": 200,
            "note": "Check Dev.to profile"
        },
        
        # Other Platforms
        "Twitch": {
            "url": "https://www.twitch.tv/{}",
            "status_code": 200,
            "note": "Check Twitch channel"
        },
        "Discord": {
            "url": "https://discordapp.com/users/{}",
            "status_code": 200,
            "note": "Check Discord user (ID required)"
        },
        "Pinterest": {
            "url": "https://www.pinterest.com/{}/",
            "status_code": 200,
            "note": "Check Pinterest profile"
        },
        "Telegram": {
            "url": "https://t.me/{}",
            "status_code": 200,
            "note": "Check Telegram username"
        },
    }
    
    def __init__(self, username: str, threads: int = 5, timeout: int = 10):
        """
        Initialize the username checker.
        
        Args:
            username (str): Username to check
            threads (int): Number of parallel threads for checking (default: 5)
            timeout (int): Timeout for each request in seconds (default: 10)
        """
        self.username = username.strip()
        self.threads = threads
        self.timeout = timeout
        self.found_accounts = []
        self.not_found = []
        self.errors = []
    
    def _check_platform(self, platform: str, url_template: str) -> Dict[str, Optional[str]]:
        """
        Check if username exists on a specific platform.
        Performs HTTP request and checks response status.
        
        Args:
            platform (str): Name of the platform
            url_template (str): URL template with {} placeholder for username
            
        Returns:
            dict: Result with platform name and status
        """
        try:
            # Build the full URL with username
            url = url_template.format(self.username)
            
            # Set headers to mimic browser request (some sites block requests without headers)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # Make HTTP request with timeout
            response = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            
            # Check if profile exists based on status code
            if response.status_code == 200:
                return {
                    "platform": platform,
                    "status": "found",
                    "url": url,
                    "http_status": response.status_code
                }
            elif response.status_code == 404:
                return {
                    "platform": platform,
                    "status": "not_found",
                    "url": url,
                    "http_status": response.status_code
                }
            else:
                # Some platforms use different status codes
                return {
                    "platform": platform,
                    "status": "unknown",
                    "url": url,
                    "http_status": response.status_code
                }
        
        except requests.exceptions.Timeout:
            return {
                "platform": platform,
                "status": "error",
                "error": "Request timeout"
            }
        except requests.exceptions.ConnectionError:
            return {
                "platform": platform,
                "status": "error",
                "error": "Connection failed"
            }
        except Exception as e:
            return {
                "platform": platform,
                "status": "error",
                "error": str(e)
            }
    
    def check_all(self, show_progress: bool = True) -> Dict[str, list]:
        """
        Check username on all platforms in parallel.
        Uses multithreading to check multiple platforms simultaneously.
        
        Args:
            show_progress (bool): Print progress during checking
            
        Returns:
            dict: Results organized by found/not found/errors
        """
        self.found_accounts = []
        self.not_found = []
        self.errors = []
        
        if show_progress:
            print(f"\n🔍 Checking username '{self.username}' across {len(self.PLATFORMS)} platforms...")
            print(f"📡 Using {self.threads} parallel threads\n")
        
        # Use ThreadPoolExecutor for parallel checking
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all platform checks
            future_to_platform = {
                executor.submit(self._check_platform, platform, data["url"]): platform
                for platform, data in self.PLATFORMS.items()
            }
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_platform):
                completed += 1
                result = future.result()
                platform = result["platform"]
                status = result["status"]
                
                if status == "found":
                    self.found_accounts.append(result)
                    if show_progress:
                        print(f"   ✅ FOUND: {platform}")
                elif status == "not_found":
                    self.not_found.append(result)
                    if show_progress:
                        print(f"   ❌ Not found: {platform}")
                else:
                    self.errors.append(result)
                    if show_progress:
                        print(f"   ⚠️  Error on {platform}: {result.get('error', 'Unknown error')}")
                
                if show_progress and completed % 5 == 0:
                    print(f"   ⏳ Progress: {completed}/{len(self.PLATFORMS)} checked", end="\r")
        
        if show_progress:
            print(f"   ✨ Check complete!                          ")
        
        return {
            "found": self.found_accounts,
            "not_found": self.not_found,
            "errors": self.errors
        }
    
    def check_specific_platforms(self, platform_list: List[str]) -> Dict[str, list]:
        """
        Check username on specific platforms only.
        
        Args:
            platform_list (list): List of platform names to check
            
        Returns:
            dict: Results for specified platforms
        """
        print(f"\n🔍 Checking username '{self.username}' on {len(platform_list)} specific platforms...\n")
        
        self.found_accounts = []
        self.not_found = []
        self.errors = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_platform = {
                executor.submit(self._check_platform, platform, self.PLATFORMS[platform]["url"]): platform
                for platform in platform_list if platform in self.PLATFORMS
            }
            
            for future in as_completed(future_to_platform):
                result = future.result()
                status = result["status"]
                
                if status == "found":
                    self.found_accounts.append(result)
                    print(f"   ✅ FOUND: {result['platform']}")
                elif status == "not_found":
                    self.not_found.append(result)
                    print(f"   ❌ Not found: {result['platform']}")
                else:
                    self.errors.append(result)
                    print(f"   ⚠️  Error on {result['platform']}")
        
        return {
            "found": self.found_accounts,
            "not_found": self.not_found,
            "errors": self.errors
        }
    
    def get_found_accounts(self) -> List[Dict]:
        """Get list of found accounts."""
        return self.found_accounts
    
    def get_account_urls(self) -> List[str]:
        """Get URLs of found accounts."""
        return [account["url"] for account in self.found_accounts]
    
    def get_statistics(self) -> Dict[str, int]:
        """Get checking statistics."""
        total = len(self.found_accounts) + len(self.not_found) + len(self.errors)
        return {
            "total_checked": total,
            "found": len(self.found_accounts),
            "not_found": len(self.not_found),
            "errors": len(self.errors)
        }
    
    def print_results(self):
        """Pretty print username checking results."""
        stats = self.get_statistics()
        
        print("\n" + "="*70)
        print(f"Username Lookup Results for: '{self.username.upper()}'")
        print("="*70)
        
        # Found accounts
        if self.found_accounts:
            print(f"\n✅ FOUND ON {len(self.found_accounts)} PLATFORM(S):\n")
            for i, account in enumerate(self.found_accounts, 1):
                print(f"   {i}. {account['platform']}")
                print(f"      🔗 {account['url']}")
        else:
            print(f"\n❌ Not found on any checked platforms")
        
        # Not found
        if self.not_found:
            print(f"\n❌ NOT FOUND ON {len(self.not_found)} PLATFORM(S):")
            platforms = [acc['platform'] for acc in self.not_found]
            print(f"   {', '.join(platforms)}")
        
        # Errors
        if self.errors:
            print(f"\n⚠️  ERRORS ON {len(self.errors)} PLATFORM(S):")
            for error in self.errors:
                print(f"   • {error['platform']}: {error.get('error', 'Unknown')}")
        
        # Statistics
        print(f"\n📊 STATISTICS:")
        print(f"   • Total Checked: {stats['total_checked']}")
        print(f"   • Found: {stats['found']}")
        print(f"   • Not Found: {stats['not_found']}")
        print(f"   • Errors: {stats['errors']}")
        
        print("\n" + "="*70 + "\n")


# Example usage / Testing function
def example_username_checking():
    """
    Example function showing how to use the UsernameChecker class.
    """
    print("\n🔍 Username Checker Module - Example\n")
    
    # Example 1: Check a common username across all platforms
    print("="*70)
    print("Example 1: Checking username 'sandesh009' across all platforms")
    print("="*70)
    
    checker1 = UsernameChecker("sandesh009", threads=5)
    results1 = checker1.check_all(show_progress=True)
    checker1.print_results()
    
    # Example 2: Check a different username
    print("\n" + "="*70)
    print("Example 2: Checking username 'torvalds' (Linux creator)")
    print("="*70)
    
    checker2 = UsernameChecker("torvalds", threads=5)
    results2 = checker2.check_all(show_progress=True)
    checker2.print_results()
    
    # Example 3: Check specific platforms only
    print("\n" + "="*70)
    print("Example 3: Checking username 'elon' on specific platforms")
    print("="*70)
    
    checker3 = UsernameChecker("elon", threads=5)
    platforms_to_check = ["Twitter", "GitHub", "LinkedIn", "Instagram"]
    results3 = checker3.check_specific_platforms(platforms_to_check)
    checker3.print_results()


if __name__ == "__main__":
    # Run example when module is executed directly
    example_username_checking()
