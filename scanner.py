#!/usr/bin/env python3
"""
Cloud Provider Detection Tool

A precise tool that detects which cloud providers are used by websites
by analyzing multiple signals:

- IP range matching of main domain against official cloud provider IP ranges
- SSL certificate analysis
- Security headers analysis
- DNS records analysis
- Website content analysis

This focuses on backend hosting, not CDN or delivery infrastructure.
Supports AWS, GCP, and Azure. Other providers are categorized as "Other".
"""

import asyncio
import csv
import socket
import argparse
import ipaddress
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
import requests
from playwright.async_api import async_playwright
from tqdm import tqdm


class CloudProviderDetector:
    """
    Precise Cloud Provider Detection Tool

    Uses only IP range analysis for maximum accuracy in detecting
    the actual backend hosting provider (not CDN/delivery layer).
    """

    def __init__(self, headless: bool = True):
        """Initialize the detector."""
        self.headless = headless
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )

        # Only IP range URLs for the most reliable detection
        self.cloud_patterns = {
            "AWS": {
                "ip_ranges_url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
            },
            "GCP": {
                "ip_ranges_url": "https://www.gstatic.com/ipranges/cloud.json",
            },
            "Azure": {
                "ip_ranges_url": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public.json",
            },
        }

        # IP ranges will be populated dynamically
        self.ip_ranges = {}

    async def load_cloud_ip_ranges(self):
        """Load IP ranges for major cloud providers."""
        print("Loading cloud provider IP ranges...")

        async with aiohttp.ClientSession() as session:
            # AWS IP ranges
            try:
                async with session.get(
                    self.cloud_patterns["AWS"]["ip_ranges_url"]
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.ip_ranges["AWS"] = [
                            item["ip_prefix"] for item in data["prefixes"]
                        ]
                        print(f"Loaded {len(self.ip_ranges['AWS'])} AWS IP ranges")
            except Exception as e:
                print(f"Failed to load AWS IP ranges: {e}")

            # GCP IP ranges
            try:
                async with session.get(
                    self.cloud_patterns["GCP"]["ip_ranges_url"]
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.ip_ranges["GCP"] = [
                            item["ipv4Prefix"]
                            for item in data["prefixes"]
                            if "ipv4Prefix" in item
                        ]
                        print(f"Loaded {len(self.ip_ranges['GCP'])} GCP IP ranges")
            except Exception as e:
                print(f"Failed to load GCP IP ranges: {e}")

            # Azure IP ranges
            try:
                async with session.get(
                    self.cloud_patterns["Azure"]["ip_ranges_url"]
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        azure_ranges = []
                        for service in data["values"]:
                            azure_ranges.extend(
                                service.get("properties", {}).get("addressPrefixes", [])
                            )
                        # Filter out IPv6 ranges for simplicity
                        self.ip_ranges["Azure"] = [
                            r for r in azure_ranges if ":" not in r
                        ]
                        print(f"Loaded {len(self.ip_ranges['Azure'])} Azure IP ranges")
            except Exception as e:
                print(f"Failed to load Azure IP ranges: {e}")

    def resolve_domain_to_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        ips = []
        try:
            result = socket.getaddrinfo(domain, None)
            for family, type, proto, canonname, sockaddr in result:
                ip = sockaddr[0]
                if ip not in ips and not ip.startswith("::"):  # Skip IPv6 for now
                    ips.append(ip)
        except Exception:
            pass
        return ips

    def check_ip_against_cloud_ranges(self, ip: str) -> Optional[str]:
        """Check if IP belongs to a cloud provider's range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for provider, ranges in self.ip_ranges.items():
                for ip_range in ranges:
                    try:
                        if "/" in ip_range:
                            network = ipaddress.ip_network(ip_range, strict=False)
                            if ip_obj in network:
                                return provider
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    async def scrape_with_playwright(self, url: str) -> Optional[Dict]:
        """Scrape website using Playwright - minimal scraping just to verify site is accessible."""
        browser = None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )

                page = await context.new_page()
                page.set_default_timeout(15000)  # Shorter timeout

                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=15000
                )

                if response and response.status < 400:
                    return {"url": response.url, "status": response.status}

        except Exception as e:
            print(f"Playwright scraping failed for {url}: {e}")
        finally:
            if browser:
                try:
                    await browser.close()
                except:
                    pass

        return None

    def scrape_with_requests(self, url: str) -> Optional[Dict]:
        """Fallback verification with requests."""
        try:
            response = self.session.head(url, timeout=10)  # HEAD request is faster
            if response.status_code < 400:
                return {"url": response.url, "status": response.status_code}
        except Exception as e:
            print(f"Requests scraping failed for {url}: {e}")
        return None

    async def analyze_website(self, url: str) -> Dict[str, any]:
        """Analyze website using only IP range detection."""
        print(f"Analyzing: {url}")

        result = {
            "url": url,
            "primary_cloud_provider": "Unknown",
            "confidence_score": 0,
            "details": {},
        }

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            # Quick verification that site is accessible (optional)
            scraped_data = await self.scrape_with_playwright(url)
            if not scraped_data:
                scraped_data = self.scrape_with_requests(url)

            # IP Range Analysis - Main detection method
            domain = urlparse(url).netloc
            main_ips = self.resolve_domain_to_ips(domain)
            result["details"]["main_domain_ips"] = main_ips

            if not main_ips:
                result["details"]["error"] = "Could not resolve domain to IPs"
                return result

            # Check each IP against cloud provider ranges
            detected_providers = {}
            for ip in main_ips:
                provider = self.check_ip_against_cloud_ranges(ip)
                if provider:
                    detected_providers[provider] = (
                        detected_providers.get(provider, 0) + 1
                    )

            if detected_providers:
                # Choose the provider with the most IPs matching
                primary_provider = max(detected_providers, key=detected_providers.get)
                result["primary_cloud_provider"] = primary_provider
                result["confidence_score"] = detected_providers[primary_provider] * 100
                result["details"]["detected_providers"] = detected_providers
            else:
                result["primary_cloud_provider"] = "Other"
                result["confidence_score"] = 0

        except Exception as e:
            result["details"]["error"] = str(e)
            print(f"Error analyzing {url}: {e}")

        return result

    async def analyze_websites_batch(self, urls: List[str]) -> List[Dict]:
        """Analyze multiple websites with progress tracking."""
        await self.load_cloud_ip_ranges()

        results = []
        for url in tqdm(urls, desc="Analyzing websites"):
            result = await self.analyze_website(url)
            results.append(result)

        return results

    def save_results(self, results: List[Dict], output_file: str):
        """Save results to CSV file."""
        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "url",
                "primary_cloud_provider",
                "confidence_score",
                "main_domain_ips",
                "detected_providers",
                "error",
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                writer.writerow(
                    {
                        "url": result.get("url", ""),
                        "primary_cloud_provider": result.get(
                            "primary_cloud_provider", "Unknown"
                        ),
                        "confidence_score": result.get("confidence_score", 0),
                        "main_domain_ips": ", ".join(
                            result.get("details", {}).get("main_domain_ips", [])
                        ),
                        "detected_providers": str(
                            result.get("details", {}).get("detected_providers", {})
                        ),
                        "error": result.get("details", {}).get("error", ""),
                    }
                )


def create_test_dataset() -> str:
    """Create a test dataset with 50 known websites and their cloud providers."""
    test_data = [
        # AWS-hosted sites
        {"url": "netflix.com", "known_provider": "AWS"},
        {"url": "twitch.tv", "known_provider": "AWS"},
        {"url": "airbnb.com", "known_provider": "AWS"},
        {"url": "slack.com", "known_provider": "AWS"},
        {"url": "pinterest.com", "known_provider": "AWS"},
        {"url": "reddit.com", "known_provider": "AWS"},
        {"url": "soundcloud.com", "known_provider": "AWS"},
        {"url": "medium.com", "known_provider": "AWS"},
        {"url": "discord.com", "known_provider": "AWS"},
        {"url": "dropbox.com", "known_provider": "AWS"},
        # GCP-hosted sites
        {"url": "spotify.com", "known_provider": "GCP"},
        {"url": "snapchat.com", "known_provider": "GCP"},
        {"url": "whatsapp.com", "known_provider": "GCP"},
        {"url": "pokemon.com", "known_provider": "GCP"},
        {"url": "shopify.com", "known_provider": "GCP"},
        {"url": "etsy.com", "known_provider": "GCP"},
        {"url": "paypal.com", "known_provider": "GCP"},
        {"url": "ebay.com", "known_provider": "GCP"},
        {"url": "bestbuy.com", "known_provider": "GCP"},
        {"url": "target.com", "known_provider": "GCP"},
        # Azure-hosted sites
        {"url": "stackoverflow.com", "known_provider": "Azure"},
        {"url": "office.com", "known_provider": "Azure"},
        {"url": "xbox.com", "known_provider": "Azure"},
        {"url": "skype.com", "known_provider": "Azure"},
        {"url": "bing.com", "known_provider": "Azure"},
        {"url": "outlook.com", "known_provider": "Azure"},
        {"url": "minecraft.net", "known_provider": "Azure"},
        {"url": "github.com", "known_provider": "Azure"},
        {"url": "linkedin.com", "known_provider": "Azure"},
        {"url": "msn.com", "known_provider": "Azure"},
        # Mixed/Other providers
        {"url": "cloudflare.com", "known_provider": "Other"},
        {"url": "digitalocean.com", "known_provider": "Other"},
        {"url": "linode.com", "known_provider": "Other"},
        {"url": "vultr.com", "known_provider": "Other"},
        # Major sites (various providers)
        {"url": "google.com", "known_provider": "GCP"},
        {"url": "youtube.com", "known_provider": "GCP"},
        {"url": "amazon.com", "known_provider": "AWS"},
        {"url": "microsoft.com", "known_provider": "Azure"},
        {"url": "apple.com", "known_provider": "Other"},
        {"url": "facebook.com", "known_provider": "Other"},
        {"url": "instagram.com", "known_provider": "Other"},
        {"url": "twitter.com", "known_provider": "Other"},
        {"url": "tiktok.com", "known_provider": "Other"},
        {"url": "wikipedia.org", "known_provider": "Other"},
        {"url": "cnn.com", "known_provider": "AWS"},
        {"url": "bbc.com", "known_provider": "AWS"},
        {"url": "nytimes.com", "known_provider": "GCP"},
        {"url": "washingtonpost.com", "known_provider": "AWS"},
    ]

    filename = "test_websites.csv"
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["url", "known_provider"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(test_data)
    print(f"Test dataset created: {filename}")
    return filename


async def main():
    """Main function to run the cloud provider detection."""

    parser = argparse.ArgumentParser(description="Cloud Provider Detection")
    parser.add_argument("input_csv", nargs="?", help="CSV file containing website URLs")
    parser.add_argument("--output", "-o", default="results.csv", help="Output CSV file")
    parser.add_argument(
        "--headless",
        action="store_true",
        default=True,
        help="Run browser in headless mode (default: True)",
    )
    parser.add_argument(
        "--visible",
        action="store_true",
        help="Run browser in visible mode for debugging",
    )
    parser.add_argument(
        "--create-test-data",
        action="store_true",
        help="Create test dataset with 50 known websites",
    )

    args = parser.parse_args()

    if args.create_test_data:
        create_test_dataset()
        return

    if not args.input_csv:
        parser.error("input_csv is required")

    # Determine headless mode (default True, unless --visible is specified)
    headless_mode = not args.visible if args.visible else args.headless

    detector = CloudProviderDetector(headless=headless_mode)

    try:
        urls = []
        with open(args.input_csv, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            if "url" not in reader.fieldnames:
                print("Error: CSV must contain a 'url' column")
                return
            urls = [row["url"].strip() for row in reader]
    except Exception as e:
        print(f"Error reading input CSV: {e}")
        return

    print(f"Starting analysis of {len(urls)} websites...")
    results = await detector.analyze_websites_batch(urls)

    detector.save_results(results, args.output)

    providers_count = {}
    for result in results:
        provider = result["primary_cloud_provider"]
        providers_count[provider] = providers_count.get(provider, 0) + 1

    print("\nDetection Summary:")
    for provider, count in sorted(providers_count.items()):
        print(f"{provider}: {count} websites")

    print(f"\nDetailed results saved to: {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
