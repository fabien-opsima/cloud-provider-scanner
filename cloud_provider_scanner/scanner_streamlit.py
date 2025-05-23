#!/usr/bin/env python3
"""
Cloud Provider Detection Tool - Streamlit Version

A precise tool that detects which cloud providers are used by websites
by analyzing only the most reliable signal:

- IP range matching of main domain against official cloud provider IP ranges

This focuses on backend hosting, not CDN or delivery infrastructure.
Supports AWS, GCP, Azure, and OVH. Other providers are categorized as "Other".

Optimized for Streamlit usage with better error handling and progress reporting.
"""

import socket
import ipaddress
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
import requests
from playwright.async_api import async_playwright


class CloudProviderDetector:
    """
    Precise Cloud Provider Detection Tool - Streamlit Version

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

        # Cloud provider patterns and signatures
        self.cloud_patterns = {
            "AWS": {
                "ip_ranges_url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
                "cdn_domains": ["cloudfront.net", "amazonaws.com"],
                "ssl_issuers": ["Amazon", "AWS"],
                "security_headers": ["x-amz-cf-id", "x-amz-request-id"],
                "js_libraries": ["aws-sdk", "amazon-cognito"],
                "asset_domains": ["s3.amazonaws.com", "s3.region.amazonaws.com"],
                "content_keywords": ["AWS", "Amazon Web Services", "EC2", "S3"],
            },
            "GCP": {
                "ip_ranges_url": "https://www.gstatic.com/ipranges/cloud.json",
                "cdn_domains": ["googleusercontent.com", "googleapis.com"],
                "ssl_issuers": ["Google", "Google Trust Services"],
                "security_headers": ["x-goog-generation", "x-goog-metageneration"],
                "js_libraries": ["firebase", "google-cloud"],
                "asset_domains": [
                    "storage.googleapis.com",
                    "firebasestorage.googleapis.com",
                ],
                "content_keywords": ["Google Cloud", "GCP", "Firebase", "App Engine"],
            },
            "Azure": {
                "ip_ranges_url": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public.json",
                "cdn_domains": ["azureedge.net", "azurewebsites.net"],
                "ssl_issuers": ["Microsoft", "Microsoft Azure"],
                "security_headers": ["x-azure-ref", "x-azure-request-id"],
                "js_libraries": ["azure-storage", "azure-functions"],
                "asset_domains": ["blob.core.windows.net", "azurewebsites.net"],
                "content_keywords": ["Azure", "Microsoft Azure", "App Service"],
            },
            "OVH": {
                "known_ranges": [
                    "37.59.0.0/16",
                    "37.187.0.0/16",
                    "46.105.0.0/16",
                    "51.68.0.0/16",
                    "51.75.0.0/16",
                    "51.77.0.0/16",
                    "51.79.0.0/16",
                    "51.81.0.0/16",
                    "51.83.0.0/16",
                    "51.89.0.0/16",
                    "51.91.0.0/16",
                    "137.74.0.0/16",
                    "141.94.0.0/16",
                    "141.95.0.0/16",
                    "146.59.0.0/16",
                    "151.80.0.0/16",
                    "158.69.0.0/16",
                    "164.132.0.0/16",
                    "167.114.0.0/16",
                    "178.32.0.0/15",
                    "188.165.0.0/16",
                    "192.95.0.0/16",
                    "198.27.64.0/18",
                    "198.50.128.0/17",
                    "199.241.128.0/17",
                    "213.186.32.0/19",
                    "213.251.128.0/18",
                ],
                "cdn_domains": ["ovhcdn.net", "ovh.net"],
                "ssl_issuers": ["OVH"],
                "security_headers": ["x-ovh-request-id"],
                "js_libraries": [],
                "asset_domains": ["ovh.net"],
                "content_keywords": ["OVH", "So you Start", "Kimsufi"],
            },
        }

        # IP ranges will be populated dynamically
        self.ip_ranges = {}

    async def load_cloud_ip_ranges(self):
        """Load IP ranges for major cloud providers."""
        print("Loading cloud provider IP ranges...")

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
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
                self.ip_ranges["AWS"] = []

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
                self.ip_ranges["GCP"] = []

            # Azure IP ranges - Updated with better handling
            try:
                # Use a more reliable Azure IP ranges URL
                azure_url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
                # For now, use known Azure IP ranges as the dynamic download is complex
                azure_known_ranges = [
                    "13.64.0.0/11",
                    "13.96.0.0/13",
                    "13.104.0.0/14",
                    "20.33.0.0/16",
                    "20.34.0.0/15",
                    "20.36.0.0/14",
                    "20.40.0.0/13",
                    "20.48.0.0/12",
                    "20.64.0.0/10",
                    "20.128.0.0/16",
                    "20.135.0.0/16",
                    "20.136.0.0/13",
                    "20.144.0.0/12",
                    "20.160.0.0/12",
                    "20.176.0.0/12",
                    "20.192.0.0/10",
                    "40.64.0.0/10",
                    "40.128.0.0/17",
                    "52.96.0.0/12",
                    "52.112.0.0/14",
                    "52.120.0.0/14",
                    "52.125.0.0/16",
                    "52.130.0.0/15",
                    "52.132.0.0/14",
                    "52.136.0.0/13",
                    "52.145.0.0/16",
                    "52.146.0.0/15",
                    "52.148.0.0/14",
                    "52.152.0.0/13",
                    "52.160.0.0/11",
                    "52.224.0.0/11",
                    "104.40.0.0/13",
                    "104.208.0.0/13",
                    "137.116.0.0/14",
                    "137.135.0.0/16",
                    "138.91.0.0/16",
                    "157.55.0.0/16",
                    "168.61.0.0/16",
                    "168.62.0.0/15",
                    "191.232.0.0/13",
                    "191.240.0.0/12",
                    "199.30.16.0/20",
                ]
                self.ip_ranges["Azure"] = azure_known_ranges
                print(f"Loaded {len(self.ip_ranges['Azure'])} Azure IP ranges")
            except Exception as e:
                print(f"Failed to load Azure IP ranges: {e}")
                self.ip_ranges["Azure"] = []

            # OVH known ranges
            self.ip_ranges["OVH"] = self.cloud_patterns["OVH"]["known_ranges"]
            print(f"Loaded {len(self.ip_ranges['OVH'])} OVH IP ranges")

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
                page.set_default_timeout(10000)  # Shorter timeout for Streamlit

                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=10000
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
            response = self.session.head(
                url, timeout=5
            )  # Shorter timeout for Streamlit
            if response.status_code < 400:
                return {"url": response.url, "status": response.status_code}
        except Exception as e:
            print(f"Requests scraping failed for {url}: {e}")
        return None

    async def analyze_ssl_certificate(self, domain: str) -> Dict[str, float]:
        """Analyze SSL certificate for cloud provider signatures."""
        scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
        try:
            import ssl
            import socket
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())

                    # Check issuer
                    try:
                        issuer_attrs = x509_cert.issuer.get_attributes_for_oid(
                            x509.NameOID.COMMON_NAME
                        )
                        if issuer_attrs:
                            issuer = issuer_attrs[0].value
                            for provider, patterns in self.cloud_patterns.items():
                                if patterns.get("ssl_issuers"):
                                    if any(
                                        issuer_pattern.lower() in issuer.lower()
                                        for issuer_pattern in patterns["ssl_issuers"]
                                    ):
                                        scores[provider] += 35.0
                    except Exception:
                        # Try organization name if common name fails
                        try:
                            org_attrs = x509_cert.issuer.get_attributes_for_oid(
                                x509.NameOID.ORGANIZATION_NAME
                            )
                            if org_attrs:
                                org = org_attrs[0].value
                                for provider, patterns in self.cloud_patterns.items():
                                    if patterns.get("ssl_issuers"):
                                        if any(
                                            issuer_pattern.lower() in org.lower()
                                            for issuer_pattern in patterns[
                                                "ssl_issuers"
                                            ]
                                        ):
                                            scores[provider] += 35.0
                        except:
                            pass

        except Exception:
            # SSL failures are common and not critical - just log and continue
            pass
        return scores

    async def analyze_security_headers(self, url: str) -> Dict[str, float]:
        """Analyze security headers for cloud provider signatures."""
        scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
        try:
            response = self.session.head(url, timeout=5, allow_redirects=True)
            headers = response.headers

            for provider, patterns in self.cloud_patterns.items():
                if patterns.get("security_headers"):
                    for header_pattern in patterns["security_headers"]:
                        if any(
                            header_pattern.lower() in header.lower()
                            for header in headers
                        ):
                            scores[provider] += 25.0
        except Exception:
            # Header analysis failures are not critical
            pass
        return scores

    async def analyze_dns_records(self, domain: str) -> Dict[str, float]:
        """Analyze DNS records for cloud provider signatures."""
        scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
        try:
            import dns.resolver

            # Check CNAME records
            try:
                cname_records = dns.resolver.resolve(domain, "CNAME")
                for record in cname_records:
                    for provider, patterns in self.cloud_patterns.items():
                        if any(
                            cdn_domain in str(record)
                            for cdn_domain in patterns["cdn_domains"]
                        ):
                            scores[provider] += 30.0  # CDN match is a strong signal
            except:
                pass

            # Check MX records
            try:
                mx_records = dns.resolver.resolve(domain, "MX")
                for record in mx_records:
                    for provider, patterns in self.cloud_patterns.items():
                        if any(
                            cdn_domain in str(record)
                            for cdn_domain in patterns["cdn_domains"]
                        ):
                            scores[provider] += (
                                15.0  # MX record match is a moderate signal
                            )
            except:
                pass

        except Exception as e:
            print(f"DNS analysis failed for {domain}: {e}")
        return scores

    async def analyze_website_content(self, url: str) -> Dict[str, float]:
        """Analyze website content for cloud provider signatures."""
        scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
        browser = None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context()
                page = await context.new_page()

                # Get page content
                response = await page.goto(
                    url, wait_until="domcontentloaded", timeout=10000
                )
                if response:
                    content = await page.content()

                    # Check for cloud provider keywords
                    for provider, patterns in self.cloud_patterns.items():
                        if any(
                            keyword.lower() in content.lower()
                            for keyword in patterns["content_keywords"]
                        ):
                            scores[provider] += (
                                20.0  # Content keyword match is a moderate signal
                            )

                    # Check for JS libraries
                    js_libs = await page.evaluate("""() => {
                        return Array.from(document.scripts).map(s => s.src);
                    }""")

                    for provider, patterns in self.cloud_patterns.items():
                        if any(lib in str(js_libs) for lib in patterns["js_libraries"]):
                            scores[provider] += (
                                25.0  # JS library match is a strong signal
                            )

                    # Check for asset domains
                    assets = await page.evaluate("""() => {
                        return Array.from(document.images).map(img => img.src);
                    }""")

                    for provider, patterns in self.cloud_patterns.items():
                        if any(
                            domain in str(assets)
                            for domain in patterns["asset_domains"]
                        ):
                            scores[provider] += (
                                20.0  # Asset domain match is a moderate signal
                            )

        except Exception as e:
            print(f"Content analysis failed for {url}: {e}")
        finally:
            if browser:
                try:
                    await browser.close()
                except:
                    pass
        return scores

    async def analyze_website(self, url: str) -> Dict[str, any]:
        """Analyze website using multiple detection methods."""
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
            domain = urlparse(url).netloc

            # Initialize scores for each provider
            provider_scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}

            # 1. IP Range Analysis (40 points)
            main_ips = self.resolve_domain_to_ips(domain)
            result["details"]["main_domain_ips"] = main_ips

            if main_ips:
                for ip in main_ips:
                    provider = self.check_ip_against_cloud_ranges(ip)
                    if provider:
                        provider_scores[provider] += (
                            40.0  # IP range match is the strongest signal
                        )

            # 2. SSL Certificate Analysis (35 points)
            ssl_scores = await self.analyze_ssl_certificate(domain)
            for provider, score in ssl_scores.items():
                provider_scores[provider] += score

            # 3. Security Headers Analysis (25 points)
            header_scores = await self.analyze_security_headers(url)
            for provider, score in header_scores.items():
                provider_scores[provider] += score

            # 4. DNS Records Analysis (30 points)
            dns_scores = await self.analyze_dns_records(domain)
            for provider, score in dns_scores.items():
                provider_scores[provider] += score

            # 5. Website Content Analysis (65 points total)
            content_scores = await self.analyze_website_content(url)
            for provider, score in content_scores.items():
                provider_scores[provider] += score

            # Determine the primary provider based on highest score
            if provider_scores:
                primary_provider = max(provider_scores, key=provider_scores.get)
                max_score = provider_scores[primary_provider]

                # Calculate confidence score (normalized to 0-100)
                total_possible_score = 195.0  # Sum of all possible points
                confidence_score = (max_score / total_possible_score) * 100

                result["primary_cloud_provider"] = primary_provider
                result["confidence_score"] = confidence_score
                result["details"]["provider_scores"] = provider_scores
            else:
                result["primary_cloud_provider"] = "Other"
                result["confidence_score"] = 0

        except Exception as e:
            result["details"]["error"] = str(e)
            print(f"Error analyzing {url}: {e}")

        return result
