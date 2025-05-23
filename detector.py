#!/usr/bin/env python3
"""
Cloud Provider Detection Tool - Focused Version

A precise tool that detects which cloud providers are used by websites
by analyzing multiple signals:

- IP range matching of main domain against official cloud provider IP ranges (primary)
- IP range matching of backend endpoints discovered during analysis
- Security headers analysis
- Assets on cloud storage and CDN analysis

This focuses on backend hosting, not CDN or delivery infrastructure.
Supports AWS, GCP, and Azure. Other providers are categorized as "Other".

Optimized for accuracy with robust IP range testing.
"""

import socket
import ipaddress
import json
import os
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    classification_report,
)

import requests
from playwright.async_api import async_playwright


class CloudProviderDetector:
    """
    Focused Cloud Provider Detection Tool

    Uses primarily IP range analysis for maximum accuracy in detecting
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

        # Cloud provider patterns for header and asset analysis
        self.cloud_patterns = {
            "AWS": {
                "cdn_domains": ["cloudfront.net", "amazonaws.com"],
                "security_headers": ["x-amz-cf-id", "x-amz-request-id", "x-amz-cf-pop"],
                "asset_domains": ["s3.amazonaws.com", "s3-", ".s3.", "cloudfront.net"],
            },
            "GCP": {
                "cdn_domains": [
                    "googleusercontent.com",
                    "googleapis.com",
                    "gstatic.com",
                ],
                "security_headers": [
                    "x-goog-generation",
                    "x-goog-metageneration",
                    "x-gfe-request-trace",
                ],
                "asset_domains": [
                    "storage.googleapis.com",
                    "firebasestorage.googleapis.com",
                    "googleusercontent.com",
                ],
            },
            "Azure": {
                "cdn_domains": ["azureedge.net", "azurewebsites.net", "windows.net"],
                "security_headers": [
                    "x-azure-ref",
                    "x-azure-request-id",
                    "x-ms-request-id",
                ],
                "asset_domains": [
                    "blob.core.windows.net",
                    "azurewebsites.net",
                    "azureedge.net",
                ],
            },
        }

        # IP ranges will be populated from local files
        self.ip_ranges = {}
        self.load_local_ip_ranges()

    def load_local_ip_ranges(self):
        """Load IP ranges from local JSON files."""
        print("Loading cloud provider IP ranges from local files...")

        data_dir = os.path.join(os.path.dirname(__file__), "data")

        # Load AWS IP ranges
        try:
            with open(os.path.join(data_dir, "aws_ranges.json"), "r") as f:
                aws_data = json.load(f)
                self.ip_ranges["AWS"] = [
                    item["ip_prefix"] for item in aws_data["prefixes"]
                ]
                print(f"Loaded {len(self.ip_ranges['AWS'])} AWS IP ranges")
        except Exception as e:
            print(f"Failed to load AWS IP ranges: {e}")
            self.ip_ranges["AWS"] = []

        # Load GCP IP ranges
        try:
            with open(os.path.join(data_dir, "gcp_ranges.json"), "r") as f:
                gcp_data = json.load(f)
                self.ip_ranges["GCP"] = [
                    item["ipv4Prefix"]
                    for item in gcp_data["prefixes"]
                    if "ipv4Prefix" in item
                ]
                print(f"Loaded {len(self.ip_ranges['GCP'])} GCP IP ranges")
        except Exception as e:
            print(f"Failed to load GCP IP ranges: {e}")
            self.ip_ranges["GCP"] = []

        # Load Azure IP ranges
        try:
            with open(os.path.join(data_dir, "azure_ranges.json"), "r") as f:
                azure_data = json.load(f)
                azure_prefixes = []
                for service in azure_data["values"]:
                    if (
                        "properties" in service
                        and "addressPrefixes" in service["properties"]
                    ):
                        for prefix in service["properties"]["addressPrefixes"]:
                            # Only add IPv4 ranges
                            if ":" not in prefix:
                                azure_prefixes.append(prefix)
                self.ip_ranges["Azure"] = azure_prefixes
                print(f"Loaded {len(self.ip_ranges['Azure'])} Azure IP ranges")
        except Exception as e:
            print(f"Failed to load Azure IP ranges: {e}")
            self.ip_ranges["Azure"] = []

    def resolve_domain_to_ips(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses with robust error handling."""
        ips = []
        try:
            # Remove any protocol if present
            if "://" in domain:
                domain = urlparse(domain).netloc

            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]

            result = socket.getaddrinfo(domain, None)
            for family, type, proto, canonname, sockaddr in result:
                ip = sockaddr[0]
                if ip not in ips and not ip.startswith(
                    "::"
                ):  # Skip IPv6 and duplicates
                    # Validate IP format
                    try:
                        ipaddress.ip_address(ip)
                        ips.append(ip)
                    except:
                        continue
        except Exception as e:
            print(f"Failed to resolve {domain}: {e}")
        return ips

    def check_ip_against_cloud_ranges(self, ip: str) -> Optional[str]:
        """Check if IP belongs to a cloud provider's range with robust matching."""
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

    async def discover_backend_endpoints(self, url: str) -> List[str]:
        """Discover backend API endpoints and additional IPs."""
        backend_ips = []
        browser = None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context()
                page = await context.new_page()

                # Track network requests to discover backend endpoints
                backend_domains = set()

                def handle_request(request):
                    try:
                        url_parsed = urlparse(request.url)
                        domain = url_parsed.netloc
                        # Look for API endpoints, different domains, etc.
                        if domain and domain not in backend_domains:
                            backend_domains.add(domain)
                    except:
                        pass

                page.on("request", handle_request)

                # Navigate to the page
                await page.goto(url, wait_until="networkidle", timeout=15000)

                # Resolve all discovered backend domains to IPs
                for domain in backend_domains:
                    domain_ips = self.resolve_domain_to_ips(domain)
                    backend_ips.extend(domain_ips)

        except Exception as e:
            print(f"Backend endpoint discovery failed for {url}: {e}")
        finally:
            if browser:
                try:
                    await browser.close()
                except:
                    pass

        return list(set(backend_ips))  # Remove duplicates

    async def analyze_security_headers(self, url: str) -> Dict[str, float]:
        """Analyze security headers for cloud provider signatures."""
        scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            headers = response.headers

            for provider, patterns in self.cloud_patterns.items():
                if patterns.get("security_headers"):
                    for header_pattern in patterns["security_headers"]:
                        if any(
                            header_pattern.lower() in header.lower()
                            for header in headers
                        ):
                            scores[provider] += 30.0
        except Exception as e:
            print(f"Header analysis failed for {url}: {e}")
        return scores

    async def analyze_assets(self, url: str) -> Dict[str, float]:
        """Analyze asset URLs for cloud storage and CDN signatures."""
        scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
        browser = None
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context()
                page = await context.new_page()

                await page.goto(url, wait_until="domcontentloaded", timeout=15000)

                # Get all asset URLs
                assets = await page.evaluate("""() => {
                    const urls = [];
                    
                    // Images
                    Array.from(document.images).forEach(img => {
                        if (img.src) urls.push(img.src);
                    });
                    
                    // Scripts
                    Array.from(document.scripts).forEach(script => {
                        if (script.src) urls.push(script.src);
                    });
                    
                    // Stylesheets
                    Array.from(document.styleSheets).forEach(sheet => {
                        if (sheet.href) urls.push(sheet.href);
                    });
                    
                    // Links (additional resources)
                    Array.from(document.links).forEach(link => {
                        if (link.href) urls.push(link.href);
                    });
                    
                    return urls;
                }""")

                # Analyze asset URLs for cloud provider patterns
                for asset_url in assets:
                    for provider, patterns in self.cloud_patterns.items():
                        if any(
                            domain.lower() in asset_url.lower()
                            for domain in patterns["asset_domains"]
                        ):
                            scores[provider] += 20.0

        except Exception as e:
            print(f"Asset analysis failed for {url}: {e}")
        finally:
            if browser:
                try:
                    await browser.close()
                except:
                    pass
        return scores

    async def analyze_website(self, url: str) -> Dict[str, any]:
        """Analyze website using focused detection methods."""
        print(f"Analyzing: {url}")

        result = {
            "url": url,
            "primary_cloud_provider": "Other",
            "confidence_score": 0,
            "details": {},
        }

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            domain = urlparse(url).netloc

            # Initialize scores for each provider
            provider_scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}

            # 1. Primary Domain IP Range Analysis (60 points - strongest signal)
            main_ips = self.resolve_domain_to_ips(domain)
            result["details"]["main_domain_ips"] = main_ips

            if main_ips:
                for ip in main_ips:
                    provider = self.check_ip_against_cloud_ranges(ip)
                    if provider:
                        provider_scores[provider] += (
                            60.0  # Primary domain IP is strongest signal
                        )
                        break  # Only count one match for main domain

            # 2. Backend Endpoint IP Analysis (40 points)
            backend_ips = await self.discover_backend_endpoints(url)
            result["details"]["backend_ips"] = backend_ips

            if backend_ips:
                for ip in backend_ips:
                    provider = self.check_ip_against_cloud_ranges(ip)
                    if provider:
                        provider_scores[provider] += 40.0
                        break  # Only count one match for backend

            # 3. Security Headers Analysis (30 points)
            header_scores = await self.analyze_security_headers(url)
            for provider, score in header_scores.items():
                provider_scores[provider] += score

            # 4. Asset Analysis (20 points per asset, max 60 points)
            asset_scores = await self.analyze_assets(url)
            for provider, score in asset_scores.items():
                provider_scores[provider] += min(score, 60.0)  # Cap at 60 points

            # Determine the primary provider based on highest score
            if provider_scores:
                primary_provider = max(provider_scores, key=provider_scores.get)
                max_score = provider_scores[primary_provider]

                # Calculate confidence score (normalized to 0-100)
                total_possible_score = 190.0  # 60 + 40 + 30 + 60
                confidence_score = min((max_score / total_possible_score) * 100, 100)

                # Only assign provider if confidence is above threshold
                if confidence_score >= 15:  # Minimum threshold
                    result["primary_cloud_provider"] = primary_provider
                else:
                    result["primary_cloud_provider"] = "Other"

                result["confidence_score"] = confidence_score
                result["details"]["provider_scores"] = provider_scores
            else:
                result["primary_cloud_provider"] = "Other"
                result["confidence_score"] = 0

        except Exception as e:
            result["details"]["error"] = str(e)
            print(f"Error analyzing {url}: {e}")

        return result

    def run_test(self, test_file_path: str = None) -> Dict[str, any]:
        """Run test against labeled data and return accuracy metrics."""
        if test_file_path is None:
            test_file_path = os.path.join(os.path.dirname(__file__), "data", "test.csv")

        print(f"Running test with file: {test_file_path}")

        try:
            # Load test data
            df = pd.read_csv(test_file_path)

            # Run analysis on test domains
            predictions = []
            true_labels = []

            for _, row in df.iterrows():
                domain = row["domain"]
                true_label = row["cloud_provider"]

                # Run analysis
                result = asyncio.run(self.analyze_website(domain))
                predicted_label = result["primary_cloud_provider"]

                predictions.append(predicted_label)
                true_labels.append(true_label)

                print(
                    f"Domain: {domain}, True: {true_label}, Predicted: {predicted_label}"
                )

            # Calculate metrics
            accuracy = accuracy_score(true_labels, predictions)

            # Get unique labels for precision/recall calculation
            labels = list(set(true_labels + predictions))

            precision = precision_score(
                true_labels,
                predictions,
                labels=labels,
                average="weighted",
                zero_division=0,
            )
            recall = recall_score(
                true_labels,
                predictions,
                labels=labels,
                average="weighted",
                zero_division=0,
            )

            # Detailed classification report
            report = classification_report(
                true_labels,
                predictions,
                labels=labels,
                zero_division=0,
                output_dict=True,
            )

            return {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "classification_report": report,
                "predictions": list(
                    zip(df["domain"].tolist(), true_labels, predictions)
                ),
            }

        except Exception as e:
            print(f"Test failed: {e}")
            return None


# For compatibility with existing imports
if __name__ == "__main__":
    import asyncio

    detector = CloudProviderDetector()

    # Example usage
    result = asyncio.run(detector.analyze_website("example.com"))
    print(f"Result: {result}")
