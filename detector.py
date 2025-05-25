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
import sys
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

# Try to import playwright and install browsers if needed
try:
    from playwright.async_api import async_playwright

    PLAYWRIGHT_AVAILABLE = True

    # Test if browsers are actually available and install if needed
    try:
        import subprocess
        import sys
        import os

        # Check if we're in a deployment environment (like Streamlit Cloud)
        is_deployment = os.environ.get("STREAMLIT_SHARING_MODE") or os.environ.get(
            "GITHUB_CODESPACE_TOKEN"
        )

        # Quick test to see if browsers are available
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from playwright.sync_api import sync_playwright; p = sync_playwright(); p.start().chromium.launch(headless=True)",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        BROWSERS_AVAILABLE = result.returncode == 0

        # If browsers aren't available, try to install them
        if not BROWSERS_AVAILABLE:
            print("Browsers not detected, attempting installation...")
            try:
                # Install browsers
                install_result = subprocess.run(
                    [sys.executable, "-m", "playwright", "install", "chromium"],
                    capture_output=True,
                    text=True,
                    timeout=120,  # Allow more time for installation
                )

                if install_result.returncode == 0:
                    print("Browser installation successful!")
                    # Test again after installation
                    test_result = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            "from playwright.sync_api import sync_playwright; p = sync_playwright(); p.start().chromium.launch(headless=True)",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    BROWSERS_AVAILABLE = test_result.returncode == 0
                    if BROWSERS_AVAILABLE:
                        print("Browser test successful after installation!")
                    else:
                        print(
                            "Browser test failed after installation, using IP-only mode"
                        )
                else:
                    print(f"Browser installation failed: {install_result.stderr}")
                    BROWSERS_AVAILABLE = False

            except Exception as e:
                print(f"Browser installation error: {e}")
                BROWSERS_AVAILABLE = False

        if not BROWSERS_AVAILABLE:
            print("Note: Using IP-only analysis mode (most reliable method)")
        else:
            print("Full browser-enabled analysis mode active")

    except Exception as e:
        print(f"Browser availability check failed: {e}")
        BROWSERS_AVAILABLE = False

except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    BROWSERS_AVAILABLE = False
    print("Note: Playwright not available - using IP-only analysis mode")


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

        # Advertising and marketing services blacklist - these are third-party services, not backend hosting
        self.advertising_blacklist = {
            # Google Ads and Marketing
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "googletagmanager.com",
            "googletagservices.com",
            "jnn-pa.googleapis.com",  # Google advertising service
            "google-analytics.com",
            "googleanalytics.com",
            "analytics.google.com",
            "pagead2.googlesyndication.com",
            "tpc.googlesyndication.com",
            "googleads.g.doubleclick.net",
            # Facebook/Meta Ads
            "facebook.com",
            "connect.facebook.net",
            "facebook.net",
            "connect.facebook.com",
            # Amazon Advertising
            "amazon-adsystem.com",
            "amazonclouddrive.com",
            # Microsoft Advertising
            "bat.bing.com",
            "ads.microsoft.com",
            "c.bing.com",
            # Twitter/X Ads
            "ads-twitter.com",
            "analytics.twitter.com",
            "ads.x.com",
            # LinkedIn Ads
            "ads.linkedin.com",
            "analytics.pointdrive.linkedin.com",
            # Other common advertising/analytics services
            "hotjar.com",
            "mixpanel.com",
            "segment.com",
            "amplitude.com",
            "fullstory.com",
            "loggly.com",
            "newrelic.com",
            "sentry.io",
            "bugsnag.com",
            "rollbar.com",
            "intercom.io",
            "zendesk.com",
            "freshworks.com",
            "crisp.chat",
            "drift.com",
            "hubspot.com",
            "marketo.com",
            "pardot.com",
            "mailchimp.com",
            "sendgrid.com",
            "twilio.com",
        }

        # Enhanced cloud provider patterns for comprehensive backend identification
        self.cloud_patterns = {
            "AWS": {
                "cdn_domains": ["cloudfront.net", "amazonaws.com"],
                "security_headers": [
                    "x-amz-cf-id",
                    "x-amz-request-id",
                    "x-amz-cf-pop",
                    "x-amz-id-2",
                    "x-amz-server-side-encryption",
                    "x-amz-version-id",
                    "x-amz-delete-marker",
                    "x-amz-expiration",
                    "x-amz-restore",
                    "x-amz-storage-class",
                    "x-amz-website-redirect-location",
                    "x-amz-replication-status",
                ],
                "backend_headers": [
                    "x-amzn-requestid",
                    "x-amzn-trace-id",
                    "x-amzn-errortype",
                    "x-amz-apigw-id",
                    "x-amzn-remapped-content-length",
                    "x-amzn-remapped-connection",
                    "x-amzn-remapped-date",
                    "x-amzn-remapped-server",
                    "x-amz-target",
                    "x-amz-user-agent",
                    "x-amz-content-sha256",
                    "x-amz-date",
                ],
                "server_headers": [
                    "server: amazon",
                    "server: awselb",
                    "server: cloudfront",
                    "server: aws",
                    "server: amazonec2",
                    "server: amazons3",
                ],
                "powered_by_headers": [
                    "x-powered-by: aws",
                    "x-powered-by: amazon",
                    "x-powered-by: lambda",
                    "x-powered-by: api gateway",
                    "x-powered-by: elastic beanstalk",
                ],
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
                    "x-goog-hash",
                    "x-goog-stored-content-encoding",
                    "x-goog-stored-content-length",
                    "x-goog-storage-class",
                    "x-goog-component-count",
                    "x-goog-expiration",
                ],
                "backend_headers": [
                    "x-cloud-trace-context",
                    "x-goog-request-id",
                    "x-goog-api-client",
                    "x-goog-user-project",
                    "x-goog-quota-user",
                    "x-goog-fieldmask",
                    "x-gfe-response-code-details-trace",
                    "x-goog-gfe-backend-request-cost",
                    "x-goog-resource-state",
                    "x-goog-safety-content-type",
                    "x-goog-safety-encoding",
                ],
                "server_headers": [
                    "server: google",
                    "server: gfe",
                    "server: google frontend",
                    "server: gws",
                    "server: sffe",
                    "server: google-cloud-storage",
                ],
                "powered_by_headers": [
                    "x-powered-by: google",
                    "x-powered-by: gcp",
                    "x-powered-by: app engine",
                    "x-powered-by: cloud functions",
                    "x-powered-by: cloud run",
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
                    "x-ms-version",
                    "x-ms-blob-type",
                    "x-ms-lease-status",
                    "x-ms-lease-state",
                    "x-ms-server-encrypted",
                    "x-ms-access-tier",
                    "x-ms-creation-time",
                ],
                "backend_headers": [
                    "x-ms-correlation-request-id",
                    "x-ms-routing-request-id",
                    "x-ms-ratelimit-remaining-subscription-reads",
                    "x-ms-request-charge",
                    "x-ms-servicebus-message-id",
                    "x-ms-activity-id",
                    "x-ms-client-request-id",
                    "x-ms-return-client-request-id",
                    "x-ms-continuation",
                    "x-ms-documentdb-partitionkey",
                    "x-ms-documentdb-collection-index-transformation-progress",
                ],
                "server_headers": [
                    "server: microsoft",
                    "server: azure",
                    "server: iis",
                    "server: microsoft-iis",
                    "server: microsoft-httpapi",
                    "server: cloudflare-nginx",
                    "server: kestrel",
                ],
                "powered_by_headers": [
                    "x-powered-by: azure",
                    "x-powered-by: microsoft",
                    "x-powered-by: asp.net",
                    "x-powered-by: azure functions",
                    "x-powered-by: azure app service",
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

    def is_advertising_service(self, domain: str) -> bool:
        """Check if a domain is an advertising/marketing service that should be excluded."""
        domain_lower = domain.lower()

        # Check exact matches
        if domain_lower in self.advertising_blacklist:
            return True

        # Check if domain ends with any blacklisted domain (for subdomains)
        for blacklisted_domain in self.advertising_blacklist:
            if domain_lower.endswith(f".{blacklisted_domain}") or domain_lower.endswith(
                blacklisted_domain
            ):
                return True

        return False

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

    def check_ip_against_cloud_ranges(self, ip: str) -> Optional[Dict[str, str]]:
        """Check if IP belongs to a cloud provider's range with detailed range information."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for provider, ranges in self.ip_ranges.items():
                for ip_range in ranges:
                    try:
                        if "/" in ip_range:
                            network = ipaddress.ip_network(ip_range, strict=False)
                            if ip_obj in network:
                                return {
                                    "provider": provider,
                                    "ip": ip,
                                    "range": ip_range,
                                    "network_name": f"{provider} IP range {ip_range}",
                                }
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    async def discover_app_subdomains_and_apis(self, url: str) -> Dict[str, List[str]]:
        """Discover app subdomains and their API endpoints through comprehensive deep exploration."""
        backend_data = {
            "xhr_api_calls": [],
            "app_subdomains": [],
            "cloud_provider_domains": [],
            "api_ips": [],
            "cloud_domain_ips": [],
            "subdomain_details": {},  # Track which subdomain found which APIs
            "processing_log": [],  # For real-time display
        }

        # Check if browsers are available
        if not PLAYWRIGHT_AVAILABLE or not BROWSERS_AVAILABLE:
            backend_data["processing_log"].append(
                "❌ Browser not available - cannot perform deep XHR analysis"
            )
            print("Browser not available - cannot perform deep XHR analysis")
            return backend_data

        browser = None
        try:
            domain = urlparse(url).netloc
            base_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain

            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(headless=self.headless)
                except Exception:
                    backend_data["processing_log"].append("❌ Failed to launch browser")
                    return backend_data

                context = await browser.new_context()
                page = await context.new_page()

                # Track all XHR/fetch requests with more detail
                xhr_calls = set()
                cloud_calls = set()
                app_domains = set()
                subdomain_xhr_map = {}  # Track which subdomain found which XHR calls

                def handle_request(request):
                    try:
                        request_url = request.url
                        url_parsed = urlparse(request_url)
                        request_domain = url_parsed.netloc

                        # Only track XHR/fetch requests (API calls)
                        resource_type = request.resource_type
                        if resource_type in ["xhr", "fetch"]:
                            # Skip advertising and marketing services - these are third-party, not backend hosting
                            if request_domain and self.is_advertising_service(
                                request_domain
                            ):
                                backend_data["processing_log"].append(
                                    f"  🚫 Skipping advertising service: {request_domain}"
                                )
                                print(
                                    f"  🚫 Skipping advertising service: {request_domain}"
                                )
                                return

                            # Check if it's a same-domain API endpoint
                            if request_domain and base_domain in request_domain:
                                xhr_calls.add(request_domain)
                                backend_data["processing_log"].append(
                                    f"  🔍 XHR to same-domain API: {request_domain}"
                                )
                                print(f"  🔍 XHR to same-domain API: {request_domain}")

                                # Track which page/subdomain found this XHR call
                                current_page_domain = (
                                    urlparse(page.url).netloc
                                    if hasattr(page, "url")
                                    else "main"
                                )
                                if current_page_domain not in subdomain_xhr_map:
                                    subdomain_xhr_map[current_page_domain] = set()
                                subdomain_xhr_map[current_page_domain].add(
                                    request_domain
                                )

                            # Check if it's a direct cloud provider domain call
                            elif request_domain:
                                # Check for AWS services with specific service identification
                                if any(
                                    pattern in request_domain.lower()
                                    for pattern in [
                                        ".amazonaws.com",
                                        ".cloudfront.net",
                                        ".execute-api",
                                    ]
                                ):
                                    service_type = self._identify_aws_service(
                                        request_domain
                                    )
                                    cloud_calls.add(
                                        (request_domain, "AWS", service_type)
                                    )
                                    backend_data["processing_log"].append(
                                        f"  ☁️ XHR to AWS {service_type}: {request_domain}"
                                    )
                                    print(
                                        f"  ☁️ XHR to AWS {service_type}: {request_domain}"
                                    )

                                # Check for GCP services (excluding Maps API, Fonts API, and advertising)
                                elif any(
                                    pattern in request_domain.lower()
                                    for pattern in [
                                        ".googleapis.com",
                                        ".googleusercontent.com",
                                        ".run.app",
                                    ]
                                ):
                                    # Exclude Google Maps API, Fonts API, and advertising calls as they're third-party services, not backend hosting
                                    if not any(
                                        excluded_pattern in request_domain.lower()
                                        for excluded_pattern in [
                                            "maps.googleapis.com",
                                            "mapsplatform.googleapis.com",
                                            "maps.gstatic.com",
                                            "fonts.googleapis.com",
                                        ]
                                    ):
                                        service_type = self._identify_gcp_service(
                                            request_domain
                                        )
                                        cloud_calls.add(
                                            (request_domain, "GCP", service_type)
                                        )
                                        backend_data["processing_log"].append(
                                            f"  ☁️ XHR to GCP {service_type}: {request_domain}"
                                        )
                                        print(
                                            f"  ☁️ XHR to GCP {service_type}: {request_domain}"
                                        )
                                    else:
                                        if (
                                            "fonts.googleapis.com"
                                            in request_domain.lower()
                                        ):
                                            backend_data["processing_log"].append(
                                                f"  🔤 Skipping Google Fonts API: {request_domain}"
                                            )
                                            print(
                                                f"  🔤 Skipping Google Fonts API: {request_domain}"
                                            )
                                        else:
                                            backend_data["processing_log"].append(
                                                f"  🗺️ Skipping Google Maps API: {request_domain}"
                                            )
                                            print(
                                                f"  🗺️ Skipping Google Maps API: {request_domain}"
                                            )

                                # Check for Azure services
                                elif any(
                                    pattern in request_domain.lower()
                                    for pattern in [
                                        ".azurewebsites.net",
                                        ".azure.com",
                                        ".azureedge.net",
                                    ]
                                ):
                                    service_type = self._identify_azure_service(
                                        request_domain
                                    )
                                    cloud_calls.add(
                                        (request_domain, "Azure", service_type)
                                    )
                                    backend_data["processing_log"].append(
                                        f"  ☁️ XHR to Azure {service_type}: {request_domain}"
                                    )
                                    print(
                                        f"  ☁️ XHR to Azure {service_type}: {request_domain}"
                                    )

                    except Exception:
                        pass

                page.on("request", handle_request)

                # 1. Start with the main page - spend more time here
                backend_data["processing_log"].append(f"  📄 Loading main page: {url}")
                print(f"  📄 Loading main page: {url}")
                await page.goto(url, wait_until="networkidle", timeout=20000)
                await page.wait_for_timeout(5000)  # Wait longer for initial API calls

                # Try to trigger more interactions on main page
                try:
                    await page.evaluate("""() => {
                        // Scroll to trigger lazy loading
                        window.scrollTo(0, document.body.scrollHeight);
                        
                        // Try to click some interactive elements
                        const buttons = document.querySelectorAll('button, [role="button"], .btn');
                        for (let i = 0; i < Math.min(5, buttons.length); i++) {
                            if (buttons[i].offsetParent !== null) {
                                buttons[i].click();
                            }
                        }
                        
                        // Try to hover over menu items that might trigger API calls
                        const menuItems = document.querySelectorAll('[class*="menu"], [class*="nav"], [class*="dropdown"]');
                        for (let i = 0; i < Math.min(3, menuItems.length); i++) {
                            if (menuItems[i].offsetParent !== null) {
                                menuItems[i].dispatchEvent(new MouseEvent('mouseenter', {bubbles: true}));
                            }
                        }
                    }""")
                    await page.wait_for_timeout(3000)
                except:
                    pass

                # 2. Comprehensive subdomain discovery - be much more thorough
                backend_data["processing_log"].append(
                    "  🔗 Discovering app subdomains..."
                )
                print("  🔗 Discovering app subdomains...")

                # Find app links on the main page
                app_links = await page.evaluate("""() => {
                    const links = [];
                    const allLinks = Array.from(document.querySelectorAll('a[href]'));
                    
                    for (const link of allLinks) {
                        const href = link.href;
                        if (href && (
                            href.includes('app.') || 
                            href.includes('application.') ||
                            href.includes('dashboard.') ||
                            href.includes('console.') ||
                            href.includes('admin.') ||
                            href.includes('portal.') ||
                            href.includes('account.') ||
                            href.includes('signin.') ||
                            href.includes('login.') ||
                            href.includes('my.') ||
                            href.includes('client.') ||
                            href.includes('api.') ||
                            href.includes('manage.') ||
                            href.includes('control.') ||
                            href.includes('studio.') ||
                            href.includes('web.') ||
                            href.includes('secure.') ||
                            link.textContent.toLowerCase().includes('app') ||
                            link.textContent.toLowerCase().includes('dashboard') ||
                            link.textContent.toLowerCase().includes('login') ||
                            link.textContent.toLowerCase().includes('sign in') ||
                            link.textContent.toLowerCase().includes('get started') ||
                            link.textContent.toLowerCase().includes('console') ||
                            link.textContent.toLowerCase().includes('portal')
                        )) {
                            links.push(href);
                        }
                    }
                    return [...new Set(links)];
                }""")

                # Comprehensive list of common app subdomain patterns
                common_app_subdomains = [
                    f"https://app.{base_domain}",
                    f"https://application.{base_domain}",
                    f"https://dashboard.{base_domain}",
                    f"https://console.{base_domain}",
                    f"https://admin.{base_domain}",
                    f"https://portal.{base_domain}",
                    f"https://my.{base_domain}",
                    f"https://client.{base_domain}",
                    f"https://account.{base_domain}",
                    f"https://accounts.{base_domain}",
                    f"https://login.{base_domain}",
                    f"https://signin.{base_domain}",
                    f"https://auth.{base_domain}",
                    f"https://api.{base_domain}",
                    f"https://manage.{base_domain}",
                    f"https://management.{base_domain}",
                    f"https://control.{base_domain}",
                    f"https://studio.{base_domain}",
                    f"https://web.{base_domain}",
                    f"https://secure.{base_domain}",
                    f"https://admin-{base_domain.replace('.', '-')}.{base_domain}",
                    f"https://app-{base_domain.replace('.', '-')}.{base_domain}",
                    f"https://panel.{base_domain}",
                    f"https://cpanel.{base_domain}",
                    f"https://members.{base_domain}",
                    f"https://user.{base_domain}",
                    f"https://users.{base_domain}",
                ]

                all_app_urls = list(set(app_links + common_app_subdomains))
                backend_data["processing_log"].append(
                    f"  📋 Found {len(app_links)} potential app links, testing {len(all_app_urls)} total URLs"
                )
                print(
                    f"  📋 Found {len(app_links)} potential app links, testing {len(all_app_urls)} total URLs"
                )

                # 3. Navigate to each app subdomain/page and collect API calls - spend more time on each
                successful_subdomains = []
                for i, app_url in enumerate(
                    all_app_urls[:10]
                ):  # Increase limit to 10 for more thorough analysis
                    try:
                        backend_data["processing_log"].append(
                            f"  🚀 [{i + 1}/{min(10, len(all_app_urls))}] Exploring: {app_url}"
                        )
                        print(
                            f"  🚀 [{i + 1}/{min(10, len(all_app_urls))}] Exploring: {app_url}"
                        )

                        await page.goto(
                            app_url, wait_until="networkidle", timeout=15000
                        )

                        # Wait longer for SPAs to load and make API calls
                        await page.wait_for_timeout(7000)  # Increased wait time

                        # More comprehensive interaction to trigger API calls
                        try:
                            await page.evaluate("""() => {
                                // Scroll to trigger lazy loading and API calls
                                for (let i = 0; i < 3; i++) {
                                    window.scrollTo(0, (i + 1) * window.innerHeight);
                                    setTimeout(() => {}, 1000);
                                }
                                
                                // Try to click buttons that might trigger API calls
                                const buttons = document.querySelectorAll('button, [role="button"], .btn, input[type="button"], input[type="submit"]');
                                for (let i = 0; i < Math.min(5, buttons.length); i++) {
                                    if (buttons[i].offsetParent !== null && !buttons[i].disabled) {
                                        try {
                                            buttons[i].click();
                                        } catch (e) {}
                                    }
                                }
                                
                                // Try to focus on input fields (might trigger autocomplete APIs)
                                const inputs = document.querySelectorAll('input[type="text"], input[type="email"], input[type="search"], textarea');
                                for (let i = 0; i < Math.min(3, inputs.length); i++) {
                                    if (inputs[i].offsetParent !== null) {
                                        try {
                                            inputs[i].focus();
                                            inputs[i].value = "test";
                                            inputs[i].dispatchEvent(new Event('input', {bubbles: true}));
                                        } catch (e) {}
                                    }
                                }
                                
                                // Try to trigger dropdown menus and navigation
                                const dropdowns = document.querySelectorAll('[class*="dropdown"], [class*="menu"], [data-toggle*="dropdown"]');
                                for (let i = 0; i < Math.min(3, dropdowns.length); i++) {
                                    if (dropdowns[i].offsetParent !== null) {
                                        try {
                                            dropdowns[i].click();
                                            dropdowns[i].dispatchEvent(new MouseEvent('mouseenter', {bubbles: true}));
                                        } catch (e) {}
                                    }
                                }
                            }""")
                            await page.wait_for_timeout(
                                4000
                            )  # Wait for triggered API calls
                        except:
                            pass

                        app_domain = urlparse(app_url).netloc
                        if base_domain in app_domain:
                            app_domains.add(app_domain)
                            successful_subdomains.append(app_domain)
                            backend_data["processing_log"].append(
                                f"    ✅ Successfully explored {app_domain}"
                            )
                            print(f"    ✅ Successfully explored {app_domain}")

                    except Exception as e:
                        backend_data["processing_log"].append(
                            f"    ❌ Failed to load {app_url}: {str(e)[:100]}"
                        )
                        print(f"    ❌ Failed to load {app_url}: {e}")
                        continue

                # 4. Store subdomain details for better reporting
                for subdomain, xhr_set in subdomain_xhr_map.items():
                    backend_data["subdomain_details"][subdomain] = {
                        "xhr_calls": list(xhr_set),
                        "xhr_count": len(xhr_set),
                    }

                # 5. Collect results with more detail
                backend_data["xhr_api_calls"] = list(xhr_calls)
                backend_data["app_subdomains"] = list(app_domains)
                backend_data["cloud_provider_domains"] = list(cloud_calls)

                # Resolve API IPs with more comprehensive logging
                backend_data["processing_log"].append(
                    f"  🎯 Resolving IPs for {len(backend_data['xhr_api_calls'])} XHR APIs..."
                )
                print(
                    f"  🎯 Resolving IPs for {len(backend_data['xhr_api_calls'])} XHR APIs..."
                )

                for api_domain in backend_data["xhr_api_calls"]:
                    ips = self.resolve_domain_to_ips(api_domain)
                    backend_data["api_ips"].extend(ips)
                    backend_data["processing_log"].append(
                        f"    📍 {api_domain} → {', '.join(ips[:3])}"
                    )

                # Resolve cloud provider domain IPs
                for domain_provider_tuple in backend_data["cloud_provider_domains"]:
                    domain = (
                        domain_provider_tuple[0]
                        if isinstance(domain_provider_tuple, tuple)
                        else domain_provider_tuple
                    )
                    ips = self.resolve_domain_to_ips(domain)
                    backend_data["cloud_domain_ips"].extend(ips)

                backend_data["processing_log"].append(
                    f"  ✅ Discovery complete: {len(backend_data['xhr_api_calls'])} XHR APIs, {len(backend_data['cloud_provider_domains'])} cloud calls from {len(successful_subdomains)} subdomains"
                )
                print(
                    f"  ✅ Discovery complete: {len(backend_data['xhr_api_calls'])} XHR APIs, {len(backend_data['cloud_provider_domains'])} cloud calls from {len(successful_subdomains)} subdomains"
                )

        except Exception as e:
            backend_data["processing_log"].append(
                f"  ❌ App discovery failed: {str(e)}"
            )
            print(f"  ❌ App discovery failed: {e}")
        finally:
            if browser:
                try:
                    await browser.close()
                except:
                    pass

        return backend_data

    async def analyze_xhr_headers(self, xhr_domains: List[str]) -> Dict[str, float]:
        """Comprehensive header analysis from XHR API endpoints for backend identification."""
        scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
        header_evidence = []

        try:
            # Check headers from XHR API domains
            for api_domain in xhr_domains[
                :5
            ]:  # Limit to first 5 to avoid too many requests
                try:
                    api_url = f"https://{api_domain}"

                    # Try both HEAD and GET requests for comprehensive header analysis
                    response = None
                    try:
                        response = self.session.head(
                            api_url, timeout=5, allow_redirects=True
                        )
                    except:
                        # If HEAD fails, try GET with small range
                        try:
                            headers = {"Range": "bytes=0-0"}
                            response = self.session.get(
                                api_url,
                                timeout=5,
                                allow_redirects=True,
                                headers=headers,
                            )
                        except:
                            continue

                    if not response:
                        continue

                    headers = response.headers
                    found_evidence = {}

                    for provider, patterns in self.cloud_patterns.items():
                        provider_headers = []
                        provider_score = 0

                        # Check security headers (40 points each)
                        if patterns.get("security_headers"):
                            for header_pattern in patterns["security_headers"]:
                                for header_name, header_value in headers.items():
                                    if header_pattern.lower() in header_name.lower():
                                        provider_headers.append(
                                            f"Security: {header_name}: {header_value}"
                                        )
                                        provider_score += 40.0

                        # Check backend-specific headers (50 points each - higher weight)
                        if patterns.get("backend_headers"):
                            for header_pattern in patterns["backend_headers"]:
                                for header_name, header_value in headers.items():
                                    if header_pattern.lower() in header_name.lower():
                                        provider_headers.append(
                                            f"Backend: {header_name}: {header_value}"
                                        )
                                        provider_score += 50.0

                        # Check server headers (45 points each)
                        if patterns.get("server_headers"):
                            server_header = headers.get("Server", "").lower()
                            for server_pattern in patterns["server_headers"]:
                                if server_pattern.lower() in server_header:
                                    provider_headers.append(f"Server: {server_header}")
                                    provider_score += 45.0

                        # Check powered-by headers (35 points each)
                        if patterns.get("powered_by_headers"):
                            powered_by = headers.get("X-Powered-By", "").lower()
                            for powered_pattern in patterns["powered_by_headers"]:
                                if powered_pattern.lower() in powered_by:
                                    provider_headers.append(f"Powered-By: {powered_by}")
                                    provider_score += 35.0

                        # Check additional backend indicators
                        self._check_additional_backend_indicators(
                            headers, provider, provider_headers, provider_score
                        )

                        if provider_headers:
                            scores[provider] += provider_score
                            found_evidence[provider] = {
                                "endpoint": api_domain,
                                "headers": provider_headers,
                                "score": provider_score,
                            }
                            print(
                                f"  🛡️ Found {provider} backend headers in {api_domain}:"
                            )
                            for header in provider_headers:
                                print(f"    • {header}")

                    # Store evidence for all providers found
                    for provider, evidence in found_evidence.items():
                        header_evidence.append(evidence)

                except Exception as e:
                    print(f"  ❌ Header check failed for {api_domain}: {e}")
                    continue

        except Exception as e:
            print(f"XHR header analysis failed: {e}")

        # Store header evidence for later use in reason generation
        self._header_evidence = header_evidence
        return scores

    def _check_additional_backend_indicators(
        self,
        headers: dict,
        provider: str,
        provider_headers: list,
        provider_score: float,
    ):
        """Check for additional backend indicators in headers."""

        # Check for cloud-specific response patterns
        if provider == "AWS":
            # Check for API Gateway patterns
            if "x-amzn-requestid" in headers or "x-amz-apigw-id" in headers:
                provider_headers.append("Backend: AWS API Gateway detected")
                provider_score += 55.0

            # Check for Lambda patterns
            if "x-amzn-trace-id" in headers:
                provider_headers.append("Backend: AWS Lambda/X-Ray tracing detected")
                provider_score += 55.0

            # Check for ELB patterns
            if any("awselb" in h.lower() for h in headers.values()):
                provider_headers.append("Backend: AWS ELB detected")
                provider_score += 50.0

        elif provider == "GCP":
            # Check for Cloud Functions/Cloud Run patterns
            if "x-cloud-trace-context" in headers:
                provider_headers.append("Backend: GCP Cloud Trace detected")
                provider_score += 55.0

            # Check for Google Frontend patterns
            if "x-gfe-request-trace" in headers:
                provider_headers.append("Backend: Google Frontend (GFE) detected")
                provider_score += 50.0

            # Check for App Engine patterns
            if any("appengine" in h.lower() for h in headers.values()):
                provider_headers.append("Backend: Google App Engine detected")
                provider_score += 55.0

        elif provider == "Azure":
            # Check for Azure Functions patterns
            if (
                "x-ms-request-id" in headers
                and "x-ms-correlation-request-id" in headers
            ):
                provider_headers.append("Backend: Azure Functions/App Service detected")
                provider_score += 55.0

            # Check for Azure API Management
            if "x-ms-ratelimit-remaining-subscription-reads" in headers:
                provider_headers.append("Backend: Azure API Management detected")
                provider_score += 50.0

            # Check for Cosmos DB patterns
            if "x-ms-documentdb-partitionkey" in headers:
                provider_headers.append("Backend: Azure Cosmos DB detected")
                provider_score += 55.0

    async def analyze_website(self, url: str) -> Dict[str, any]:
        """Analyze website focusing exclusively on XHR/API calls from app subdomains with comprehensive IP range matching."""
        print(f"🔍 Analyzing backend infrastructure for: {url}")

        result = {
            "url": url,
            "primary_cloud_provider": "Other",
            "confidence_score": 0,
            "primary_reason": "No backend API endpoints detected",
            "evidence": [],
            "details": {},
            "ip_analysis": {},  # Detailed IP analysis for each XHR call
        }

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            # Initialize scores for each provider
            provider_scores = {provider: 0.0 for provider in self.cloud_patterns.keys()}
            evidence_list = []

            # 1. XHR/API Discovery from App Subdomains (PRIMARY Analysis)
            print("  🚀 Discovering app subdomains and XHR API calls...")
            backend_data = await self.discover_app_subdomains_and_apis(url)
            result["details"]["backend_data"] = backend_data

            # 1a. Comprehensive XHR API IP Range Analysis - check ALL IPs for precision
            backend_provider = None
            backend_match = None
            ip_matches = []
            all_ip_details = {}

            if backend_data["api_ips"]:
                print(
                    f"  🎯 Analyzing {len(backend_data['api_ips'])} API endpoint IPs for cloud provider ranges..."
                )

                # Check every single IP against cloud ranges
                for ip in backend_data["api_ips"]:
                    ip_info = self.check_ip_against_cloud_ranges(ip)

                    # Find which API domain this IP belongs to
                    api_domain = "unknown API endpoint"
                    for api_domain_candidate in backend_data["xhr_api_calls"]:
                        api_ips = self.resolve_domain_to_ips(api_domain_candidate)
                        if ip in api_ips:
                            api_domain = api_domain_candidate
                            break

                    # Store detailed IP analysis for reporting
                    all_ip_details[ip] = {
                        "api_domain": api_domain,
                        "cloud_match": ip_info,
                        "is_cloud_ip": ip_info is not None,
                    }

                    if ip_info:
                        provider = ip_info["provider"]
                        ip_matches.append(
                            {
                                "ip": ip,
                                "api_domain": api_domain,
                                "provider": provider,
                                "ip_range": ip_info["range"],
                                "network_name": ip_info["network_name"],
                            }
                        )

                        # High confidence score for IP range matches (90 points for precision)
                        provider_scores[provider] += 90.0
                        backend_provider = provider
                        backend_match = ip

                        evidence_list.append(
                            {
                                "method": "XHR API Endpoint IP Range",
                                "provider": provider,
                                "evidence": f"XHR API {api_domain} (IP {ip}) matches {provider} range {ip_info['range']}",
                                "confidence": "High",
                                "details": {
                                    "endpoint_url": api_domain,
                                    "ip_address": ip,
                                    "ip_range": ip_info["range"],
                                    "network_name": ip_info["network_name"],
                                },
                            }
                        )
                        print(
                            f"  ✅ CLOUD MATCH: {api_domain} → {provider} (IP {ip} in {ip_info['range']})"
                        )
                    else:
                        print(
                            f"  ❌ No cloud match: {api_domain} → {ip} (not in known cloud ranges)"
                        )

                # Store comprehensive IP analysis
                result["ip_analysis"] = {
                    "total_ips_checked": len(backend_data["api_ips"]),
                    "cloud_matches": len(ip_matches),
                    "ip_details": all_ip_details,
                    "cloud_ip_matches": ip_matches,
                }

                if ip_matches:
                    print(
                        f"  📊 IP Analysis Summary: {len(ip_matches)}/{len(backend_data['api_ips'])} IPs matched cloud ranges"
                    )
                else:
                    print(
                        f"  📊 IP Analysis Summary: 0/{len(backend_data['api_ips'])} IPs matched cloud ranges - no cloud backend detected"
                    )

            # 1b. Direct cloud provider domain calls from XHR (60 points)
            cloud_provider_calls = backend_data.get("cloud_provider_domains", [])
            if cloud_provider_calls:
                print(
                    f"  ☁️ Found {len(cloud_provider_calls)} direct cloud provider XHR calls..."
                )
                for cloud_call_info in cloud_provider_calls:
                    if isinstance(cloud_call_info, tuple):
                        if len(cloud_call_info) == 3:
                            cloud_domain, provider, service_type = cloud_call_info
                        else:
                            cloud_domain, provider = cloud_call_info[:2]
                            service_type = f"{provider} Service"

                        provider_scores[provider] += 60.0
                        evidence_list.append(
                            {
                                "method": "Direct Cloud XHR Call",
                                "provider": provider,
                                "evidence": f"XHR calls directly to {cloud_domain} ({service_type})",
                                "details": {
                                    "cloud_domain": cloud_domain,
                                    "service_type": service_type,
                                    "provider": provider,
                                },
                            }
                        )
                        print(
                            f"  ✅ Direct cloud call: {cloud_domain} → {provider} {service_type}"
                        )

            # 2. XHR API Headers Analysis (40 points)
            if backend_data["xhr_api_calls"]:
                print(
                    f"  🛡️ Analyzing headers from {len(backend_data['xhr_api_calls'])} XHR API endpoints..."
                )
                header_scores = await self.analyze_xhr_headers(
                    backend_data["xhr_api_calls"]
                )

                # Add detailed header evidence
                if hasattr(self, "_header_evidence"):
                    for header_info in self._header_evidence:
                        provider = header_info["provider"]
                        endpoint = header_info["endpoint"]
                        headers = header_info["headers"]

                        # Create detailed evidence with endpoint and header information
                        header_details = f"Found {provider}-specific headers at XHR endpoint {endpoint}: {', '.join(headers)}"

                        evidence_list.append(
                            {
                                "method": "XHR API Headers",
                                "provider": provider,
                                "evidence": header_details,
                                "details": {
                                    "endpoint_url": endpoint,
                                    "headers_found": headers,
                                    "provider": provider,
                                },
                            }
                        )

                # Fallback for any providers with header scores but no detailed evidence
                for provider, score in header_scores.items():
                    if score > 0:
                        provider_scores[provider] += score
                        # Only add generic evidence if we don't already have detailed evidence for this provider
                        existing_header_evidence = [
                            e
                            for e in evidence_list
                            if e["method"] == "XHR API Headers"
                            and e["provider"] == provider
                        ]
                        if not existing_header_evidence:
                            evidence_list.append(
                                {
                                    "method": "XHR API Headers",
                                    "provider": provider,
                                    "evidence": f"Found {provider}-specific headers in XHR API endpoints",
                                }
                            )

            # Determine the primary provider based on highest score with high confidence threshold
            if provider_scores:
                primary_provider = max(provider_scores, key=provider_scores.get)
                max_score = provider_scores[primary_provider]

                # HIGH PRECISION APPROACH: Only classify if we have strong evidence
                # We require IP range matches for high confidence classification
                has_ip_evidence = any(
                    e["method"] == "XHR API Endpoint IP Range"
                    and e["provider"] == primary_provider
                    for e in evidence_list
                )
                has_direct_cloud_calls = any(
                    e["method"] == "Direct Cloud XHR Call"
                    and e["provider"] == primary_provider
                    for e in evidence_list
                )

                # Calculate confidence score based on evidence strength
                confidence_score = 0
                if has_ip_evidence:
                    confidence_score = 95  # Very high confidence for IP range matches
                elif has_direct_cloud_calls:
                    confidence_score = 85  # High confidence for direct cloud API calls
                elif max_score > 0:
                    confidence_score = max(
                        20, min(60, max_score)
                    )  # Medium confidence for other evidence

                # Only classify with high confidence (we prioritize precision over recall)
                if confidence_score >= 80:  # High confidence threshold
                    result["primary_cloud_provider"] = primary_provider
                    result["confidence_score"] = confidence_score

                    # Determine primary reason based on evidence
                    primary_reason, main_evidence = self._determine_primary_reason_xhr(
                        evidence_list, primary_provider, backend_match, backend_data
                    )
                    result["primary_reason"] = primary_reason
                    result["evidence"] = [
                        e for e in evidence_list if e["provider"] == primary_provider
                    ]

                    print(
                        f"  ✅ HIGH CONFIDENCE DETECTION: {primary_provider} ({confidence_score}% confidence)"
                    )

                elif max_score > 0:
                    # We have some evidence but not high confidence
                    result["primary_cloud_provider"] = "Insufficient Data"
                    result["confidence_score"] = confidence_score
                    result["primary_reason"] = (
                        f"Evidence found for {primary_provider} but confidence too low ({confidence_score}%) - requires IP range match or direct cloud calls for high-precision detection"
                    )
                    result["evidence"] = (
                        evidence_list  # Show all evidence but don't classify
                    )

                    print(
                        f"  ⚠️ LOW CONFIDENCE: Found {primary_provider} evidence but only {confidence_score}% confidence"
                    )

                else:
                    # No evidence found at all
                    result["primary_cloud_provider"] = "Insufficient Data"
                    result["confidence_score"] = 0
                    result["primary_reason"] = (
                        "No XHR API evidence found for classification"
                    )

                    print("  ❌ No evidence found")

                result["details"]["provider_scores"] = provider_scores
                result["details"]["all_evidence"] = evidence_list
                result["details"]["evidence_summary"] = {
                    "has_ip_evidence": has_ip_evidence,
                    "has_direct_cloud_calls": has_direct_cloud_calls,
                    "max_score": max_score,
                    "confidence_threshold_met": confidence_score >= 80,
                }

                # Detailed summary stats
                classified_as = result["primary_cloud_provider"]
                confidence = result["confidence_score"]
                print(
                    f"  📊 Analysis complete: {classified_as} ({confidence}% confidence)"
                )
                print(f"    - XHR APIs found: {len(backend_data['xhr_api_calls'])}")
                print(f"    - App subdomains: {len(backend_data['app_subdomains'])}")
                print(
                    f"    - Cloud XHR calls: {len(backend_data['cloud_provider_domains'])}"
                )
                if result.get("ip_analysis"):
                    print(
                        f"    - IP matches: {result['ip_analysis'].get('cloud_matches', 0)}/{result['ip_analysis'].get('total_ips_checked', 0)}"
                    )

            else:
                # No evidence found at all
                result["primary_cloud_provider"] = "Insufficient Data"
                result["confidence_score"] = 0
                result["primary_reason"] = (
                    "No XHR API endpoints found in app subdomains - cannot determine cloud provider"
                )
                print("  ❌ No backend cloud infrastructure detected")

        except Exception as e:
            result["details"]["error"] = str(e)
            result["primary_reason"] = f"XHR analysis failed: {str(e)}"
            print(f"  ❌ Error analyzing {url}: {e}")

        return result

    def _determine_primary_reason_xhr(
        self, evidence_list, primary_provider, backend_match, backend_data
    ):
        """Determine the primary reason for detection based on XHR evidence with detailed endpoint info."""
        provider_evidence = [
            e for e in evidence_list if e["provider"] == primary_provider
        ]

        if not provider_evidence:
            return "Detection based on combined XHR signals", ""

        # Use the first evidence (since all evidence is equally valid now)
        strongest = provider_evidence[0]

        if strongest["method"] == "XHR API Endpoint":
            details = strongest.get("details", {})
            endpoint = details.get("endpoint_url", "unknown endpoint")
            ip_addr = details.get("ip_address", "unknown IP")
            ip_range = details.get("ip_range", "unknown range")
            return (
                f"XHR API endpoint {endpoint} (IP {ip_addr}) in {primary_provider} range {ip_range}",
                strongest["evidence"],
            )
        elif strongest["method"] == "Direct Cloud XHR Call":
            # Return the specific evidence text which includes the service type
            return strongest["evidence"], strongest["evidence"]
        elif strongest["method"] == "XHR API Headers":
            # Check if we have detailed header information
            details = strongest.get("details", {})
            if details.get("endpoint_url") and details.get("headers_found"):
                endpoint = details["endpoint_url"]
                headers = details["headers_found"]
                return (
                    f"XHR endpoint {endpoint} shows {primary_provider}-specific headers: {', '.join(headers)}",
                    strongest["evidence"],
                )
            else:
                return (
                    f"XHR API endpoints show {primary_provider}-specific headers",
                    strongest["evidence"],
                )
        else:
            return strongest["evidence"], strongest["evidence"]

    def run_test(self, test_file_path: str = None) -> Dict[str, any]:
        """Run test against labeled data and return accuracy metrics."""
        if test_file_path is None:
            test_file_path = os.path.join(os.path.dirname(__file__), "data", "test.csv")

        print(f"Running test with file: {test_file_path}")

        try:
            # Load test data
            df = pd.read_csv(test_file_path)

            # Shuffle the test data to ensure random order each time
            df = df.sample(frac=1).reset_index(drop=True)
            print(f"Shuffled {len(df)} test domains for random order")

            # Run analysis on test domains
            predictions = []
            true_labels = []
            insufficient_data_count = 0
            all_results = []

            for _, row in df.iterrows():
                domain = row["domain"]
                true_label = row["cloud_provider"]

                # Run analysis
                result = asyncio.run(self.analyze_website(domain))
                predicted_label = result["primary_cloud_provider"]

                all_results.append(
                    {
                        "domain": domain,
                        "true_label": true_label,
                        "predicted_label": predicted_label,
                        "confidence": result.get("confidence_score", 0),
                        "reason": result.get("primary_reason", ""),
                    }
                )

                # Track insufficient data cases separately
                if predicted_label == "Insufficient Data":
                    insufficient_data_count += 1
                    print(
                        f"Domain: {domain}, True: {true_label}, Predicted: {predicted_label} (excluded from accuracy)"
                    )
                else:
                    predictions.append(predicted_label)
                    true_labels.append(true_label)
                    print(
                        f"Domain: {domain}, True: {true_label}, Predicted: {predicted_label}"
                    )

            # Calculate metrics only for classified domains (excluding "Insufficient Data")
            total_domains = len(df)
            classified_domains = len(predictions)
            classification_rate = (
                (classified_domains / total_domains) * 100 if total_domains > 0 else 0
            )

            if classified_domains > 0:
                accuracy = accuracy_score(true_labels, predictions)

                # Get unique labels for precision/recall calculation (excluding "Insufficient Data")
                labels = list(set(true_labels + predictions))
                # Remove "Insufficient Data" if it somehow got in
                labels = [label for label in labels if label != "Insufficient Data"]

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
            else:
                # No domains were classified
                accuracy = 0.0
                precision = 0.0
                recall = 0.0
                report = {}

            return {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "classification_report": report,
                "total_domains": total_domains,
                "classified_domains": classified_domains,
                "insufficient_data_count": insufficient_data_count,
                "classification_rate": classification_rate,
                "all_results": all_results,
                "predictions": list(
                    zip(
                        df["domain"].tolist(),
                        [r["true_label"] for r in all_results],
                        [r["predicted_label"] for r in all_results],
                    )
                ),
            }

        except Exception as e:
            print(f"Test failed: {e}")
            return None

    def _identify_aws_service(self, domain: str) -> str:
        """Identify specific AWS service from domain."""
        domain_lower = domain.lower()

        if "s3.amazonaws.com" in domain_lower or ".s3." in domain_lower:
            return "S3 (Simple Storage Service)"
        elif "execute-api" in domain_lower:
            return "API Gateway"
        elif "lambda" in domain_lower:
            return "Lambda (Serverless Functions)"
        elif "cloudfront.net" in domain_lower:
            return "CloudFront (CDN)"
        elif "ec2" in domain_lower:
            return "EC2 (Elastic Compute Cloud)"
        elif "rds" in domain_lower:
            return "RDS (Relational Database Service)"
        elif "dynamodb" in domain_lower:
            return "DynamoDB (NoSQL Database)"
        elif "cognito" in domain_lower:
            return "Cognito (User Authentication)"
        elif "ses" in domain_lower:
            return "SES (Simple Email Service)"
        elif "sns" in domain_lower:
            return "SNS (Simple Notification Service)"
        elif "sqs" in domain_lower:
            return "SQS (Simple Queue Service)"
        elif "elasticloadbalancing" in domain_lower:
            return "Elastic Load Balancing"
        else:
            return "AWS Service"

    def _identify_gcp_service(self, domain: str) -> str:
        """Identify specific GCP service from domain."""
        domain_lower = domain.lower()

        if "storage.googleapis.com" in domain_lower:
            return "Cloud Storage"
        elif "firestore.googleapis.com" in domain_lower:
            return "Firestore (NoSQL Database)"
        elif "cloudfunctions" in domain_lower:
            return "Cloud Functions (Serverless)"
        elif "run.app" in domain_lower:
            return "Cloud Run (Containers)"
        elif "appengine" in domain_lower:
            return "App Engine"
        elif "compute.googleapis.com" in domain_lower:
            return "Compute Engine (VMs)"
        elif "bigquery" in domain_lower:
            return "BigQuery (Data Warehouse)"
        elif "firebase" in domain_lower:
            return "Firebase"
        elif "youtube.googleapis.com" in domain_lower:
            return "YouTube API"
        elif "oauth2.googleapis.com" in domain_lower:
            return "OAuth2 Authentication"
        elif "analytics.googleapis.com" in domain_lower:
            return "Google Analytics API"
        else:
            return "Google Cloud Service"

    def _identify_azure_service(self, domain: str) -> str:
        """Identify specific Azure service from domain."""
        domain_lower = domain.lower()

        if "blob.core.windows.net" in domain_lower:
            return "Blob Storage"
        elif "azurewebsites.net" in domain_lower:
            return "App Service (Web Apps)"
        elif "database.windows.net" in domain_lower:
            return "SQL Database"
        elif "cosmosdb" in domain_lower:
            return "Cosmos DB (NoSQL)"
        elif "functions.azure.com" in domain_lower:
            return "Azure Functions (Serverless)"
        elif "azureedge.net" in domain_lower:
            return "Azure CDN"
        elif "servicebus" in domain_lower:
            return "Service Bus (Messaging)"
        elif "vault.azure.net" in domain_lower:
            return "Key Vault (Security)"
        else:
            return "Azure Service"


# For compatibility with existing imports
if __name__ == "__main__":
    import asyncio

    detector = CloudProviderDetector()

    # Example usage
    result = asyncio.run(detector.analyze_website("example.com"))
    print(f"Result: {result}")
