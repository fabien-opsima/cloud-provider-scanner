#!/usr/bin/env python3
"""
Comprehensive test script for the enhanced cloud provider scanner.
Tests all detection methods: IP ranges, SSL certificates, DNS records,
security headers, and website content analysis.
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cloud_provider_scanner.scanner_streamlit import CloudProviderDetector


async def test_enhanced_detection():
    """Test the enhanced cloud provider detection with multiple methods."""
    print("🚀 Testing Enhanced Cloud Provider Scanner...")
    print("=" * 60)

    # Initialize detector
    detector = CloudProviderDetector(headless=True)

    # Test loading IP ranges
    print("📡 Loading cloud provider IP ranges...")
    await detector.load_cloud_ip_ranges()

    # Check if IP ranges were loaded
    for provider, ranges in detector.ip_ranges.items():
        print(f"✅ {provider}: {len(ranges)} IP ranges loaded")

    print("\n🔍 Testing individual detection methods...")
    print("-" * 60)

    # Test websites with known cloud providers
    test_sites = [
        {"url": "github.com", "expected": "Azure"},
        {"url": "netflix.com", "expected": "AWS"},
        {"url": "firebase.google.com", "expected": "GCP"},
        {"url": "microsoft.com", "expected": "Azure"},
        {"url": "amazonaws.com", "expected": "AWS"},
    ]

    for site in test_sites:
        url = site["url"]
        expected = site["expected"]

        print(f"\n🌐 Testing: {url} (expected: {expected})")
        print("-" * 40)

        try:
            # Test domain resolution
            ips = detector.resolve_domain_to_ips(url)
            print(f"   📍 IPs: {ips}")

            # Test IP range detection
            if ips:
                for ip in ips[:2]:  # Test first 2 IPs only
                    provider = detector.check_ip_against_cloud_ranges(ip)
                    print(f"   ☁️  {ip} -> {provider or 'Unknown'}")

            # Test SSL certificate analysis
            print("   🔒 Testing SSL certificate analysis...")
            ssl_scores = await detector.analyze_ssl_certificate(url)
            for provider, score in ssl_scores.items():
                if score > 0:
                    print(f"      SSL: {provider} -> {score} points")

            # Test security headers
            print("   🛡️  Testing security headers...")
            header_scores = await detector.analyze_security_headers(f"https://{url}")
            for provider, score in header_scores.items():
                if score > 0:
                    print(f"      Headers: {provider} -> {score} points")

            # Test DNS records
            print("   🌍 Testing DNS records...")
            dns_scores = await detector.analyze_dns_records(url)
            for provider, score in dns_scores.items():
                if score > 0:
                    print(f"      DNS: {provider} -> {score} points")

            # Test website content (this might be slower)
            print("   📄 Testing website content analysis...")
            content_scores = await detector.analyze_website_content(f"https://{url}")
            for provider, score in content_scores.items():
                if score > 0:
                    print(f"      Content: {provider} -> {score} points")

        except Exception as e:
            print(f"   ❌ Error testing {url}: {e}")

    print("\n🔬 Running full website analysis...")
    print("=" * 60)

    # Test full analysis on a few sites
    full_test_sites = ["github.com", "netflix.com", "firebase.google.com"]

    for url in full_test_sites:
        print(f"\n🎯 Full analysis: {url}")
        print("-" * 40)

        try:
            result = await detector.analyze_website(url)

            print(f"   Provider: {result['primary_cloud_provider']}")
            print(f"   Confidence: {result['confidence_score']:.1f}%")
            print(f"   IPs: {result['details'].get('main_domain_ips', [])}")

            if "provider_scores" in result["details"]:
                print("   Detailed scores:")
                for provider, score in result["details"]["provider_scores"].items():
                    if score > 0:
                        print(f"      {provider}: {score:.1f} points")

            if "error" in result["details"]:
                print(f"   Error: {result['details']['error']}")

        except Exception as e:
            print(f"   ❌ Error in full analysis of {url}: {e}")

    print("\n✅ Enhanced detection testing completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_enhanced_detection())
