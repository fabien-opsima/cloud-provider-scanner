#!/usr/bin/env python3
"""
Test script for the Streamlit Cloud Provider Scanner

This script tests basic functionality to ensure the app works correctly.
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cloud_provider_scanner.scanner_streamlit import CloudProviderDetector


async def test_basic_functionality():
    """Test basic functionality of the cloud provider detector."""
    print("🧪 Testing Cloud Provider Scanner...")

    # Initialize detector
    detector = CloudProviderDetector(headless=True)

    # Test loading IP ranges
    print("📡 Loading cloud provider IP ranges...")
    await detector.load_cloud_ip_ranges()

    # Check if IP ranges were loaded
    for provider, ranges in detector.ip_ranges.items():
        print(f"✅ {provider}: {len(ranges)} IP ranges loaded")

    # Test domain resolution
    print("\n🔍 Testing domain resolution...")
    test_domains = ["google.com", "github.com", "netflix.com"]

    for domain in test_domains:
        ips = detector.resolve_domain_to_ips(domain)
        print(f"🌐 {domain}: {ips}")

        if ips:
            # Test cloud provider detection
            for ip in ips[:1]:  # Test first IP only
                provider = detector.check_ip_against_cloud_ranges(ip)
                print(f"   ☁️  {ip} -> {provider or 'Unknown'}")

    # Test full analysis
    print("\n🚀 Testing full website analysis...")
    result = await detector.analyze_website("github.com")
    print("📊 Analysis result for github.com:")
    print(f"   Provider: {result['primary_cloud_provider']}")
    print(f"   Confidence: {result['confidence_score']}%")
    print(f"   IPs: {result['details'].get('main_domain_ips', [])}")

    print("\n✅ All tests completed successfully!")


if __name__ == "__main__":
    asyncio.run(test_basic_functionality())
