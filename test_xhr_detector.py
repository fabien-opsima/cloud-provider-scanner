#!/usr/bin/env python3
"""
Test the updated XHR-focused Cloud Provider Detector

This demonstrates the new methodology that:
1. Completely ignores main domain hosting
2. Focuses exclusively on XHR/API calls
3. Explores app subdomains and SPAs
4. Detects real backend infrastructure
"""

import asyncio
from detector import CloudProviderDetector


async def test_xhr_detection():
    """Test the XHR-focused detection on sample domains."""

    detector = CloudProviderDetector(headless=True)

    # Test domains - these should reveal backend infrastructure through XHR calls
    test_domains = [
        "spotify.com",  # Should find app.spotify.com with API calls
        "netflix.com",  # Should find APIs in app subdomains
        "github.com",  # May have direct cloud calls
        "dropbox.com",  # Should have app subdomain with APIs
        "discord.com",  # Should have app with API calls
    ]

    print("🚀 Testing XHR-Focused Cloud Provider Detection")
    print("=" * 60)
    print()

    for domain in test_domains:
        print(f"🔍 Analyzing: {domain}")
        print("-" * 40)

        try:
            result = await detector.analyze_website(domain)

            provider = result["primary_cloud_provider"]
            confidence = result["confidence_score"]
            reason = result["primary_reason"]

            print(f"Provider: {provider}")
            print(f"Confidence: {confidence:.1f}%")
            print(f"Reason: {reason}")

            # Show discovered data
            backend_data = result.get("details", {}).get("backend_data", {})
            if backend_data:
                xhr_apis = backend_data.get("xhr_api_calls", [])
                app_subs = backend_data.get("app_subdomains", [])
                cloud_calls = backend_data.get("cloud_provider_domains", [])

                if xhr_apis:
                    print(
                        f"XHR APIs: {', '.join(xhr_apis[:3])}{'...' if len(xhr_apis) > 3 else ''}"
                    )
                if app_subs:
                    print(f"App Subdomains: {', '.join(app_subs)}")
                if cloud_calls:
                    print(
                        f"Cloud XHR Calls: {', '.join([str(c) for c in cloud_calls[:2]])}"
                    )

            # Show evidence
            evidence = result.get("evidence", [])
            if evidence:
                print("Evidence:")
                for ev in evidence[:2]:  # Show top 2 pieces of evidence
                    print(f"  • {ev['method']}: {ev['evidence'][:60]}...")

        except Exception as e:
            print(f"❌ Error: {e}")

        print()

    print("🎉 XHR-focused detection test complete!")
    print()
    print("Key differences from old approach:")
    print("✅ No main domain IP analysis")
    print("✅ Only XHR/fetch requests analyzed")
    print("✅ App subdomain exploration")
    print("✅ Real backend infrastructure focus")


if __name__ == "__main__":
    asyncio.run(test_xhr_detection())
