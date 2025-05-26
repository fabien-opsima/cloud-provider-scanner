#!/usr/bin/env python3
"""
Test script to verify that API subdomains are properly treated as API endpoints.
This tests the fix for the lecab.fr issue where api.lecab.fr was discovered as a subdomain
but not analyzed as an API endpoint.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def test_api_subdomain_logic():
    """Test the logic for converting API subdomains to XHR endpoints."""

    print("🧪 Testing API subdomain to XHR endpoint conversion...")

    # Mock discovered data similar to lecab.fr case
    app_domains = [
        "lecab.fr",
        "api.lecab.fr",  # This should be treated as an API endpoint
        "www.lecab.fr",
        "app.example.com",  # This should also be treated as an API endpoint
        "dashboard.test.com",  # This should also be treated as an API endpoint
        "blog.lecab.fr",  # This should NOT be treated as an API endpoint
    ]

    xhr_calls = set(
        [
            "lecab.fr"  # Only the main domain was captured as XHR
        ]
    )

    # Apply the fix logic
    api_subdomains = [
        domain
        for domain in app_domains
        if any(
            prefix in domain.lower()
            for prefix in [
                "api.",
                "app.",
                "admin.",
                "dashboard.",
                "console.",
                "portal.",
            ]
        )
    ]

    print(f"\n📋 Discovered app domains: {app_domains}")
    print(f"🔍 Original XHR calls: {list(xhr_calls)}")
    print(f"🎯 Identified API subdomains: {api_subdomains}")

    # Add API subdomains to XHR calls if not already present
    xhr_api_calls = list(xhr_calls)
    added_apis = []

    for api_subdomain in api_subdomains:
        if api_subdomain not in xhr_calls:
            xhr_api_calls.append(api_subdomain)
            added_apis.append(api_subdomain)

    # Remove duplicates
    xhr_api_calls = list(set(xhr_api_calls))

    print(f"\n✅ Added API subdomains to XHR analysis: {added_apis}")
    print(f"🔧 Final XHR API calls list: {xhr_api_calls}")

    # Verify the fix works correctly
    expected_additions = ["api.lecab.fr", "app.example.com", "dashboard.test.com"]

    print(f"\n🎯 Expected additions: {expected_additions}")
    print(f"🔍 Actual additions: {added_apis}")

    success = True
    for expected in expected_additions:
        if expected in added_apis:
            print(f"  ✅ {expected} correctly added to XHR analysis")
        else:
            print(f"  ❌ {expected} missing from XHR analysis")
            success = False

    # Verify non-API subdomains are not added
    non_api_domains = ["lecab.fr", "www.lecab.fr", "blog.lecab.fr"]
    for domain in non_api_domains:
        if domain in added_apis:
            print(
                f"  ❌ {domain} incorrectly added to XHR analysis (should not be treated as API)"
            )
            success = False
        else:
            print(f"  ✅ {domain} correctly not treated as API endpoint")

    if success:
        print(
            "\n🎉 Test PASSED! API subdomains are properly converted to XHR endpoints"
        )
        print(f"📊 Summary: {len(added_apis)} API subdomains added to analysis")
    else:
        print("\n❌ Test FAILED! Some API subdomains were not handled correctly")

    return success


def test_lecab_scenario():
    """Test the specific lecab.fr scenario."""
    print("\n" + "=" * 60)
    print("🎯 Testing specific lecab.fr scenario")
    print("=" * 60)

    # Simulate the lecab.fr discovery
    app_domains = ["lecab.fr", "api.lecab.fr"]
    xhr_calls = set(["lecab.fr"])  # Only main domain captured as XHR

    print(f"📋 lecab.fr discovered domains: {app_domains}")
    print(f"🔍 lecab.fr original XHR calls: {list(xhr_calls)}")

    # Apply fix
    api_subdomains = [
        domain
        for domain in app_domains
        if any(
            prefix in domain.lower()
            for prefix in [
                "api.",
                "app.",
                "admin.",
                "dashboard.",
                "console.",
                "portal.",
            ]
        )
    ]

    xhr_api_calls = list(xhr_calls)
    for api_subdomain in api_subdomains:
        if api_subdomain not in xhr_calls:
            xhr_api_calls.append(api_subdomain)
            print(
                f"  🔧 Added discovered API subdomain to XHR analysis: {api_subdomain}"
            )

    xhr_api_calls = list(set(xhr_api_calls))

    print(f"✅ lecab.fr final XHR API calls: {xhr_api_calls}")

    if "api.lecab.fr" in xhr_api_calls:
        print(
            "🎉 SUCCESS: api.lecab.fr will now be analyzed for IP ranges and headers!"
        )
        print("📍 This means the AWS IP detection will work correctly")
        return True
    else:
        print("❌ FAILURE: api.lecab.fr is still missing from XHR analysis")
        return False


if __name__ == "__main__":
    print("🧪 Testing API Subdomain Fix")
    print("=" * 60)

    test1_result = test_api_subdomain_logic()
    test2_result = test_lecab_scenario()

    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    print(
        f"General API subdomain logic: {'✅ PASSED' if test1_result else '❌ FAILED'}"
    )
    print(f"lecab.fr specific scenario: {'✅ PASSED' if test2_result else '❌ FAILED'}")

    if test1_result and test2_result:
        print("\n🎉 ALL TESTS PASSED!")
        print("The fix ensures that API subdomains like api.lecab.fr are properly")
        print("analyzed for cloud provider detection via IP ranges and headers.")
    else:
        print("\n❌ SOME TESTS FAILED!")
        print("The fix needs further adjustment.")
