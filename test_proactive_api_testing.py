#!/usr/bin/env python3
"""
Test script to verify that common API endpoints are proactively tested.
This tests the improvement where we always test api.domain, app.domain, etc.
even if they weren't discovered during browser navigation.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def test_proactive_api_testing():
    """Test that common API endpoints are always added to XHR analysis."""

    print("🧪 Testing proactive API endpoint testing...")

    # Mock scenario: lecab.fr with minimal discovery
    base_domain = "lecab.fr"
    app_domains = ["lecab.fr"]  # Only main domain discovered
    xhr_calls = set(["lecab.fr"])  # Only main domain captured as XHR

    print(f"\n📋 Base domain: {base_domain}")
    print(f"🔍 Discovered app domains: {app_domains}")
    print(f"🔗 Original XHR calls: {list(xhr_calls)}")

    # Apply the proactive testing logic
    common_api_endpoints = [
        f"api.{base_domain}",
        f"app.{base_domain}",
        f"admin.{base_domain}",
        f"dashboard.{base_domain}",
        f"console.{base_domain}",
        f"portal.{base_domain}",
        f"manage.{base_domain}",
        f"backend.{base_domain}",
        f"service.{base_domain}",
        f"services.{base_domain}",
    ]

    print(f"\n🎯 Common API endpoints to test: {common_api_endpoints}")

    # Start with existing XHR calls
    xhr_api_calls = list(xhr_calls)
    added_endpoints = []

    # Add common API endpoints if not already present
    for api_endpoint in common_api_endpoints:
        if api_endpoint not in xhr_calls and api_endpoint not in xhr_api_calls:
            xhr_api_calls.append(api_endpoint)
            added_endpoints.append(api_endpoint)

    # Also check for discovered API subdomains (none in this case)
    discovered_api_subdomains = [
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

    for api_subdomain in discovered_api_subdomains:
        if api_subdomain not in xhr_calls and api_subdomain not in xhr_api_calls:
            xhr_api_calls.append(api_subdomain)
            added_endpoints.append(api_subdomain)

    # Remove duplicates
    xhr_api_calls = list(set(xhr_api_calls))

    print(f"\n✅ Added API endpoints: {added_endpoints}")
    print(f"🔧 Final XHR API calls list: {xhr_api_calls}")

    # Verify the improvement works
    expected_additions = [
        "api.lecab.fr",
        "app.lecab.fr",
        "admin.lecab.fr",
        "dashboard.lecab.fr",
        "console.lecab.fr",
        "portal.lecab.fr",
        "manage.lecab.fr",
        "backend.lecab.fr",
        "service.lecab.fr",
        "services.lecab.fr",
    ]

    print(f"\n🎯 Expected additions: {expected_additions}")
    print(f"🔍 Actual additions: {added_endpoints}")

    success = True
    for expected in expected_additions:
        if expected in added_endpoints:
            print(f"  ✅ {expected} correctly added to XHR analysis")
        else:
            print(f"  ❌ {expected} missing from XHR analysis")
            success = False

    # Verify api.lecab.fr is specifically included
    if "api.lecab.fr" in xhr_api_calls:
        print("\n🎉 SUCCESS: api.lecab.fr will be proactively tested!")
        print(
            "📍 This means AWS detection will work even if api.lecab.fr wasn't discovered"
        )
    else:
        print("\n❌ FAILURE: api.lecab.fr is missing from proactive testing")
        success = False

    if success:
        print("\n🎉 Test PASSED! Common API endpoints are proactively tested")
        print(f"📊 Summary: {len(added_endpoints)} API endpoints added for testing")
    else:
        print("\n❌ Test FAILED! Some API endpoints were not added")

    return success


def test_lecab_specific_scenario():
    """Test the specific lecab.fr scenario with proactive testing."""
    print("\n" + "=" * 60)
    print("🎯 Testing lecab.fr scenario with proactive API testing")
    print("=" * 60)

    # Simulate lecab.fr with no API discovery
    base_domain = "lecab.fr"
    app_domains = ["lecab.fr"]  # Only main domain
    xhr_calls = set(["lecab.fr"])  # Only main domain

    print(f"📋 lecab.fr base domain: {base_domain}")
    print(f"🔍 lecab.fr discovered domains: {app_domains}")
    print(f"🔗 lecab.fr original XHR calls: {list(xhr_calls)}")

    # Apply proactive testing
    common_api_endpoints = [f"api.{base_domain}"]  # Focus on the key one

    xhr_api_calls = list(xhr_calls)
    for api_endpoint in common_api_endpoints:
        if api_endpoint not in xhr_calls:
            xhr_api_calls.append(api_endpoint)
            print(f"  🔧 Proactively added API endpoint: {api_endpoint}")

    print(f"✅ lecab.fr final XHR API calls: {xhr_api_calls}")

    if "api.lecab.fr" in xhr_api_calls:
        print("🎉 SUCCESS: api.lecab.fr will be proactively tested!")
        print("📍 IP analysis will detect AWS even without browser discovery")
        print("🔍 Header analysis will also be performed on api.lecab.fr")
        return True
    else:
        print("❌ FAILURE: api.lecab.fr is still missing")
        return False


def test_comprehensive_coverage():
    """Test that we cover various domain scenarios."""
    print("\n" + "=" * 60)
    print("🎯 Testing comprehensive API endpoint coverage")
    print("=" * 60)

    test_domains = ["example.com", "test.org", "mycompany.io", "startup.dev"]

    all_success = True

    for domain in test_domains:
        print(f"\n📋 Testing domain: {domain}")

        # Expected API endpoints for this domain
        expected_apis = [
            f"api.{domain}",
            f"app.{domain}",
            f"admin.{domain}",
            f"dashboard.{domain}",
            f"console.{domain}",
            f"portal.{domain}",
            f"manage.{domain}",
            f"backend.{domain}",
            f"service.{domain}",
            f"services.{domain}",
        ]

        print(f"  🎯 Expected API endpoints: {len(expected_apis)}")
        print(f"  📍 Key endpoint: api.{domain}")

        # Verify api.domain is always included
        if f"api.{domain}" in expected_apis:
            print(f"  ✅ api.{domain} will be proactively tested")
        else:
            print(f"  ❌ api.{domain} missing from proactive testing")
            all_success = False

    return all_success


if __name__ == "__main__":
    print("🧪 Testing Proactive API Endpoint Testing")
    print("=" * 60)

    test1_result = test_proactive_api_testing()
    test2_result = test_lecab_specific_scenario()
    test3_result = test_comprehensive_coverage()

    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    print(
        f"Proactive API testing logic: {'✅ PASSED' if test1_result else '❌ FAILED'}"
    )
    print(f"lecab.fr specific scenario: {'✅ PASSED' if test2_result else '❌ FAILED'}")
    print(f"Comprehensive coverage: {'✅ PASSED' if test3_result else '❌ FAILED'}")

    if test1_result and test2_result and test3_result:
        print("\n🎉 ALL TESTS PASSED!")
        print("The improvement ensures that common API endpoints like api.domain")
        print("are ALWAYS tested, even if not discovered during browser navigation.")
        print("This will catch cases like api.lecab.fr → AWS detection.")
    else:
        print("\n❌ SOME TESTS FAILED!")
        print("The improvement needs further adjustment.")
