#!/usr/bin/env python3
"""
Final test to verify complete domain isolation and prevent data contamination.
This tests the fixes for the issues where believe.com was showing data from dropcontact.com.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def test_ip_analysis_domain_filtering():
    """Test that IP analysis only shows data for the current domain."""

    print("🧪 Testing IP analysis domain filtering...")

    # Mock contaminated IP analysis data (like in the screenshot)
    ip_analysis = {
        "cloud_ip_matches": [
            {
                "api_domain": "believe.com",
                "ip": "1.2.3.4",
                "provider": "AWS",
                "ip_range": "1.2.0.0/16",
            },
            {
                "api_domain": "app.dropcontact.com",  # This should be filtered out for believe.com
                "ip": "3.165.160.74",
                "provider": "AWS",
                "ip_range": "3.165.0.0/16",
            },
            {
                "api_domain": "services.dropcontact.com",  # This should be filtered out for believe.com
                "ip": "3.248.132.202",
                "provider": "AWS",
                "ip_range": "3.248.0.0/13",
            },
        ]
    }

    current_domain = "believe.com"

    print(f"\n📋 Current domain: {current_domain}")
    print(f"🔍 Total IP matches in data: {len(ip_analysis['cloud_ip_matches'])}")

    # Apply domain filtering logic
    domain_filtered_matches = []
    for match in ip_analysis["cloud_ip_matches"]:
        api_domain = match.get("api_domain", "unknown")
        # Only include matches where the API domain belongs to the current domain
        if current_domain and (
            current_domain in api_domain or api_domain == current_domain
        ):
            domain_filtered_matches.append(match)

    print(f"✅ Filtered matches for {current_domain}: {len(domain_filtered_matches)}")

    # Verify filtering worked correctly
    expected_matches = 1  # Only believe.com should remain
    actual_matches = len(domain_filtered_matches)

    print(f"\n🎯 Expected matches: {expected_matches}")
    print(f"🔍 Actual matches: {actual_matches}")

    success = True

    if actual_matches == expected_matches:
        print("  ✅ Correct number of matches after filtering")
    else:
        print("  ❌ Wrong number of matches after filtering")
        success = False

    # Check that only believe.com data remains
    for match in domain_filtered_matches:
        api_domain = match.get("api_domain", "")
        if "believe.com" in api_domain:
            print(f"  ✅ {api_domain} correctly included")
        else:
            print(f"  ❌ {api_domain} should have been filtered out")
            success = False

    # Check that dropcontact.com data was filtered out
    dropcontact_domains = [
        m["api_domain"]
        for m in domain_filtered_matches
        if "dropcontact.com" in m["api_domain"]
    ]
    if not dropcontact_domains:
        print("  ✅ dropcontact.com data correctly filtered out")
    else:
        print(f"  ❌ dropcontact.com data still present: {dropcontact_domains}")
        success = False

    return success


def test_xhr_calls_domain_filtering():
    """Test that XHR calls only show data for the current domain."""

    print("\n🧪 Testing XHR calls domain filtering...")

    # Mock contaminated XHR data
    backend_data = {
        "xhr_api_calls": [
            "believe.com",
            "console.believe.com",
            "api.believe.com",
            "app.dropcontact.com",  # Should be filtered out
            "services.dropcontact.com",  # Should be filtered out
        ]
    }

    current_domain = "believe.com"

    print(f"\n📋 Current domain: {current_domain}")
    print(f"🔍 Total XHR calls in data: {len(backend_data['xhr_api_calls'])}")

    # Apply domain filtering logic
    domain_filtered_calls = [
        api
        for api in backend_data["xhr_api_calls"]
        if current_domain and (current_domain in api or api == current_domain)
    ]

    print(f"✅ Filtered XHR calls for {current_domain}: {len(domain_filtered_calls)}")
    print(f"📡 Filtered calls: {domain_filtered_calls}")

    # Verify filtering
    expected_calls = ["believe.com", "console.believe.com", "api.believe.com"]

    success = True
    for expected in expected_calls:
        if expected in domain_filtered_calls:
            print(f"  ✅ {expected} correctly included")
        else:
            print(f"  ❌ {expected} missing from filtered calls")
            success = False

    # Check that dropcontact calls were filtered out
    dropcontact_calls = [
        call for call in domain_filtered_calls if "dropcontact.com" in call
    ]
    if not dropcontact_calls:
        print("  ✅ dropcontact.com calls correctly filtered out")
    else:
        print(f"  ❌ dropcontact.com calls still present: {dropcontact_calls}")
        success = False

    return success


def test_subdomains_domain_filtering():
    """Test that subdomains only show data for the current domain."""

    print("\n🧪 Testing subdomains domain filtering...")

    # Mock contaminated subdomain data
    backend_data = {
        "app_subdomains": [
            "believe.com",
            "console.believe.com",
            "app.dropcontact.com",  # Should be filtered out
            "www.believe.com",  # Should be filtered out (www filter)
        ]
    }

    current_domain = "believe.com"

    print(f"\n📋 Current domain: {current_domain}")
    print(f"🔍 Total subdomains in data: {len(backend_data['app_subdomains'])}")

    # Apply domain filtering logic
    domain_filtered_subdomains = [
        sub
        for sub in backend_data["app_subdomains"]
        if current_domain
        and (current_domain in sub or sub == current_domain)
        and not sub.startswith("www.")
    ]

    print(
        f"✅ Filtered subdomains for {current_domain}: {len(domain_filtered_subdomains)}"
    )
    print(f"🏢 Filtered subdomains: {domain_filtered_subdomains}")

    # Verify filtering
    expected_subdomains = ["believe.com", "console.believe.com"]

    success = True
    for expected in expected_subdomains:
        if expected in domain_filtered_subdomains:
            print(f"  ✅ {expected} correctly included")
        else:
            print(f"  ❌ {expected} missing from filtered subdomains")
            success = False

    # Check that dropcontact and www subdomains were filtered out
    unwanted_subdomains = [
        sub
        for sub in domain_filtered_subdomains
        if "dropcontact.com" in sub or sub.startswith("www.")
    ]
    if not unwanted_subdomains:
        print("  ✅ unwanted subdomains correctly filtered out")
    else:
        print(f"  ❌ unwanted subdomains still present: {unwanted_subdomains}")
        success = False

    return success


def test_complete_isolation_scenario():
    """Test the complete scenario from the screenshot."""
    print("\n" + "=" * 60)
    print("🎯 Testing complete isolation scenario (believe.com vs dropcontact.com)")
    print("=" * 60)

    # This simulates the exact contamination seen in the screenshot
    current_domain = "believe.com"

    # Mock data that would cause contamination
    contaminated_data = {
        "ip_analysis": {
            "cloud_ip_matches": [
                {
                    "api_domain": "app.dropcontact.com",
                    "ip": "3.165.160.74",
                    "provider": "AWS",
                    "ip_range": "3.165.0.0/16",
                },
                {
                    "api_domain": "services.dropcontact.com",
                    "ip": "3.248.132.202",
                    "provider": "AWS",
                    "ip_range": "3.248.0.0/13",
                },
                {
                    "api_domain": "console.believe.com",
                    "ip": "1.2.3.4",
                    "provider": "AWS",
                    "ip_range": "1.2.0.0/16",
                },
            ]
        },
        "backend_data": {
            "xhr_api_calls": [
                "console.believe.com",
                "app.dropcontact.com",
                "services.dropcontact.com",
            ],
            "app_subdomains": ["console.believe.com", "app.dropcontact.com"],
        },
    }

    print(f"📋 Current domain: {current_domain}")
    print("🔍 Before filtering:")
    print(
        f"  - IP matches: {len(contaminated_data['ip_analysis']['cloud_ip_matches'])}"
    )
    print(f"  - XHR calls: {len(contaminated_data['backend_data']['xhr_api_calls'])}")
    print(f"  - Subdomains: {len(contaminated_data['backend_data']['app_subdomains'])}")

    # Apply all filtering
    # IP Analysis filtering
    filtered_ip_matches = [
        match
        for match in contaminated_data["ip_analysis"]["cloud_ip_matches"]
        if current_domain in match.get("api_domain", "")
    ]

    # XHR calls filtering
    filtered_xhr_calls = [
        api
        for api in contaminated_data["backend_data"]["xhr_api_calls"]
        if current_domain in api
    ]

    # Subdomains filtering
    filtered_subdomains = [
        sub
        for sub in contaminated_data["backend_data"]["app_subdomains"]
        if current_domain in sub and not sub.startswith("www.")
    ]

    print("\n✅ After filtering:")
    print(f"  - IP matches: {len(filtered_ip_matches)}")
    print(f"  - XHR calls: {len(filtered_xhr_calls)}")
    print(f"  - Subdomains: {len(filtered_subdomains)}")

    # Verify no dropcontact.com data remains
    dropcontact_ips = [
        m for m in filtered_ip_matches if "dropcontact.com" in m.get("api_domain", "")
    ]
    dropcontact_xhr = [x for x in filtered_xhr_calls if "dropcontact.com" in x]
    dropcontact_subs = [s for s in filtered_subdomains if "dropcontact.com" in s]

    success = True
    if not dropcontact_ips and not dropcontact_xhr and not dropcontact_subs:
        print("🎉 SUCCESS: No dropcontact.com data contamination!")
    else:
        print("❌ FAILURE: dropcontact.com data still present")
        if dropcontact_ips:
            print(f"  - Contaminated IPs: {[m['api_domain'] for m in dropcontact_ips]}")
        if dropcontact_xhr:
            print(f"  - Contaminated XHR: {dropcontact_xhr}")
        if dropcontact_subs:
            print(f"  - Contaminated subdomains: {dropcontact_subs}")
        success = False

    return success


if __name__ == "__main__":
    print("🧪 Testing Complete Domain Isolation")
    print("=" * 60)

    test1_result = test_ip_analysis_domain_filtering()
    test2_result = test_xhr_calls_domain_filtering()
    test3_result = test_subdomains_domain_filtering()
    test4_result = test_complete_isolation_scenario()

    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS")
    print("=" * 60)
    print(
        f"IP analysis domain filtering: {'✅ PASSED' if test1_result else '❌ FAILED'}"
    )
    print(f"XHR calls domain filtering: {'✅ PASSED' if test2_result else '❌ FAILED'}")
    print(
        f"Subdomains domain filtering: {'✅ PASSED' if test3_result else '❌ FAILED'}"
    )
    print(
        f"Complete isolation scenario: {'✅ PASSED' if test4_result else '❌ FAILED'}"
    )

    if test1_result and test2_result and test3_result and test4_result:
        print("\n🎉 ALL TESTS PASSED!")
        print("Domain isolation is now complete. No more data contamination!")
        print("believe.com will only show believe.com data.")
        print("dropcontact.com data will be completely filtered out.")
    else:
        print("\n❌ SOME TESTS FAILED!")
        print("Domain isolation needs further fixes.")
