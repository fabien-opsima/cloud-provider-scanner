#!/usr/bin/env python3
"""
Test script to verify complete data isolation between domain analyses.
This tests that believe.com results don't show dropcontact.com data.
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector import CloudProviderDetector
from app import create_test_result, create_deep_copy_result_data


async def test_data_isolation():
    """Test that domain results are completely isolated."""
    print("🧪 Testing complete data isolation between domain analyses...")

    detector = CloudProviderDetector(headless=True)

    # Test domains that might have contamination
    test_domains = ["believe.com", "dropcontact.com"]
    all_results = []

    for domain in test_domains:
        print(f"\n🔍 Analyzing {domain}...")

        # Run analysis
        result = await detector.analyze_website(domain)

        # Create deep copies like the app does
        backend_data, ip_analysis, evidence_data = create_deep_copy_result_data(result)

        # Create test result with filtering
        test_result = create_test_result(
            domain=domain,
            true_label="Test",
            predicted_label=result["primary_cloud_provider"],
            all_detected_providers=[],
            confidence=result.get("confidence_score", 0),
            primary_reason=result.get("primary_reason", ""),
            is_correct=False,
            activity_log=[],
            backend_data=backend_data,
            ip_analysis=ip_analysis,
            evidence_data=evidence_data,
        )

        all_results.append(test_result)

        print(f"  ✅ {domain} analysis complete")
        print(
            f"    - XHR APIs: {len(test_result['backend_data'].get('xhr_api_calls', []))}"
        )
        print(f"    - Evidence items: {len(test_result['evidence'])}")
        print(
            f"    - IP matches: {len(test_result['ip_analysis'].get('cloud_ip_matches', []))}"
        )

    # Verify isolation
    print(f"\n🔬 Verifying data isolation between {len(all_results)} results...")

    contamination_found = False

    for i, result in enumerate(all_results):
        domain = result["domain"]
        base_domain = domain.replace("www.", "")

        print(f"\n📋 Checking {domain} result for contamination...")

        # Check XHR API calls
        xhr_calls = result["backend_data"].get("xhr_api_calls", [])
        for xhr in xhr_calls:
            if base_domain not in xhr:
                print(f"  ❌ CONTAMINATION: {domain} result contains XHR call {xhr}")
                contamination_found = True

        # Check evidence
        evidence = result.get("evidence", [])
        for ev in evidence:
            if ev.get("method") == "XHR API Headers":
                endpoint = ev.get("details", {}).get("endpoint_url", "")
                if endpoint and base_domain not in endpoint:
                    print(
                        f"  ❌ CONTAMINATION: {domain} result contains evidence from {endpoint}"
                    )
                    contamination_found = True

        # Check IP analysis
        ip_matches = result["ip_analysis"].get("cloud_ip_matches", [])
        for match in ip_matches:
            api_domain = match.get("api_domain", "")
            if api_domain and base_domain not in api_domain:
                print(
                    f"  ❌ CONTAMINATION: {domain} result contains IP match from {api_domain}"
                )
                contamination_found = True

        if not contamination_found:
            print(f"  ✅ {domain} result is clean - no contamination detected")

    # Summary
    if contamination_found:
        print("\n❌ FAILED: Data contamination still exists!")
        return False
    else:
        print("\n✅ SUCCESS: All domain results are properly isolated!")
        return True


if __name__ == "__main__":
    success = asyncio.run(test_data_isolation())
    sys.exit(0 if success else 1)
