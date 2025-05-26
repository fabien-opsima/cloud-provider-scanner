#!/usr/bin/env python3
"""
Comprehensive test to verify complete elimination of data contamination between domain analyses.
This test ensures that each domain analysis only shows its own data.
"""

import asyncio
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector import CloudProviderDetector
from app import create_test_result, create_deep_copy_result_data


async def test_complete_data_isolation():
    """Test that domain results are completely isolated with no contamination."""
    print("🧪 Testing COMPLETE data isolation between domain analyses...")
    print("=" * 70)

    detector = CloudProviderDetector(headless=True)

    # Test with domains that are likely to have different cloud providers
    test_domains = [
        "dropcontact.com",  # Likely different provider
        "believe.com",  # Likely different provider
        "lecab.fr",  # Likely different provider
    ]

    all_results = []

    for i, domain in enumerate(test_domains, 1):
        print(f"\n🔍 [{i}/{len(test_domains)}] Analyzing: {domain}")
        print("-" * 50)

        try:
            # Run analysis
            result = await detector.analyze_website(domain)

            # Create deep copies to prevent sharing
            backend_data, ip_analysis, evidence_data = create_deep_copy_result_data(
                result
            )

            # Create test result with domain filtering
            test_result = create_test_result(
                domain=domain,
                true_label="Unknown",  # We don't care about accuracy here
                predicted_label=result["primary_cloud_provider"],
                all_detected_providers=result.get("details", {})
                .get("provider_scores", {})
                .keys(),
                confidence=result.get("confidence_score", 0),
                primary_reason=result.get("primary_reason", ""),
                is_correct=True,  # Not relevant for this test
                activity_log=[],
                backend_data=backend_data,
                ip_analysis=ip_analysis,
                evidence_data=evidence_data,
            )

            all_results.append(test_result)

            # Show what was found for this domain
            print(f"✅ Analysis complete for {domain}")
            print(f"   Provider: {result['primary_cloud_provider']}")
            print(f"   Confidence: {result.get('confidence_score', 0)}%")

            # Show backend data summary
            xhr_calls = backend_data.get("xhr_api_calls", [])
            subdomains = backend_data.get("app_subdomains", [])
            ip_matches = ip_analysis.get("cloud_ip_matches", [])

            print(f"   XHR calls: {len(xhr_calls)}")
            print(f"   Subdomains: {len(subdomains)}")
            print(f"   IP matches: {len(ip_matches)}")

            # Show evidence summary
            header_evidence = [
                e for e in evidence_data if e.get("method") == "XHR API Headers"
            ]
            print(f"   Header evidence: {len(header_evidence)} endpoints")

        except Exception as e:
            print(f"❌ Error analyzing {domain}: {e}")
            continue

    print("\n" + "=" * 70)
    print("🔍 CONTAMINATION CHECK - Verifying data isolation...")
    print("=" * 70)

    # Check for contamination between results
    contamination_found = False

    for i, result_a in enumerate(all_results):
        domain_a = result_a["domain"]
        base_domain_a = domain_a[4:] if domain_a.startswith("www.") else domain_a

        for j, result_b in enumerate(all_results):
            if i >= j:  # Skip self and already checked pairs
                continue

            domain_b = result_b["domain"]
            base_domain_b = domain_b[4:] if domain_b.startswith("www.") else domain_b

            print(f"\n🔍 Checking {domain_a} vs {domain_b}...")

            # Check XHR calls contamination
            xhr_a = result_a.get("backend_data", {}).get("xhr_api_calls", [])
            xhr_b = result_b.get("backend_data", {}).get("xhr_api_calls", [])

            # Check if domain A has XHR calls that belong to domain B
            contaminated_xhr_a = [
                xhr
                for xhr in xhr_a
                if base_domain_b in xhr and base_domain_a not in xhr
            ]
            contaminated_xhr_b = [
                xhr
                for xhr in xhr_b
                if base_domain_a in xhr and base_domain_b not in xhr
            ]

            if contaminated_xhr_a:
                print(
                    f"❌ CONTAMINATION: {domain_a} has XHR calls from {domain_b}: {contaminated_xhr_a}"
                )
                contamination_found = True
            if contaminated_xhr_b:
                print(
                    f"❌ CONTAMINATION: {domain_b} has XHR calls from {domain_a}: {contaminated_xhr_b}"
                )
                contamination_found = True

            # Check subdomains contamination
            subs_a = result_a.get("backend_data", {}).get("app_subdomains", [])
            subs_b = result_b.get("backend_data", {}).get("app_subdomains", [])

            contaminated_subs_a = [
                sub
                for sub in subs_a
                if base_domain_b in sub and base_domain_a not in sub
            ]
            contaminated_subs_b = [
                sub
                for sub in subs_b
                if base_domain_a in sub and base_domain_b not in sub
            ]

            if contaminated_subs_a:
                print(
                    f"❌ CONTAMINATION: {domain_a} has subdomains from {domain_b}: {contaminated_subs_a}"
                )
                contamination_found = True
            if contaminated_subs_b:
                print(
                    f"❌ CONTAMINATION: {domain_b} has subdomains from {domain_a}: {contaminated_subs_b}"
                )
                contamination_found = True

            # Check IP analysis contamination
            ips_a = result_a.get("ip_analysis", {}).get("cloud_ip_matches", [])
            ips_b = result_b.get("ip_analysis", {}).get("cloud_ip_matches", [])

            contaminated_ips_a = [
                ip
                for ip in ips_a
                if base_domain_b in ip.get("api_domain", "")
                and base_domain_a not in ip.get("api_domain", "")
            ]
            contaminated_ips_b = [
                ip
                for ip in ips_b
                if base_domain_a in ip.get("api_domain", "")
                and base_domain_b not in ip.get("api_domain", "")
            ]

            if contaminated_ips_a:
                print(
                    f"❌ CONTAMINATION: {domain_a} has IP matches from {domain_b}: {[ip['api_domain'] for ip in contaminated_ips_a]}"
                )
                contamination_found = True
            if contaminated_ips_b:
                print(
                    f"❌ CONTAMINATION: {domain_b} has IP matches from {domain_a}: {[ip['api_domain'] for ip in contaminated_ips_b]}"
                )
                contamination_found = True

            # Check header evidence contamination
            headers_a = [
                e
                for e in result_a.get("evidence", [])
                if e.get("method") == "XHR API Headers"
            ]
            headers_b = [
                e
                for e in result_b.get("evidence", [])
                if e.get("method") == "XHR API Headers"
            ]

            contaminated_headers_a = [
                h
                for h in headers_a
                if base_domain_b in h.get("details", {}).get("endpoint_url", "")
                and base_domain_a not in h.get("details", {}).get("endpoint_url", "")
            ]
            contaminated_headers_b = [
                h
                for h in headers_b
                if base_domain_a in h.get("details", {}).get("endpoint_url", "")
                and base_domain_b not in h.get("details", {}).get("endpoint_url", "")
            ]

            if contaminated_headers_a:
                endpoints = [
                    h.get("details", {}).get("endpoint_url", "")
                    for h in contaminated_headers_a
                ]
                print(
                    f"❌ CONTAMINATION: {domain_a} has header evidence from {domain_b}: {endpoints}"
                )
                contamination_found = True
            if contaminated_headers_b:
                endpoints = [
                    h.get("details", {}).get("endpoint_url", "")
                    for h in contaminated_headers_b
                ]
                print(
                    f"❌ CONTAMINATION: {domain_b} has header evidence from {domain_a}: {endpoints}"
                )
                contamination_found = True

            if not (
                contaminated_xhr_a
                or contaminated_xhr_b
                or contaminated_subs_a
                or contaminated_subs_b
                or contaminated_ips_a
                or contaminated_ips_b
                or contaminated_headers_a
                or contaminated_headers_b
            ):
                print(f"✅ No contamination found between {domain_a} and {domain_b}")

    print("\n" + "=" * 70)
    if contamination_found:
        print("❌ CONTAMINATION DETECTED - Data isolation is NOT working properly!")
        print("   Some domains are showing data from other domains.")
    else:
        print("✅ NO CONTAMINATION DETECTED - Data isolation is working perfectly!")
        print("   Each domain only shows its own data.")
    print("=" * 70)

    return not contamination_found


if __name__ == "__main__":
    success = asyncio.run(test_complete_data_isolation())
    if success:
        print("\n🎉 Test PASSED: Data contamination completely eliminated!")
        sys.exit(0)
    else:
        print("\n💥 Test FAILED: Data contamination still exists!")
        sys.exit(1)
