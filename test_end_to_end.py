#!/usr/bin/env python3
"""
End-to-end test for the enhanced cloud provider detection system.
Tests all detection methods and validates the robustness of the system.
"""

import asyncio
import pandas as pd
import sys
import os
import time

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cloud_provider_scanner.scanner_streamlit import CloudProviderDetector


async def test_detection_methods():
    """Test all individual detection methods."""
    print("🔬 Testing Individual Detection Methods")
    print("=" * 60)

    detector = CloudProviderDetector(headless=True)
    await detector.load_cloud_ip_ranges()

    # Test domains with known providers
    test_cases = [
        {
            "domain": "microsoft.com",
            "expected": "Azure",
            "url": "https://microsoft.com",
        },
        {"domain": "amazonaws.com", "expected": "AWS", "url": "https://aws.amazon.com"},
        {
            "domain": "firebase.google.com",
            "expected": "GCP",
            "url": "https://firebase.google.com",
        },
    ]

    for test_case in test_cases:
        domain = test_case["domain"]
        expected = test_case["expected"]
        url = test_case["url"]

        print(f"\n🎯 Testing: {domain} (Expected: {expected})")
        print("-" * 40)

        # Test IP resolution
        ips = detector.resolve_domain_to_ips(domain)
        print(f"   📍 Resolved IPs: {len(ips)} addresses")

        # Test IP range detection
        ip_detections = []
        for ip in ips[:3]:  # Test first 3 IPs
            provider = detector.check_ip_against_cloud_ranges(ip)
            if provider:
                ip_detections.append(provider)
                print(f"   ☁️  {ip} -> {provider}")

        # Test SSL certificate analysis
        ssl_scores = await detector.analyze_ssl_certificate(domain)
        ssl_detections = [p for p, s in ssl_scores.items() if s > 0]
        if ssl_detections:
            print(f"   🔒 SSL detections: {ssl_detections}")

        # Test security headers
        header_scores = await detector.analyze_security_headers(url)
        header_detections = [p for p, s in header_scores.items() if s > 0]
        if header_detections:
            print(f"   🛡️  Header detections: {header_detections}")

        # Test DNS analysis
        dns_scores = await detector.analyze_dns_records(domain)
        dns_detections = [p for p, s in dns_scores.items() if s > 0]
        if dns_detections:
            print(f"   🌍 DNS detections: {dns_detections}")

        # Test content analysis (limited for speed)
        content_scores = await detector.analyze_website_content(url)
        content_detections = [p for p, s in content_scores.items() if s > 0]
        if content_detections:
            print(f"   📄 Content detections: {content_detections}")

        # Summary
        all_detections = (
            ip_detections
            + ssl_detections
            + header_detections
            + dns_detections
            + content_detections
        )
        if expected in all_detections:
            print(f"   ✅ SUCCESS: {expected} detected correctly")
        else:
            print(f"   ⚠️  PARTIAL: Expected {expected}, got {set(all_detections)}")


async def test_full_analysis():
    """Test full website analysis."""
    print("\n🚀 Testing Full Website Analysis")
    print("=" * 60)

    detector = CloudProviderDetector(headless=True)
    await detector.load_cloud_ip_ranges()

    # Test websites across different providers
    test_sites = [
        {"url": "github.com", "expected": "Azure", "note": "GitHub is hosted on Azure"},
        {"url": "microsoft.com", "expected": "Azure", "note": "Microsoft's own site"},
        {
            "url": "firebase.google.com",
            "expected": "GCP",
            "note": "Firebase is Google's product",
        },
        {"url": "netflix.com", "expected": "AWS", "note": "Netflix uses AWS heavily"},
    ]

    results = []
    for site in test_sites:
        url = site["url"]
        expected = site["expected"]
        note = site["note"]

        print(f"\n🌐 Analyzing: {url}")
        print(f"   Expected: {expected} ({note})")

        start_time = time.time()
        result = await detector.analyze_website(url)
        analysis_time = time.time() - start_time

        detected = result["primary_cloud_provider"]
        confidence = result["confidence_score"]

        print(f"   Detected: {detected}")
        print(f"   Confidence: {confidence:.1f}%")
        print(f"   Analysis time: {analysis_time:.2f}s")

        # Detailed breakdown
        if "provider_scores" in result["details"]:
            scores = result["details"]["provider_scores"]
            top_scores = [(p, s) for p, s in scores.items() if s > 0]
            if top_scores:
                top_scores.sort(key=lambda x: x[1], reverse=True)
                print(f"   Score breakdown: {top_scores}")

        results.append(
            {
                "url": url,
                "expected": expected,
                "detected": detected,
                "confidence": confidence,
                "correct": detected == expected,
                "analysis_time": analysis_time,
            }
        )

        if detected == expected:
            print("   ✅ CORRECT detection!")
        elif confidence > 0:
            print("   ⚠️  Different provider detected")
        else:
            print("   ❌ No detection")

    return results


async def test_robustness():
    """Test robustness with edge cases."""
    print("\n🛡️  Testing Robustness & Error Handling")
    print("=" * 60)

    detector = CloudProviderDetector(headless=True)
    await detector.load_cloud_ip_ranges()

    # Test edge cases
    edge_cases = [
        "nonexistent-domain-12345.com",  # Non-existent domain
        "localhost",  # Local domain
        "192.168.1.1",  # Direct IP
        "malformed-url",  # Malformed URL
    ]

    for case in edge_cases:
        print(f"\n🔍 Testing edge case: {case}")
        try:
            result = await detector.analyze_website(case)
            print(
                f"   Result: {result['primary_cloud_provider']} ({result['confidence_score']:.1f}%)"
            )
            if "error" in result["details"]:
                print(f"   Error handled: {result['details']['error']}")
        except Exception as e:
            print(f"   Exception handled: {e}")


async def test_csv_workflow():
    """Test the CSV processing workflow."""
    print("\n📊 Testing CSV Workflow")
    print("=" * 60)

    # Create test data
    test_data = pd.DataFrame(
        {
            "domain": [
                "github.com",
                "microsoft.com",
                "firebase.google.com",
                "netflix.com",
            ],
            "expected_provider": ["Azure", "Azure", "GCP", "AWS"],
        }
    )

    test_file = "end_to_end_test.csv"
    test_data.to_csv(test_file, index=False)
    print(f"📄 Created test file: {test_file}")

    # Process CSV
    detector = CloudProviderDetector(headless=True)
    await detector.load_cloud_ip_ranges()

    results = []
    for _, row in test_data.iterrows():
        domain = row["domain"]
        expected = row["expected_provider"]

        result = await detector.analyze_website(domain)
        detected = result["primary_cloud_provider"]
        confidence = result["confidence_score"]

        results.append(
            {
                "domain": domain,
                "expected_provider": expected,
                "detected_provider": detected,
                "confidence_score": confidence,
                "correct_detection": detected == expected,
                "ip_addresses": ", ".join(result["details"].get("main_domain_ips", [])),
            }
        )

    # Save results
    results_df = pd.DataFrame(results)
    results_file = "end_to_end_results.csv"
    results_df.to_csv(results_file, index=False)

    print(f"💾 Results saved to: {results_file}")

    # Summary statistics
    correct_count = sum(r["correct_detection"] for r in results)
    total_count = len(results)
    accuracy = (correct_count / total_count) * 100 if total_count > 0 else 0

    print(f"📈 Accuracy: {correct_count}/{total_count} ({accuracy:.1f}%)")

    return results_df


async def main():
    """Main test function."""
    print("🚀 Enhanced Cloud Provider Detection - End-to-End Test")
    print("=" * 80)

    start_time = time.time()

    try:
        # Test individual detection methods
        await test_detection_methods()

        # Test full analysis
        analysis_results = await test_full_analysis()

        # Test robustness
        await test_robustness()

        # Test CSV workflow
        csv_results = await test_csv_workflow()

        total_time = time.time() - start_time

        print("\n🎉 End-to-End Test Completed!")
        print("=" * 80)
        print(f"⏱️  Total execution time: {total_time:.2f} seconds")

        # Final summary
        if analysis_results:
            correct_analyses = sum(1 for r in analysis_results if r["correct"])
            total_analyses = len(analysis_results)
            avg_confidence = (
                sum(r["confidence"] for r in analysis_results) / total_analyses
            )
            avg_time = (
                sum(r["analysis_time"] for r in analysis_results) / total_analyses
            )

            print("📊 Analysis Summary:")
            print(f"   Correct detections: {correct_analyses}/{total_analyses}")
            print(f"   Average confidence: {avg_confidence:.1f}%")
            print(f"   Average analysis time: {avg_time:.2f}s")

        print("\n✅ All tests completed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
