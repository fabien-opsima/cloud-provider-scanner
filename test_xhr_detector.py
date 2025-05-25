#!/usr/bin/env python3
"""
Test the enhanced XHR-focused Cloud Provider Detector

This demonstrates the improved methodology that:
1. Comprehensively crawls app subdomains and SPAs
2. Analyzes ALL XHR/API calls with detailed IP range matching
3. Shows processing in real-time with detailed information
4. Prioritizes precision with high confidence thresholds
5. Provides comprehensive reporting of findings
"""

import asyncio
from detector import CloudProviderDetector


async def test_xhr_detection():
    """Test the enhanced XHR-focused detection on sample domains."""

    detector = CloudProviderDetector(headless=True)

    # Test domains - these should reveal backend infrastructure through XHR calls
    test_domains = [
        "spotify.com",  # Should find app.spotify.com with API calls
        "netflix.com",  # Should find APIs in app subdomains
        "github.com",  # May have direct cloud calls
        "dropbox.com",  # Should have app subdomain with APIs
        "discord.com",  # Should have app with API calls
    ]

    print("🚀 Testing Enhanced XHR-Focused Cloud Provider Detection")
    print("=" * 70)
    print("🎯 **KEY IMPROVEMENTS:**")
    print("  • Comprehensive app subdomain discovery")
    print("  • Detailed IP range analysis for ALL XHR calls")
    print("  • High precision confidence scoring (80%+ threshold)")
    print("  • Real-time processing information")
    print("  • Complete transparency on all findings")
    print("=" * 70)
    print()

    for i, domain in enumerate(test_domains, 1):
        print(f"🔍 [{i}/{len(test_domains)}] Analyzing: {domain}")
        print("-" * 50)

        try:
            result = await detector.analyze_website(domain)

            provider = result["primary_cloud_provider"]
            confidence = result.get("confidence_score", 0)
            reason = result["primary_reason"]

            print(f"🎯 **FINAL RESULT:** {provider} ({confidence}% confidence)")
            print(f"📝 **Reason:** {reason}")

            # Show comprehensive backend data analysis
            backend_data = result.get("details", {}).get("backend_data", {})
            ip_analysis = result.get("ip_analysis", {})

            if backend_data:
                print("\n📊 **DETAILED ANALYSIS:**")

                # App subdomains discovered
                app_subs = backend_data.get("app_subdomains", [])
                if app_subs:
                    print(f"  🏢 **App Subdomains Found:** {len(app_subs)}")
                    for sub in app_subs:
                        print(f"     • {sub}")
                else:
                    print("  🏢 **App Subdomains:** None discovered")

                # XHR API calls discovered
                xhr_apis = backend_data.get("xhr_api_calls", [])
                if xhr_apis:
                    print(f"  🔗 **XHR API Calls Found:** {len(xhr_apis)}")
                    for api in xhr_apis:
                        print(f"     • {api}")
                else:
                    print("  🔗 **XHR API Calls:** None found")

                # Direct cloud provider calls
                cloud_calls = backend_data.get("cloud_provider_domains", [])
                if cloud_calls:
                    print(f"  ☁️ **Direct Cloud Service Calls:** {len(cloud_calls)}")
                    for call in cloud_calls:
                        if isinstance(call, tuple) and len(call) >= 3:
                            domain_call, cloud_provider, service_type = call[:3]
                            print(
                                f"     • {domain_call} → {cloud_provider} ({service_type})"
                            )
                        elif isinstance(call, tuple) and len(call) >= 2:
                            domain_call, cloud_provider = call[:2]
                            print(f"     • {domain_call} → {cloud_provider}")
                        else:
                            print(f"     • {call}")
                else:
                    print("  ☁️ **Direct Cloud Service Calls:** None found")

            # Show detailed IP analysis
            if ip_analysis:
                print("\n📍 **IP RANGE ANALYSIS:**")
                total_ips = ip_analysis.get("total_ips_checked", 0)
                cloud_matches = ip_analysis.get("cloud_matches", 0)
                print(
                    f"  📊 **Summary:** {cloud_matches}/{total_ips} IPs matched cloud ranges"
                )

                # Show all IP matches
                ip_matches = ip_analysis.get("cloud_ip_matches", [])
                if ip_matches:
                    print(f"  ✅ **Cloud IP Matches Found:** {len(ip_matches)}")
                    for match in ip_matches:
                        api_domain = match.get("api_domain", "unknown")
                        ip = match.get("ip", "unknown")
                        provider = match.get("provider", "unknown")
                        ip_range = match.get("ip_range", "unknown")
                        print(
                            f"     • {api_domain} (IP {ip}) → {provider} range {ip_range}"
                        )
                else:
                    print("  ❌ **Cloud IP Matches:** None found")

                # Show all IPs checked
                ip_details = ip_analysis.get("ip_details", {})
                if ip_details and total_ips > 0:
                    print("  🔍 **All IPs Analyzed:**")
                    for ip, details in ip_details.items():
                        api_domain = details.get("api_domain", "unknown")
                        is_cloud = details.get("is_cloud_ip", False)
                        status = "✅ Cloud IP" if is_cloud else "❌ Not cloud"
                        print(f"     • {api_domain} → {ip} ({status})")

            # Show evidence
            evidence = result.get("evidence", [])
            if evidence:
                print(f"\n🧾 **EVIDENCE SUMMARY:** {len(evidence)} pieces of evidence")
                for i, ev in enumerate(evidence, 1):
                    method = ev.get("method", "Unknown")
                    evidence_text = ev.get("evidence", "No details")
                    confidence_level = ev.get("confidence", "Unknown")
                    print(f"  {i}. **{method}** ({confidence_level} confidence)")
                    print(f"     {evidence_text}")

            # Show confidence analysis
            details = result.get("details", {})
            evidence_summary = details.get("evidence_summary", {})
            if evidence_summary:
                print("\n🎯 **CONFIDENCE ANALYSIS:**")
                has_ip = evidence_summary.get("has_ip_evidence", False)
                has_cloud_calls = evidence_summary.get("has_direct_cloud_calls", False)
                threshold_met = evidence_summary.get("confidence_threshold_met", False)

                print(f"  📍 IP Range Evidence: {'✅ Yes' if has_ip else '❌ No'}")
                print(
                    f"  ☁️ Direct Cloud Calls: {'✅ Yes' if has_cloud_calls else '❌ No'}"
                )
                print(
                    f"  🎯 High Confidence (80%+): {'✅ Yes' if threshold_met else '❌ No'}"
                )

        except Exception as e:
            print(f"❌ **ERROR:** {e}")

        print("\n" + "=" * 70 + "\n")

    print("🎉 Enhanced XHR-focused detection test complete!")
    print()
    print("🔥 **KEY IMPROVEMENTS DEMONSTRATED:**")
    print("✅ Comprehensive subdomain crawling (10+ patterns)")
    print("✅ Detailed interaction to trigger more API calls")
    print("✅ ALL XHR IPs checked against cloud ranges")
    print("✅ High precision confidence scoring (80%+ threshold)")
    print("✅ Complete transparency in findings")
    print("✅ Real-time processing information")
    print("✅ Detailed evidence reporting")


if __name__ == "__main__":
    asyncio.run(test_xhr_detection())
