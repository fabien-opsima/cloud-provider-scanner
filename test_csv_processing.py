#!/usr/bin/env python3
"""
Test CSV processing functionality of the enhanced cloud provider scanner.
"""

import asyncio
import pandas as pd
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cloud_provider_scanner.scanner_streamlit import CloudProviderDetector


async def test_csv_processing():
    """Test processing a CSV file with the enhanced scanner."""
    print("🧪 Testing CSV Processing with Enhanced Scanner...")
    print("=" * 60)

    # Read the test CSV
    df = pd.read_csv("test_sample_data.csv")
    print(f"📄 Loaded CSV with {len(df)} domains:")
    print(df["domain"].tolist())

    # Initialize detector
    detector = CloudProviderDetector(headless=True)

    # Load IP ranges
    print("\n📡 Loading cloud provider IP ranges...")
    await detector.load_cloud_ip_ranges()

    print("\n🔍 Analyzing domains...")
    print("-" * 60)

    results = []
    for index, row in df.iterrows():
        domain = row["domain"]
        print(f"\n🌐 Analyzing: {domain}")

        try:
            result = await detector.analyze_website(domain)
            results.append(
                {
                    "domain": domain,
                    "provider": result["primary_cloud_provider"],
                    "confidence": result["confidence_score"],
                    "ips": ", ".join(result["details"].get("main_domain_ips", [])),
                    "scores": result["details"].get("provider_scores", {}),
                }
            )

            print(f"   Provider: {result['primary_cloud_provider']}")
            print(f"   Confidence: {result['confidence_score']:.1f}%")
            print(f"   IPs: {result['details'].get('main_domain_ips', [])}")

            # Show top scoring methods
            if "provider_scores" in result["details"]:
                top_scores = [
                    (p, s)
                    for p, s in result["details"]["provider_scores"].items()
                    if s > 0
                ]
                if top_scores:
                    top_scores.sort(key=lambda x: x[1], reverse=True)
                    print(f"   Top detections: {top_scores[:3]}")

        except Exception as e:
            print(f"   ❌ Error: {e}")
            results.append(
                {
                    "domain": domain,
                    "provider": "Error",
                    "confidence": 0,
                    "ips": "",
                    "scores": {},
                }
            )

    print("\n📊 Summary Results:")
    print("=" * 60)
    for result in results:
        print(
            f"{result['domain']:20} | {result['provider']:10} | {result['confidence']:6.1f}% | {result['ips']}"
        )

    # Save results to CSV
    results_df = pd.DataFrame(
        [
            {
                "domain": r["domain"],
                "detected_provider": r["provider"],
                "confidence_score": r["confidence"],
                "ip_addresses": r["ips"],
            }
            for r in results
        ]
    )

    results_df.to_csv("test_results.csv", index=False)
    print("\n💾 Results saved to test_results.csv")

    print("\n✅ CSV processing test completed!")


if __name__ == "__main__":
    asyncio.run(test_csv_processing())
