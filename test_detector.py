#!/usr/bin/env python3
"""
Test script for the Cloud Provider Detector
"""

import asyncio
import pandas as pd
from detector import CloudProviderDetector


async def test_detector():
    """Test the detector with a few sample domains."""
    detector = CloudProviderDetector()

    # Test domains with known providers
    test_domains = [
        "netflix.com",  # Should be AWS
        "spotify.com",  # Should be GCP
        "github.com",  # Should be Other (GitHub uses their own infrastructure)
    ]

    print("Testing Cloud Provider Detector...")
    print("=" * 50)

    for domain in test_domains:
        try:
            result = await detector.analyze_website(domain)
            print(f"Domain: {domain}")
            print(f"Provider: {result['primary_cloud_provider']}")
            print(f"Confidence: {result['confidence_score']:.1f}%")
            print(f"Main IPs: {result['details'].get('main_domain_ips', [])}")
            print(
                f"Backend IPs: {len(result['details'].get('backend_ips', []))} discovered"
            )
            print("-" * 30)
        except Exception as e:
            print(f"Error analyzing {domain}: {e}")
            print("-" * 30)


def test_accuracy_small():
    """Test accuracy on a small subset of test data."""
    print("\nTesting accuracy on small subset...")
    print("=" * 50)

    # Load first 10 rows of test data
    df = pd.read_csv("data/test.csv").head(10)

    detector = CloudProviderDetector()
    correct = 0
    total = 0

    for _, row in df.iterrows():
        domain = row["domain"]
        true_label = row["cloud_provider"]

        try:
            result = asyncio.run(detector.analyze_website(domain))
            predicted_label = result["primary_cloud_provider"]

            is_correct = predicted_label == true_label
            if is_correct:
                correct += 1
            total += 1

            print(
                f"{domain}: True={true_label}, Predicted={predicted_label}, Correct={is_correct}"
            )

        except Exception as e:
            print(f"Error analyzing {domain}: {e}")
            total += 1

    accuracy = correct / total if total > 0 else 0
    print(f"\nAccuracy on {total} samples: {accuracy:.2f} ({correct}/{total})")


if __name__ == "__main__":
    # Test basic functionality
    asyncio.run(test_detector())

    # Test accuracy on small subset
    test_accuracy_small()
