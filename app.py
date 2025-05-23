#!/usr/bin/env python3
"""
Streamlit Cloud Provider Scanner Application

A web interface for detecting cloud providers used by websites.
Features:
- Upload CSV files with domains for batch analysis
- Run accuracy tests against labeled data
- Display results with confidence scores and metrics
"""

import streamlit as st
import pandas as pd
import asyncio
from typing import List, Dict
import time

# Import our updated detector
from detector import CloudProviderDetector

# Page configuration
st.set_page_config(
    page_title="Cloud Provider Scanner",
    page_icon="☁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown(
    """
<style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .results-container {
        border: 1px solid #e0e0e0;
        border-radius: 10px;
        padding: 1rem;
        margin-top: 1rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }
    .test-results {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-top: 1rem;
    }
</style>
""",
    unsafe_allow_html=True,
)


def main():
    # Header
    st.markdown(
        """
    <div class="main-header">
        <h1>☁️ Cloud Provider Scanner</h1>
        <p>Detect which cloud providers are hosting your domains</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")

        # Mode selection
        mode = st.selectbox(
            "Select Mode",
            ["📊 Analyze Domains", "🧪 Run Accuracy Test"],
            help="Choose between analyzing new domains or testing accuracy against labeled data",
        )

        if mode == "📊 Analyze Domains":
            # File upload
            uploaded_file = st.file_uploader(
                "Upload CSV file with domains",
                type=["csv"],
                help="Upload a CSV file containing domain names",
            )

            # Column name input
            domain_column = st.text_input(
                "Domain Column Name",
                value="domain",
                help="Enter the column name that contains the domain names",
            )

        # Options
        st.subheader("Analysis Options")
        headless_mode = st.checkbox(
            "Headless browser mode",
            value=True,
            help="Run browser in headless mode for faster processing",
        )

        # Sample data option
        if mode == "📊 Analyze Domains" and st.button("📊 Use Sample Data"):
            st.session_state.use_sample_data = True

    # Main content area
    if mode == "📊 Analyze Domains":
        analyze_domains_interface(uploaded_file, domain_column, headless_mode)
    else:
        test_accuracy_interface(headless_mode)


def analyze_domains_interface(uploaded_file, domain_column, headless_mode):
    """Interface for analyzing domains."""
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📤 Upload & Analyze")

        # Check if we should use sample data
        if getattr(st.session_state, "use_sample_data", False):
            # Create sample data
            sample_data = pd.DataFrame(
                {
                    "domain": [
                        "netflix.com",
                        "spotify.com",
                        "stackoverflow.com",
                        "github.com",
                        "dropbox.com",
                        "shopify.com",
                        "reddit.com",
                        "discord.com",
                        "paypal.com",
                        "linkedin.com",
                    ]
                }
            )
            st.success("✅ Sample data loaded!")
            process_domains(sample_data, "domain", headless_mode)

        elif uploaded_file is not None:
            try:
                # Read the uploaded CSV
                df = pd.read_csv(uploaded_file)

                # Display file info
                st.success(f"✅ File uploaded successfully! ({len(df)} rows)")

                # Show preview
                with st.expander("📋 Preview uploaded data"):
                    st.dataframe(df.head(10))

                # Check if domain column exists
                if domain_column not in df.columns:
                    st.error(f"❌ Column '{domain_column}' not found in the CSV file.")
                    st.info(f"Available columns: {', '.join(df.columns)}")
                else:
                    # Start analysis button
                    if st.button("🚀 Start Analysis", type="primary"):
                        process_domains(df, domain_column, headless_mode)

            except Exception as e:
                st.error(f"❌ Error reading CSV file: {str(e)}")
        else:
            # Instructions when no file is uploaded
            st.info("""
            👆 **Upload a CSV file** to get started or use sample data
            
            **CSV Requirements:**
            - Must contain a column with domain names
            - Domains can be with or without http/https prefix
            - Example: `netflix.com`, `https://spotify.com`
            """)

    with col2:
        st.subheader("ℹ️ About")
        st.markdown("""
        This tool analyzes domains to detect which cloud provider hosts them:
        
        **Supported Providers:**
        - 🟧 AWS (Amazon Web Services)
        - 🔵 GCP (Google Cloud Platform)  
        - 🔷 Azure (Microsoft Azure)
        - ⚫ Other providers
        
        **Detection Methods:**
        - 🎯 **IP Range Analysis** (Primary - 60 pts)
        - 🔍 **Backend Endpoint Discovery** (40 pts)
        - 🛡️ **Security Headers** (30 pts)
        - 📦 **Cloud Assets & CDN** (60 pts max)
        
        **Focus:** Backend hosting detection (not CDN layer)
        """)


def test_accuracy_interface(headless_mode):
    """Interface for testing accuracy against labeled data."""
    st.subheader("🧪 Accuracy Testing")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("""
        Test the accuracy of the cloud provider detection against labeled data.
        This uses the `test.csv` file in the data directory.
        """)

        if st.button("🚀 Run Accuracy Test", type="primary"):
            run_accuracy_test(headless_mode)

    with col2:
        st.subheader("📊 Test Info")
        st.markdown("""
        **Metrics Calculated:**
        - 🎯 **Accuracy**: Overall correctness
        - 🔍 **Precision**: Positive prediction accuracy
        - 📈 **Recall**: True positive detection rate
        - 📋 **Classification Report**: Detailed per-class metrics
        """)


def process_domains(df: pd.DataFrame, domain_column: str, headless_mode: bool):
    """Process domains and display results."""
    # Extract URLs
    urls = df[domain_column].dropna().tolist()

    if not urls:
        st.error("❌ No valid URLs found in the specified column.")
        return

    st.subheader(f"🔍 Analyzing {len(urls)} domains...")

    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    results_container = st.empty()

    # Run analysis
    try:
        # Initialize detector
        detector = CloudProviderDetector(headless=headless_mode)

        async def run_analysis():
            results = []
            for i, url in enumerate(urls):
                status_text.text(f"Analyzing {i + 1}/{len(urls)}: {url}")
                progress_bar.progress((i + 1) / len(urls))

                try:
                    result = await detector.analyze_website(url)
                    results.append(result)

                    # Update results display in real-time
                    display_results(results, results_container)

                except Exception as e:
                    st.error(f"Error analyzing {url}: {e}")
                    results.append(
                        {
                            "url": url,
                            "primary_cloud_provider": "Error",
                            "confidence_score": 0,
                            "details": {"error": str(e)},
                        }
                    )

            return results

        # Run the analysis
        results = asyncio.run(run_analysis())

        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()

        # Display final results
        display_final_results(results, df, domain_column)

    except Exception as e:
        st.error(f"❌ Analysis failed: {str(e)}")


def run_accuracy_test(headless_mode: bool):
    """Run accuracy test and display metrics."""
    st.subheader("🧪 Running Accuracy Test...")

    progress_placeholder = st.empty()
    results_placeholder = st.empty()

    try:
        with progress_placeholder.container():
            progress_bar = st.progress(0)
            status_text = st.empty()
            status_text.text("Initializing detector...")

        # Initialize detector
        detector = CloudProviderDetector(headless=headless_mode)

        # Load test data to show progress
        test_df = pd.read_csv("data/test.csv")
        total_domains = len(test_df)

        status_text.text(f"Testing {total_domains} domains...")

        # Custom test run with progress
        results = []
        predictions = []
        true_labels = []

        for i, (_, row) in enumerate(test_df.iterrows()):
            domain = row["domain"]
            true_label = row["cloud_provider"]

            status_text.text(f"Analyzing {i + 1}/{total_domains}: {domain}")
            progress_bar.progress((i + 1) / total_domains)

            # Run analysis
            result = asyncio.run(detector.analyze_website(domain))
            predicted_label = result["primary_cloud_provider"]

            predictions.append(predicted_label)
            true_labels.append(true_label)
            results.append(
                {
                    "domain": domain,
                    "true_label": true_label,
                    "predicted_label": predicted_label,
                    "confidence": result["confidence_score"],
                }
            )

        # Clear progress
        progress_placeholder.empty()

        # Calculate metrics
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            classification_report,
        )

        accuracy = accuracy_score(true_labels, predictions)
        labels = list(set(true_labels + predictions))
        precision = precision_score(
            true_labels, predictions, labels=labels, average="weighted", zero_division=0
        )
        recall = recall_score(
            true_labels, predictions, labels=labels, average="weighted", zero_division=0
        )
        report = classification_report(
            true_labels, predictions, labels=labels, zero_division=0, output_dict=True
        )

        # Display results
        display_test_results(accuracy, precision, recall, report, results)

    except Exception as e:
        st.error(f"❌ Test failed: {str(e)}")
        progress_placeholder.empty()


def display_results(results: List[Dict], container):
    """Display analysis results in real-time."""
    if not results:
        return

    with container.container():
        # Summary metrics
        total = len(results)
        providers = {}
        avg_confidence = 0

        for result in results:
            provider = result.get("primary_cloud_provider", "Unknown")
            providers[provider] = providers.get(provider, 0) + 1
            avg_confidence += result.get("confidence_score", 0)

        avg_confidence = avg_confidence / total if total > 0 else 0

        # Display summary
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Analyzed", total)
        with col2:
            st.metric("Avg Confidence", f"{avg_confidence:.1f}%")
        with col3:
            most_common = (
                max(providers.items(), key=lambda x: x[1]) if providers else ("None", 0)
            )
            st.metric("Most Common", most_common[0])
        with col4:
            st.metric("Providers Found", len(providers))

        # Provider distribution
        if providers:
            st.subheader("Provider Distribution")
            provider_df = pd.DataFrame(
                list(providers.items()), columns=["Provider", "Count"]
            )
            st.bar_chart(provider_df.set_index("Provider"))


def display_final_results(
    results: List[Dict], original_df: pd.DataFrame, domain_column: str
):
    """Display final comprehensive results."""
    st.subheader("📊 Analysis Complete!")

    # Create results DataFrame
    results_data = []
    for result in results:
        results_data.append(
            {
                "Domain": result["url"],
                "Cloud Provider": result["primary_cloud_provider"],
                "Confidence": f"{result['confidence_score']:.1f}%",
                "Main IPs": ", ".join(
                    result.get("details", {}).get("main_domain_ips", [])
                ),
                "Backend IPs": ", ".join(
                    result.get("details", {}).get("backend_ips", [])
                ),
            }
        )

    results_df = pd.DataFrame(results_data)

    # Display summary metrics
    total = len(results)
    providers = {}
    high_confidence = 0

    for result in results:
        provider = result["primary_cloud_provider"]
        providers[provider] = providers.get(provider, 0) + 1
        if result["confidence_score"] >= 70:
            high_confidence += 1

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Analyzed", total)
    with col2:
        st.metric(
            "High Confidence",
            f"{high_confidence} ({high_confidence / total * 100:.1f}%)",
        )
    with col3:
        most_common = (
            max(providers.items(), key=lambda x: x[1]) if providers else ("None", 0)
        )
        st.metric("Most Common Provider", most_common[0])
    with col4:
        st.metric("Unique Providers", len(providers))

    # Provider distribution chart
    if providers:
        st.subheader("Provider Distribution")
        provider_df = pd.DataFrame(
            list(providers.items()), columns=["Provider", "Count"]
        )
        st.bar_chart(provider_df.set_index("Provider"))

    # Detailed results table
    st.subheader("Detailed Results")
    st.dataframe(results_df, use_container_width=True)

    # Download button
    csv = results_df.to_csv(index=False)
    st.download_button(
        label="📥 Download Results as CSV",
        data=csv,
        file_name=f"cloud_provider_analysis_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )


def display_test_results(
    accuracy: float, precision: float, recall: float, report: dict, results: List[Dict]
):
    """Display test results with metrics."""
    st.subheader("🎯 Test Results")

    # Main metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Accuracy", f"{accuracy:.3f}", f"{accuracy * 100:.1f}%")
    with col2:
        st.metric("Precision", f"{precision:.3f}", f"{precision * 100:.1f}%")
    with col3:
        st.metric("Recall", f"{recall:.3f}", f"{recall * 100:.1f}%")

    # Detailed classification report
    st.subheader("📊 Per-Class Metrics")

    class_metrics = []
    for label, metrics in report.items():
        if label not in ["accuracy", "macro avg", "weighted avg"] and isinstance(
            metrics, dict
        ):
            class_metrics.append(
                {
                    "Provider": label,
                    "Precision": f"{metrics['precision']:.3f}",
                    "Recall": f"{metrics['recall']:.3f}",
                    "F1-Score": f"{metrics['f1-score']:.3f}",
                    "Support": int(metrics["support"]),
                }
            )

    if class_metrics:
        metrics_df = pd.DataFrame(class_metrics)
        st.dataframe(metrics_df, use_container_width=True)

    # Confusion matrix visualization
    st.subheader("🔍 Detailed Results")

    # Create results DataFrame
    detailed_results = pd.DataFrame(results)
    detailed_results["Correct"] = (
        detailed_results["true_label"] == detailed_results["predicted_label"]
    )

    st.dataframe(detailed_results, use_container_width=True)

    # Download test results
    csv = detailed_results.to_csv(index=False)
    st.download_button(
        label="📥 Download Test Results as CSV",
        data=csv,
        file_name=f"accuracy_test_results_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
