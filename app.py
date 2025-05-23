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
import time
from typing import List, Dict

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

        # Check for browser availability and show appropriate message
        try:
            from detector import BROWSERS_AVAILABLE

            if BROWSERS_AVAILABLE:
                st.success("""
                🚀 **Full Analysis Mode Active**
                
                All browser features available for comprehensive analysis!
                
                ✅ **IP Range Analysis** (Primary detection)
                🔍 **Backend Endpoint Discovery** 
                🛡️ **Security Headers Analysis**
                📦 **Cloud Assets & CDN Detection**
                ⚡ **Maximum accuracy and detail**
                """)
            else:
                st.info("""
                🔍 **IP-Only Analysis Mode**
                
                Using IP range analysis - the most reliable detection method!
                
                ✅ **Still detects:** AWS, GCP, Azure
                ⚡ **Faster:** No browser overhead
                🎯 **Accurate:** Based on official IP ranges
                📊 **Reliable:** Core detection functionality
                """)
        except:
            pass

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
          Based on official cloud provider IP ranges
        - 🔍 **Backend Endpoint Discovery** (40 pts)
          When browsers available
        - 🛡️ **Security Headers** (30 pts)
        - 📦 **Cloud Assets & CDN** (60 pts max)
          When browsers available
        
        **Robust Design:**
        - ✅ Works with or without browser dependencies
        - 🎯 IP analysis alone provides reliable detection
        - ⚡ Faster performance in IP-only mode
        - 🌐 Focus on backend hosting (not CDN layer)
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
                status_text.text(f"🔍 Analyzing {i + 1}/{len(urls)}: {url}")
                progress_bar.progress((i + 1) / len(urls))

                try:
                    result = await detector.analyze_website(url)
                    results.append(result)

                    # Print result to console for real-time feedback
                    provider = result["primary_cloud_provider"]
                    confidence = result["confidence_score"]
                    print(f"✅ {url} → {provider} ({confidence:.1f}%)")

                    # Update status with result
                    status_text.text(
                        f"✅ {i + 1}/{len(urls)} complete: {url} → {provider} ({confidence:.1f}%)"
                    )

                    # Update results display in real-time
                    display_results(results, results_container)

                except Exception as e:
                    error_msg = f"Error analyzing {url}: {e}"
                    st.error(error_msg)
                    print(f"❌ {url} → Error: {e}")
                    status_text.text(f"❌ {i + 1}/{len(urls)} failed: {url}")
                    results.append(
                        {
                            "url": url,
                            "primary_cloud_provider": "Error",
                            "confidence_score": 0,
                            "details": {"error": str(e)},
                        }
                    )
                    # Update display even with errors
                    display_results(results, results_container)

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

    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()

    # Real-time test results display
    st.subheader("📊 Live Test Results")

    # Create placeholders for live updates
    current_result_placeholder = st.empty()
    test_results_table = st.empty()
    test_summary_metrics = st.empty()

    try:
        # Initialize detector
        detector = CloudProviderDetector(headless=headless_mode)

        # Load test data to show progress
        test_df = pd.read_csv("data/test.csv")
        total_domains = len(test_df)

        status_text.text(f"🧪 Testing {total_domains} domains...")

        # Custom test run with progress and live display
        results = []
        predictions = []
        true_labels = []

        for i, (_, row) in enumerate(test_df.iterrows()):
            domain = row["domain"]
            true_label = row["cloud_provider"]

            status_text.text(f"🔍 Testing {i + 1}/{total_domains}: {domain}")
            progress_bar.progress((i + 1) / total_domains)

            # Show current domain being tested
            current_result_placeholder.info(f"🔄 **Currently testing:** `{domain}`")

            try:
                # Run analysis
                result = asyncio.run(detector.analyze_website(domain))
                predicted_label = result["primary_cloud_provider"]
                confidence = result["confidence_score"]
                primary_reason = result.get("primary_reason", "No reason provided")

                predictions.append(predicted_label)
                true_labels.append(true_label)

                # Determine if prediction is correct
                is_correct = predicted_label == true_label

                test_result = {
                    "domain": domain,
                    "true_label": true_label,
                    "predicted_label": predicted_label,
                    "confidence": confidence,
                    "primary_reason": primary_reason,
                    "correct": is_correct,
                }
                results.append(test_result)

                # Print result to console for real-time feedback
                correct_emoji = "✅" if is_correct else "❌"
                print(
                    f"{correct_emoji} {domain} → True: {true_label}, Predicted: {predicted_label} ({confidence:.1f}%) {'CORRECT' if is_correct else 'WRONG'}"
                )
                print(f"   Reason: {primary_reason}")

                # Show immediate result with prominent display
                if is_correct:
                    current_result_placeholder.success(
                        f"✅ **CORRECT!** `{domain}` → True: {true_label}, Predicted: {predicted_label} ({confidence:.1f}%)\n\n💡 **Reason:** {primary_reason}"
                    )
                else:
                    current_result_placeholder.error(
                        f"❌ **WRONG!** `{domain}` → True: {true_label}, Predicted: {predicted_label} ({confidence:.1f}%)\n\n💡 **Reason:** {primary_reason}"
                    )

                # Update status with result
                accuracy_so_far = (
                    sum(1 for r in results if r.get("correct", False)) / len(results)
                ) * 100
                status_text.text(
                    f"{correct_emoji} {i + 1}/{total_domains}: {domain} → {predicted_label} ({'✅ Correct' if is_correct else '❌ Wrong'}) | Running Accuracy: {accuracy_so_far:.1f}%"
                )

                # Update live test results display
                display_test_results_live(
                    results, test_results_table, test_summary_metrics
                )

                # Small delay to make the result visible
                time.sleep(0.5)

            except Exception as e:
                error_msg = f"Error testing {domain}: {e}"
                st.error(error_msg)
                print(f"❌ {domain} → Error: {e}")
                current_result_placeholder.error(
                    f"❌ **ERROR!** `{domain}` → {error_msg}"
                )
                status_text.text(f"❌ {i + 1}/{total_domains} failed: {domain}")

                # Add error result
                test_result = {
                    "domain": domain,
                    "true_label": true_label,
                    "predicted_label": "Error",
                    "confidence": 0,
                    "primary_reason": f"Analysis failed: {error_msg}",
                    "correct": False,
                }
                results.append(test_result)
                predictions.append("Error")
                true_labels.append(true_label)

                # Update display even with errors
                display_test_results_live(
                    results, test_results_table, test_summary_metrics
                )

        # Clear progress indicators
        progress_bar.empty()
        current_result_placeholder.success("🎉 **All tests completed!**")
        status_text.success("✅ Accuracy Test Complete!")

        # Calculate final metrics
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

        # Display final test results
        display_final_test_results(accuracy, precision, recall, report, results)

    except Exception as e:
        st.error(f"❌ Test failed: {str(e)}")
        progress_bar.empty()
        status_text.empty()
        current_result_placeholder.empty()


def display_results(results: List[Dict], container):
    """Display analysis results in real-time."""
    if not results:
        return

    with container.container():
        # Create results dataframe for display
        display_data = []
        providers = {}
        total_confidence = 0

        for result in results:
            provider = result.get("primary_cloud_provider", "Unknown")
            confidence = result.get("confidence_score", 0)
            primary_reason = result.get("primary_reason", "No reason provided")

            providers[provider] = providers.get(provider, 0) + 1
            total_confidence += confidence

            # Add emoji indicators
            if provider == "AWS":
                provider_display = "🟧 AWS"
            elif provider == "GCP":
                provider_display = "🔵 GCP"
            elif provider == "Azure":
                provider_display = "🔷 Azure"
            elif provider == "Error":
                provider_display = "❌ Error"
            else:
                provider_display = "⚫ Other"

            # Confidence indicator
            if confidence >= 70:
                confidence_display = f"🟢 {confidence:.1f}%"
            elif confidence >= 40:
                confidence_display = f"🟡 {confidence:.1f}%"
            else:
                confidence_display = f"🔴 {confidence:.1f}%"

            # Truncate reason if too long for table display
            reason_display = primary_reason
            if len(reason_display) > 60:
                reason_display = reason_display[:57] + "..."

            display_data.append(
                {
                    "Domain": result["url"],
                    "Provider": provider_display,
                    "Confidence": confidence_display,
                    "Primary Reason": reason_display,
                    "Status": "✅ Success" if provider != "Error" else "❌ Failed",
                }
            )

        # Display current results table
        st.subheader(f"📊 Results ({len(results)} analyzed)")
        st.dataframe(
            pd.DataFrame(display_data), use_container_width=True, hide_index=True
        )

        # Summary metrics
        total = len(results)
        avg_confidence = total_confidence / total if total > 0 else 0

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Analyzed", total)
        with col2:
            st.metric("Avg Confidence", f"{avg_confidence:.1f}%")
        with col3:
            high_confidence = sum(
                1 for r in results if r.get("confidence_score", 0) >= 70
            )
            st.metric("High Confidence", f"{high_confidence}")
        with col4:
            st.metric("Providers Found", len(providers))

        # Provider distribution
        if providers:
            st.subheader("🔍 Live Provider Distribution")
            provider_df = pd.DataFrame(
                list(providers.items()), columns=["Provider", "Count"]
            )
            st.bar_chart(provider_df.set_index("Provider"))


def display_final_results(
    results: List[Dict], original_df: pd.DataFrame, domain_column: str
):
    """Display final comprehensive results with download options."""
    st.subheader("🎉 Analysis Complete!")

    # Create comprehensive results DataFrame
    final_data = []
    for result in results:
        # Get evidence details
        evidence_summary = "No evidence"
        if result.get("evidence"):
            evidence_methods = [e["method"] for e in result["evidence"]]
            evidence_summary = ", ".join(set(evidence_methods))

        final_data.append(
            {
                "Domain": result["url"],
                "Cloud Provider": result["primary_cloud_provider"],
                "Confidence Score": f"{result['confidence_score']:.1f}%",
                "Primary Reason": result.get("primary_reason", "No reason provided"),
                "Evidence Methods": evidence_summary,
                "Main IPs": ", ".join(
                    result.get("details", {}).get("main_domain_ips", [])
                ),
                "Backend IPs": ", ".join(
                    result.get("details", {}).get("backend_ips", [])
                ),
                "Error": result.get("details", {}).get("error", ""),
            }
        )

    results_df = pd.DataFrame(final_data)

    # Summary statistics
    total = len(results)
    providers = {}
    high_confidence = 0
    errors = 0

    for result in results:
        provider = result["primary_cloud_provider"]
        providers[provider] = providers.get(provider, 0) + 1
        if result["confidence_score"] >= 70:
            high_confidence += 1
        if provider == "Error":
            errors += 1

    # Display summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Domains", total)
    with col2:
        success_rate = ((total - errors) / total * 100) if total > 0 else 0
        st.metric("Success Rate", f"{success_rate:.1f}%")
    with col3:
        confidence_rate = (high_confidence / total * 100) if total > 0 else 0
        st.metric("High Confidence", f"{confidence_rate:.1f}%")
    with col4:
        st.metric(
            "Unique Providers", len([p for p in providers.keys() if p != "Error"])
        )

    # Provider distribution chart
    if providers:
        st.subheader("☁️ Final Provider Distribution")
        provider_df = pd.DataFrame(
            list(providers.items()), columns=["Provider", "Count"]
        )
        st.bar_chart(provider_df.set_index("Provider"))

    # Detailed results table
    st.subheader("📋 Complete Results with Reasoning")

    # Add expandable details for each domain
    for i, result in enumerate(results):
        with st.expander(
            f"🔍 {result['url']} → {result['primary_cloud_provider']} ({result['confidence_score']:.1f}%)"
        ):
            col1, col2 = st.columns([2, 1])

            with col1:
                st.write(
                    f"**Primary Reason:** {result.get('primary_reason', 'No reason provided')}"
                )

                # Show evidence details
                if result.get("evidence"):
                    st.write("**Evidence Found:**")
                    for evidence in result["evidence"]:
                        st.write(
                            f"• **{evidence['method']}**: {evidence['evidence']} (+{evidence['confidence_points']} pts)"
                        )

                # Show all provider scores
                if result.get("details", {}).get("provider_scores"):
                    st.write("**All Provider Scores:**")
                    scores = result["details"]["provider_scores"]
                    for provider, score in scores.items():
                        if score > 0:
                            st.write(f"• {provider}: {score:.1f} points")

            with col2:
                # Summary info
                st.metric("Confidence", f"{result['confidence_score']:.1f}%")
                if result.get("details", {}).get("main_domain_ips"):
                    st.write("**Main IPs:**")
                    for ip in result["details"]["main_domain_ips"][:3]:  # Show first 3
                        st.write(f"• {ip}")

    # Original table for CSV download
    st.dataframe(results_df, use_container_width=True, hide_index=True)

    # Download section
    st.subheader("💾 Download Results")

    # Create downloadable CSVs
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    # Detailed CSV
    detailed_csv = results_df.to_csv(index=False)
    detailed_filename = f"cloud_provider_detailed_{timestamp}.csv"

    # Summary CSV (simplified)
    summary_data = []
    for result in results:
        summary_data.append(
            {
                "Domain": result["url"],
                "Cloud Provider": result["primary_cloud_provider"],
                "Confidence": f"{result['confidence_score']:.1f}%",
                "Primary Reason": result.get("primary_reason", "No reason provided"),
                "Main IP": result.get("details", {}).get("main_domain_ips", [""])[0]
                if result.get("details", {}).get("main_domain_ips")
                else "",
            }
        )

    summary_df = pd.DataFrame(summary_data)
    summary_csv = summary_df.to_csv(index=False)
    summary_filename = f"cloud_provider_summary_{timestamp}.csv"

    # Download buttons
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            label="📥 Download Detailed Results",
            data=detailed_csv,
            file_name=detailed_filename,
            mime="text/csv",
            help="Complete analysis data with IPs, scores, reasoning, and errors",
            type="primary",
        )

    with col2:
        st.download_button(
            label="📄 Download Summary",
            data=summary_csv,
            file_name=summary_filename,
            mime="text/csv",
            help="Simplified domain → provider mapping with reasoning",
        )

    # Analysis summary info
    st.info(f"""
    📊 **Analysis Complete!**
    
    ✅ **{total} domains analyzed**
    🎯 **{success_rate:.1f}% success rate**
    📈 **{high_confidence} high-confidence detections** (≥70%)
    ⚡ **{len([p for p in providers.keys() if p != "Error"])} unique providers found**
    🔍 **Detailed reasoning provided for each detection**
    
    💡 Use the download buttons above to save your results!
    """)

    # Print summary to console/logs
    print("\n🎉 ANALYSIS COMPLETE!")
    print(f"📊 Total domains analyzed: {total}")
    print(f"✅ Success rate: {success_rate:.1f}%")
    print(f"🎯 High confidence detections: {high_confidence}")
    print("☁️ Provider breakdown:")
    for provider, count in providers.items():
        if provider != "Error":
            percentage = (count / total) * 100
            print(f"   {provider}: {count} domains ({percentage:.1f}%)")
    print(f"📁 Results available for download: {detailed_filename}")

    return results_df


def display_test_results_live(
    results: List[Dict], test_results_table, test_summary_metrics
):
    """Display live test results and summary metrics."""
    if not results:
        return

    # Create results dataframe for display
    display_data = []
    providers = {}
    total_confidence = 0

    for result in results:
        provider = result.get("predicted_label", "Unknown")
        confidence = result.get("confidence", 0)
        primary_reason = result.get("primary_reason", "No reason provided")

        providers[provider] = providers.get(provider, 0) + 1
        total_confidence += confidence

        # Add emoji indicators for predicted provider
        if provider == "AWS":
            provider_display = "🟧 AWS"
        elif provider == "GCP":
            provider_display = "🔵 GCP"
        elif provider == "Azure":
            provider_display = "🔷 Azure"
        elif provider == "Error":
            provider_display = "❌ Error"
        else:
            provider_display = "⚫ Other"

        # True label display
        true_label = result.get("true_label", "Unknown")
        if true_label == "AWS":
            true_display = "🟧 AWS"
        elif true_label == "GCP":
            true_display = "🔵 GCP"
        elif true_label == "Azure":
            true_display = "🔷 Azure"
        else:
            true_display = "⚫ Other"

        # Confidence indicator
        if confidence >= 70:
            confidence_display = f"🟢 {confidence:.1f}%"
        elif confidence >= 40:
            confidence_display = f"🟡 {confidence:.1f}%"
        else:
            confidence_display = f"🔴 {confidence:.1f}%"

        # Correctness indicator with background color styling
        is_correct = result.get("correct", False)
        if is_correct:
            correctness_display = "🎯 CORRECT"
            domain_display = f"✅ {result['domain']}"
        else:
            correctness_display = "💥 WRONG"
            domain_display = f"❌ {result['domain']}"

        # Truncate reason for table display
        reason_display = primary_reason
        if len(reason_display) > 45:
            reason_display = reason_display[:42] + "..."

        display_data.append(
            {
                "Domain": domain_display,
                "Expected": true_display,
                "Predicted": provider_display,
                "Confidence": confidence_display,
                "Primary Reason": reason_display,
                "Accuracy": correctness_display,
            }
        )

    # Display current results table with enhanced formatting
    results_df = pd.DataFrame(display_data)

    # Sort by most recent (last row first) for better visibility
    results_df = results_df.iloc[::-1].reset_index(drop=True)

    with test_results_table.container():
        st.write(f"**📋 Test Results ({len(results)} completed)**")
        st.dataframe(
            results_df,
            use_container_width=True,
            hide_index=True,
            height=min(400, len(results) * 35 + 50),  # Dynamic height
        )

    # Summary metrics with enhanced display
    total = len(results)
    avg_confidence = total_confidence / total if total > 0 else 0
    correct_count = sum(1 for r in results if r.get("correct", False))
    accuracy_so_far = (correct_count / total * 100) if total > 0 else 0

    with test_summary_metrics.container():
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🧪 Tested", total)
        with col2:
            # Color code the accuracy metric
            accuracy_delta = None
            if total > 1:
                prev_accuracy = (
                    (correct_count - (1 if results[-1].get("correct", False) else 0))
                    / (total - 1)
                ) * 100
                accuracy_delta = f"{accuracy_so_far - prev_accuracy:+.1f}%"
            st.metric("🎯 Accuracy", f"{accuracy_so_far:.1f}%", accuracy_delta)
        with col3:
            st.metric("📊 Avg Confidence", f"{avg_confidence:.1f}%")
        with col4:
            st.metric("✅ Correct", f"{correct_count}/{total}")

        # Progress indicator
        st.progress(accuracy_so_far / 100 if accuracy_so_far <= 100 else 1.0)

        # Quick stats
        wrong_count = total - correct_count
        if wrong_count > 0:
            st.write(
                f"📈 **Current Stats:** {correct_count} correct, {wrong_count} wrong"
            )
        else:
            st.write(
                f"🎉 **Perfect so far!** {correct_count} out of {correct_count} correct"
            )

    # Provider distribution chart for predictions
    if providers and len(providers) > 1:
        with test_summary_metrics.container():
            st.write("🔍 **Live Prediction Distribution:**")
            provider_df = pd.DataFrame(
                list(providers.items()), columns=["Provider", "Count"]
            )
            st.bar_chart(provider_df.set_index("Provider"), height=200)


def display_final_test_results(
    accuracy: float, precision: float, recall: float, report: dict, results: List[Dict]
):
    """Display final test results and metrics."""
    st.subheader("🎯 Final Test Results")

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

    # Test summary statistics
    total = len(results)
    correct_count = sum(1 for r in results if r.get("correct", False))
    error_count = sum(1 for r in results if r.get("predicted_label") == "Error")
    success_rate = ((total - error_count) / total * 100) if total > 0 else 0

    # Provider breakdown
    providers = {}
    for result in results:
        provider = result.get("predicted_label", "Unknown")
        providers[provider] = providers.get(provider, 0) + 1

    # Display summary metrics
    st.subheader("📈 Test Summary")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Tested", total)
    with col2:
        st.metric("Test Success Rate", f"{success_rate:.1f}%")
    with col3:
        st.metric("Correctly Predicted", f"{correct_count}/{total}")
    with col4:
        st.metric("Error Count", error_count)

    # Confusion matrix visualization
    st.subheader("🔍 Detailed Test Results")

    # Create results DataFrame with better formatting
    detailed_results = []
    for result in results:
        detailed_results.append(
            {
                "Domain": result["domain"],
                "True Label": result["true_label"],
                "Predicted Label": result["predicted_label"],
                "Confidence": f"{result['confidence']:.1f}%",
                "Correct": "✅ Yes" if result["correct"] else "❌ No",
            }
        )

    detailed_df = pd.DataFrame(detailed_results)
    st.dataframe(detailed_df, use_container_width=True)

    # Download test results
    csv = pd.DataFrame(results).to_csv(index=False)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    st.download_button(
        label="📥 Download Test Results as CSV",
        data=csv,
        file_name=f"accuracy_test_results_{timestamp}.csv",
        mime="text/csv",
        type="primary",
    )

    # Final summary info
    st.info(f"""
    🧪 **Accuracy Test Complete!**
    
    ✅ **{total} domains tested**
    🎯 **{accuracy * 100:.1f}% overall accuracy**
    📈 **{correct_count} correct predictions**
    ⚡ **{len([p for p in providers.keys() if p != "Error"])} unique providers detected**
    
    💡 Download the results above for further analysis!
    """)

    # Print summary to console/logs
    print("\n🧪 ACCURACY TEST COMPLETE!")
    print(f"📊 Total domains tested: {total}")
    print(f"🎯 Overall accuracy: {accuracy * 100:.1f}%")
    print(f"✅ Correct predictions: {correct_count}")
    print(f"❌ Incorrect predictions: {total - correct_count}")
    print("☁️ Provider prediction breakdown:")
    for provider, count in providers.items():
        if provider != "Error":
            percentage = (count / total) * 100
            print(f"   {provider}: {count} predictions ({percentage:.1f}%)")
    if error_count > 0:
        print(f"⚠️  Errors encountered: {error_count}")
    print(
        f"📁 Test results available for download: accuracy_test_results_{timestamp}.csv"
    )


if __name__ == "__main__":
    main()
