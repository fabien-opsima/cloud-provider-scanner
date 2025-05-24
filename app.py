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
    .scrollable-test-results {
        height: 500px;
        overflow-y: auto;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 10px;
        background-color: #fafafa;
        scroll-behavior: smooth;
    }
    .scrollable-test-results::-webkit-scrollbar {
        width: 8px;
    }
    .scrollable-test-results::-webkit-scrollbar-track {
        background: #f1f1f1;
        border-radius: 4px;
    }
    .scrollable-test-results::-webkit-scrollbar-thumb {
        background: #888;
        border-radius: 4px;
    }
    .scrollable-test-results::-webkit-scrollbar-thumb:hover {
        background: #555;
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

        # Auto-load sample data when the app starts (default behavior)
        auto_load_sample = uploaded_file is None and not hasattr(
            st.session_state, "sample_data_loaded"
        )

        # Check if we should use sample data (either auto-load or user clicked button)
        if getattr(st.session_state, "use_sample_data", False) or auto_load_sample:
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
            if auto_load_sample:
                st.info(
                    "✨ Sample test data loaded automatically! You can upload your own CSV file above to analyze different domains."
                )
                st.session_state.sample_data_loaded = True
            else:
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
        This tool analyzes domains to detect which cloud provider hosts their **backend API infrastructure** by exploring app subdomains and XHR calls:
        
        **Supported Providers:**
        - 🟧 AWS (Amazon Web Services)
        - 🔵 GCP (Google Cloud Platform)  
        - 🔷 Azure (Microsoft Azure)
        - ⚫ Other providers
        
        **XHR-Focused Detection Methods:**
        - 🎯 **XHR API Endpoint IPs** (80 pts) 
          IP analysis of XHR/fetch requests from app subdomains
        - ☁️ **Direct Cloud XHR Calls** (60 pts)
          XHR requests directly to *.amazonaws.com, *.googleapis.com etc.
          (Excludes Google Maps API - not backend hosting)
        - 🛡️ **XHR API Headers** (40 pts)
          Headers from actual API endpoints making XHR calls
        
        **App Subdomain Exploration:**
        - 🔍 Automatically discovers app.domain.com, dashboard.domain.com etc.
        - 📱 Navigates to Single Page Applications (SPAs)
        - 🔄 Interacts with pages to trigger API calls
        - 🎪 Focuses on actual backend infrastructure, not website hosting
        
        **Enhanced Reporting:**
        - 📍 Shows exact endpoint URLs and IP addresses
        - 📊 Displays specific IP ranges matched
        - 🏷️ Provides detailed network information
        - 🔍 Transparent evidence for each detection
        
        **Why XHR-Only?**
        - ✅ Ignores website hosting platforms completely
        - 🎯 Only analyzes actual backend API calls
        - 📊 More accurate for business intelligence
        - 🚀 Focuses on app subdomains where real applications live
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

        # Shuffle the test data to ensure random order each time
        test_df = test_df.sample(frac=1).reset_index(drop=True)
        print(f"🔀 Shuffled {len(test_df)} test domains for random order")

        total_domains = len(test_df)

        status_text.text(f"🧪 Testing {total_domains} domains...")

        # Custom test run with progress and live display
        results = []
        predictions = []  # Only classified predictions (excluding "Insufficient Data")
        true_labels = []  # Corresponding true labels for classified predictions
        all_results = []  # All results including "Insufficient Data"
        insufficient_data_count = 0

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

                # Create test result object
                test_result = {
                    "domain": domain,
                    "true_label": true_label,
                    "predicted_label": predicted_label,
                    "confidence": confidence,
                    "primary_reason": primary_reason,
                    "correct": predicted_label == true_label,
                    "is_insufficient_data": predicted_label == "Insufficient Data",
                }
                results.append(test_result)
                all_results.append(test_result)

                # Handle "Insufficient Data" separately
                if predicted_label == "Insufficient Data":
                    insufficient_data_count += 1
                    # Print result to console for real-time feedback
                    print(
                        f"🔍 {domain} → True: {true_label}, Predicted: {predicted_label} (excluded from accuracy)"
                    )
                    print(f"   Reason: {primary_reason}")

                    # Show immediate result with prominent display
                    current_result_placeholder.info(
                        f"🔍 **INSUFFICIENT DATA** `{domain}` → Expected: {true_label}, Result: Insufficient Data\n\n💡 **Reason:** {primary_reason}"
                    )

                    # Update status
                    classified_so_far = len(predictions)
                    accuracy_so_far = (
                        (
                            sum(
                                1
                                for r in results
                                if r.get("correct", False)
                                and not r.get("is_insufficient_data", False)
                            )
                            / classified_so_far
                            * 100
                        )
                        if classified_so_far > 0
                        else 0
                    )

                    status_text.text(
                        f"🔍 {i + 1}/{total_domains}: {domain} → Insufficient Data (excluded) | Accuracy of classified: {accuracy_so_far:.1f}%"
                    )

                else:
                    # Add to classification metrics
                    predictions.append(predicted_label)
                    true_labels.append(true_label)

                    # Determine if prediction is correct
                    is_correct = predicted_label == true_label

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
                        (
                            sum(
                                1
                                for r in results
                                if r.get("correct", False)
                                and not r.get("is_insufficient_data", False)
                            )
                            / len(predictions)
                            * 100
                        )
                        if len(predictions) > 0
                        else 0
                    )

                    status_text.text(
                        f"{correct_emoji} {i + 1}/{total_domains}: {domain} → {predicted_label} ({'✅ Correct' if is_correct else '❌ Wrong'}) | Accuracy: {accuracy_so_far:.1f}%"
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

        # Calculate final metrics excluding "Insufficient Data"
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            classification_report,
        )

        # Calculate comprehensive metrics
        total_domains = len(test_df)
        classified_domains = len(predictions)
        classification_rate = (
            (classified_domains / total_domains) * 100 if total_domains > 0 else 0
        )

        if classified_domains > 0:
            accuracy = accuracy_score(true_labels, predictions)

            # Get unique labels for precision/recall calculation (excluding "Insufficient Data")
            labels = list(set(true_labels + predictions))
            labels = [label for label in labels if label != "Insufficient Data"]

            precision = precision_score(
                true_labels,
                predictions,
                labels=labels,
                average="weighted",
                zero_division=0,
            )
            recall = recall_score(
                true_labels,
                predictions,
                labels=labels,
                average="weighted",
                zero_division=0,
            )
            report = classification_report(
                true_labels,
                predictions,
                labels=labels,
                zero_division=0,
                output_dict=True,
            )
        else:
            # No domains were classified
            accuracy = 0.0
            precision = 0.0
            recall = 0.0
            report = {}

        # Enhanced metrics object
        enhanced_metrics = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "classification_report": report,
            "total_domains": total_domains,
            "classified_domains": classified_domains,
            "insufficient_data_count": insufficient_data_count,
            "classification_rate": classification_rate,
        }

        # Display final test results with enhanced metrics
        display_final_test_results(enhanced_metrics, results)

    except Exception as e:
        st.error(f"❌ Test failed: {str(e)}")
        progress_bar.empty()
        status_text.empty()
        current_result_placeholder.empty()


def display_results(results: List[Dict], container):
    """Display analysis results using individual cards for better readability."""
    if not results:
        return

    with container.container():
        st.subheader(f"📊 Results ({len(results)} analyzed)")

        # Summary metrics first
        total = len(results)
        providers = {}
        high_confidence = 0
        total_confidence = 0

        for result in results:
            provider = result.get("primary_cloud_provider", "Unknown")
            confidence = result.get("confidence_score", 0)
            providers[provider] = providers.get(provider, 0) + 1
            total_confidence += confidence
            if confidence >= 70:
                high_confidence += 1

        avg_confidence = total_confidence / total if total > 0 else 0

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Analyzed", total)
        with col2:
            st.metric("Avg Confidence", f"{avg_confidence:.1f}%")
        with col3:
            st.metric("High Confidence", f"{high_confidence}")
        with col4:
            st.metric(
                "Providers Found", len([p for p in providers.keys() if p != "Error"])
            )

        # Individual result cards for better readability
        st.subheader("🔍 Detailed Results")

        for i, result in enumerate(results):
            provider = result.get("primary_cloud_provider", "Unknown")
            confidence = result.get("confidence_score", 0)
            primary_reason = result.get("primary_reason", "No reason provided")

            # Color coding based on correctness and confidence
            if provider == "Insufficient Data":
                card_color = "#e8f4fd"  # Light blue for insufficient data
                status_emoji = "🔍"
                status_text = "INSUFFICIENT DATA"
                border_color = "#17a2b8"
            elif (
                result.get("correct", False) and confidence >= 40
            ):  # Correct with reasonable confidence
                card_color = "#d4f6d4"  # Light green
                status_emoji = "✅"
                status_text = "CORRECT"
                border_color = "#28a745"
            elif (
                result.get("correct", False)
                and result["predicted_label"] == "Other"
                and confidence < 40
            ):  # "Other" match but low confidence
                card_color = "#f0f0f0"  # Light grey - not enough info to be confident about "Other"
                status_emoji = "⚫"
                status_text = "LOW CONFIDENCE"
                border_color = "#6c757d"
            elif confidence < 30:  # Low confidence for any result
                card_color = "#f0f0f0"  # Light grey
                status_emoji = "⚫"
                status_text = "LOW CONFIDENCE"
                border_color = "#6c757d"
            else:
                card_color = "#f6d4d4"  # Light red for actual wrong predictions with decent confidence
                status_emoji = "❌"
                status_text = "WRONG"
                border_color = "#dc3545"

            # Provider emojis
            def get_provider_emoji(provider):
                if provider == "AWS":
                    return "🟧"
                elif provider == "GCP":
                    return "🔵"
                elif provider == "Azure":
                    return "🔷"
                elif provider == "Insufficient Data":
                    return "🔍"
                else:
                    return "⚫"

            true_emoji = get_provider_emoji(result["true_label"])
            pred_emoji = get_provider_emoji(result["predicted_label"])

            # Create individual result card
            st.markdown(
                f"""
            <div style="
                background-color: {card_color};
                padding: 20px;
                border-radius: 10px;
                border-left: 5px solid {border_color};
                margin: 10px 0;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            ">
                <h4 style="margin: 0 0 15px 0; color: #333;">
                    {status_emoji} <strong>{result["url"]}</strong> - {status_text}
                </h4>
                <div style="background-color: white; padding: 15px; border-radius: 5px; margin: 10px 0;">
                    <strong>🎯 Primary Reason:</strong><br>
                    <span style="font-family: monospace; font-size: 14px; line-height: 1.5;">
                        {primary_reason}
                    </span>
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

            # Additional details in expander
            with st.expander(f"🔍 Full Details for {result['url']}", expanded=False):
                col1, col2 = st.columns([2, 1])

                with col1:
                    # Show backend data
                    backend_data = result.get("details", {}).get("backend_data", {})

                    if backend_data.get("xhr_api_calls"):
                        st.write("**🎯 XHR API Calls Found:**")
                        for api in backend_data["xhr_api_calls"]:
                            st.code(api, language="text")

                    if backend_data.get("cloud_provider_domains"):
                        st.write("**☁️ Direct Cloud Provider Calls:**")
                        for domain_info in backend_data["cloud_provider_domains"]:
                            if isinstance(domain_info, tuple):
                                if len(domain_info) == 3:
                                    domain, provider_name, service_type = domain_info
                                    st.success(
                                        f"🔗 **{domain}** → {provider_name} {service_type}"
                                    )
                                else:
                                    domain, provider_name = domain_info
                                    st.success(f"🔗 **{domain}** → {provider_name}")
                            else:
                                st.success(f"🔗 **{domain_info}**")

                    if backend_data.get("app_subdomains"):
                        st.write("**📱 App Subdomains Explored:**")
                        for subdomain in backend_data["app_subdomains"]:
                            st.info(f"📍 {subdomain}")

                    # Show evidence with enhanced details
                    evidence = result.get("evidence", [])
                    if evidence:
                        st.write("**🔍 Technical Evidence:**")
                        for ev in evidence:
                            method = ev["method"]
                            evidence_text = ev["evidence"]
                            points = ev["confidence_points"]

                            st.write(f"**{method}** (+{points} pts)")
                            st.write(f"📋 {evidence_text}")

                            # Show detailed technical info if available
                            if ev.get("details"):
                                details = ev["details"]
                                with st.container():
                                    st.markdown("**Technical Details:**")
                                    if details.get("endpoint_url"):
                                        st.code(f"Endpoint: {details['endpoint_url']}")
                                    if details.get("ip_address"):
                                        st.code(f"IP Address: {details['ip_address']}")
                                    if details.get("ip_range"):
                                        st.code(f"IP Range: {details['ip_range']}")
                                    if details.get("cloud_domain"):
                                        st.code(
                                            f"Cloud Domain: {details['cloud_domain']}"
                                        )
                                    if details.get("service_type"):
                                        st.code(f"Service: {details['service_type']}")
                            st.write("---")

                with col2:
                    # Summary info
                    st.metric("Confidence Score", f"{confidence:.1f}%")

                    # All provider scores
                    if result.get("details", {}).get("provider_scores"):
                        st.write("**📊 All Scores:**")
                        scores = result["details"]["provider_scores"]
                        for prov, score in scores.items():
                            if score > 0:
                                st.write(f"• **{prov}**: {score:.1f}")

        # Provider distribution chart
        if providers and len(providers) > 1:
            st.subheader("🔍 Provider Distribution")
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

        # Get backend API info
        backend_data = result.get("details", {}).get("backend_data", {})
        xhr_apis = ", ".join(backend_data.get("xhr_api_calls", []))
        app_subdomains = ", ".join(backend_data.get("app_subdomains", []))
        cloud_domains = ", ".join(
            [
                d[0] if isinstance(d, tuple) else str(d)
                for d in backend_data.get("cloud_provider_domains", [])
            ]
        )

        # Wrap long text fields for better display
        primary_reason = result.get("primary_reason", "No reason provided")
        if len(primary_reason) > 100:
            import textwrap

            primary_reason = "\n".join(textwrap.wrap(primary_reason, width=100))

        final_data.append(
            {
                "Domain": result["url"],
                "Cloud Provider": result["primary_cloud_provider"],
                "Confidence Score": f"{result['confidence_score']:.1f}%",
                "Primary Reason": primary_reason,
                "Evidence Methods": evidence_summary,
                "XHR API Calls": xhr_apis if xhr_apis else "None detected",
                "App Subdomains": app_subdomains if app_subdomains else "None detected",
                "Cloud XHR Calls": cloud_domains if cloud_domains else "None detected",
                "Error": result.get("details", {}).get("error", ""),
            }
        )

    results_df = pd.DataFrame(final_data)

    # Summary statistics
    total = len(results)
    providers = {}
    high_confidence = 0
    errors = 0
    api_detected = 0

    for result in results:
        provider = result["primary_cloud_provider"]
        providers[provider] = providers.get(provider, 0) + 1
        if result["confidence_score"] >= 70:
            high_confidence += 1
        if provider == "Error":
            errors += 1
        # Count domains where API endpoints were detected
        backend_data = result.get("details", {}).get("backend_data", {})
        if backend_data.get("xhr_api_calls") or backend_data.get(
            "cloud_provider_domains"
        ):
            api_detected += 1

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
        api_rate = (api_detected / total * 100) if total > 0 else 0
        st.metric("API Endpoints Found", f"{api_rate:.1f}%")

    # Provider distribution chart
    if providers:
        st.subheader("☁️ Final Provider Distribution")
        provider_df = pd.DataFrame(
            list(providers.items()), columns=["Provider", "Count"]
        )
        st.bar_chart(provider_df.set_index("Provider"))

    # Detailed results table
    st.subheader("📋 Complete Results with Backend Analysis")

    # Add expandable details for each domain
    for i, result in enumerate(results):
        with st.expander(
            f"🔍 {result['url']} → {result['primary_cloud_provider']} ({result['confidence_score']:.1f}%)"
        ):
            col1, col2 = st.columns([2, 1])

            with col1:
                primary_reason = result.get("primary_reason", "No reason provided")

                # Display primary reason with proper formatting
                st.write("**Primary Reason:**")
                if len(primary_reason) > 120:
                    # For very long reasons, use an info box for better readability
                    st.info(primary_reason)
                else:
                    st.write(primary_reason)

                # Show backend data
                backend_data = result.get("details", {}).get("backend_data", {})
                if backend_data.get("xhr_api_calls"):
                    st.write("**🎯 XHR API Calls:**")
                    for api in backend_data["xhr_api_calls"]:
                        st.write(f"• {api}")

                if backend_data.get("cloud_provider_domains"):
                    st.write("**☁️ Direct Cloud Provider Calls:**")
                    for domain_info in backend_data["cloud_provider_domains"]:
                        if isinstance(domain_info, tuple):
                            domain, provider = domain_info
                            st.write(f"• {domain} ({provider})")
                        else:
                            st.write(f"• {domain_info}")

                # Show evidence details
                if result.get("evidence"):
                    st.write("**Evidence Found:**")
                    for evidence in result["evidence"]:
                        st.write(
                            f"• **{evidence['method']}**: {evidence['evidence']} (+{evidence['confidence_points']} pts)"
                        )

                        # Show detailed information if available
                        if evidence.get("details"):
                            details = evidence["details"]
                            with st.expander(
                                "🔍 Detailed Evidence Info", expanded=False
                            ):
                                if details.get("endpoint_url"):
                                    st.write(
                                        f"📍 **Endpoint:** `{details['endpoint_url']}`"
                                    )
                                if details.get("ip_address"):
                                    st.write(
                                        f"🌐 **IP Address:** `{details['ip_address']}`"
                                    )
                                if details.get("ip_range"):
                                    st.write(
                                        f"📊 **IP Range:** `{details['ip_range']}`"
                                    )
                                if details.get("network_name"):
                                    st.write(
                                        f"🏷️ **Network:** {details['network_name']}"
                                    )

                # Show all provider scores
                if result.get("details", {}).get("provider_scores"):
                    with st.expander("📊 All Provider Scores", expanded=False):
                        scores = result["details"]["provider_scores"]
                        for provider, score in scores.items():
                            if score > 0:
                                st.write(f"• **{provider}**: {score:.1f} points")

            with col2:
                # Summary info
                st.metric("Confidence", f"{result['confidence_score']:.1f}%")
                if result.get("details", {}).get("main_domain_ips"):
                    st.write("**Main IPs:**")
                    for ip in result["details"]["main_domain_ips"][:3]:  # Show first 3
                        st.write(f"• {ip}")

    # Original table for CSV download
    st.subheader("📋 Detailed Results Table")

    # Enhanced CSS for better table readability
    st.markdown(
        """
    <style>
    .stDataFrame {
        width: 100%;
    }
    .stDataFrame td {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        max-width: 300px !important;
        vertical-align: top !important;
        font-size: 0.9em;
    }
    .stDataFrame th {
        white-space: nowrap !important;
        font-weight: bold;
        background-color: #f0f2f6;
    }
    .primary-reason-col {
        max-width: 400px !important;
    }
    </style>
    """,
        unsafe_allow_html=True,
    )

    # Use st.table for better text wrapping of complex data
    if results_df.empty == False:
        st.table(results_df)

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
        backend_data = result.get("details", {}).get("backend_data", {})
        summary_data.append(
            {
                "Domain": result["url"],
                "Cloud Provider": result["primary_cloud_provider"],
                "Confidence": f"{result['confidence_score']:.1f}%",
                "Primary Reason": result.get("primary_reason", "No reason provided"),
                "API Calls": len(backend_data.get("xhr_api_calls", [])),
                "Cloud Calls": len(backend_data.get("cloud_provider_domains", [])),
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
            help="Complete analysis data with API calls, cloud calls, and reasoning",
            type="primary",
        )

    with col2:
        st.download_button(
            label="📄 Download Summary",
            data=summary_csv,
            file_name=summary_filename,
            mime="text/csv",
            help="Simplified results with API call and cloud call counts",
        )

    # Analysis summary info
    st.info(f"""
    📊 **Backend Analysis Complete!**
    
    ✅ **{total} domains analyzed**
    🎯 **{success_rate:.1f}% success rate**
    📈 **{high_confidence} high-confidence detections** (≥70%)
    🔍 **{api_detected} domains with API calls detected** ({api_rate:.1f}%)
    ⚡ **{len([p for p in providers.keys() if p != "Error"])} unique providers found**
    
    💡 Use the download buttons above to save your results!
    """)

    # Print summary to console/logs
    print("\n🎉 BACKEND ANALYSIS COMPLETE!")
    print(f"📊 Total domains analyzed: {total}")
    print(f"✅ Success rate: {success_rate:.1f}%")
    print(f"🎯 High confidence detections: {high_confidence}")
    print(f"🔍 API calls detected: {api_detected} domains")
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
    """Display live test results using cards instead of tables to prevent truncation."""
    if not results:
        return

    # Summary metrics with enhanced display
    total = len(results)
    correct_count = sum(1 for r in results if r.get("correct", False))
    accuracy_so_far = (correct_count / total * 100) if total > 0 else 0
    providers = {}
    total_confidence = 0

    for result in results:
        provider = result.get("predicted_label", "Unknown")
        confidence = result.get("confidence", 0)
        providers[provider] = providers.get(provider, 0) + 1
        total_confidence += confidence

    avg_confidence = total_confidence / total if total > 0 else 0

    # Always visible summary metrics at the top
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

        # Provider distribution chart for predictions - always visible
        if providers and len(providers) > 1:
            st.write("🔍 **Live Prediction Distribution:**")
            provider_df = pd.DataFrame(
                list(providers.items()), columns=["Provider", "Count"]
            )
            st.bar_chart(provider_df.set_index("Provider"), height=200)

    # Scrollable test results container with fixed height
    with test_results_table.container():
        st.write(f"**📋 Live Test Results ({len(results)} completed)**")

        # Add CSS for scrollable container
        st.markdown(
            """
            <style>
            .element-container:has(.test-result-card) {
                max-height: 500px;
                overflow-y: auto;
            }
            .test-result-card {
                margin: 8px 0;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

        # Display individual cards using native Streamlit components
        # Streamlit will handle scrolling automatically
        for i, result in enumerate(results):
            is_correct = result.get("correct", False)
            is_insufficient_data = result.get("is_insufficient_data", False)
            domain = result["domain"]
            true_label = result["true_label"]
            predicted_label = result["predicted_label"]
            confidence = result.get("confidence", 0)
            primary_reason = result.get("primary_reason", "No reason provided")

            # Enhanced color coding to handle "Insufficient Data"
            if is_insufficient_data:
                card_color = "#e8f4fd"  # Light blue for insufficient data
                status_emoji = "🔍"
                status_text = "INSUFFICIENT DATA"
                border_color = "#17a2b8"
            elif is_correct and confidence >= 40:  # Correct with reasonable confidence
                card_color = "#d4f6d4"  # Light green
                status_emoji = "✅"
                status_text = "CORRECT"
                border_color = "#28a745"
            elif (
                is_correct and predicted_label == "Other" and confidence < 40
            ):  # "Other" match but low confidence
                card_color = "#f0f0f0"  # Light grey - not enough info to be confident about "Other"
                status_emoji = "⚫"
                status_text = "LOW CONFIDENCE"
                border_color = "#6c757d"
            elif confidence < 30:  # Low confidence for any result
                card_color = "#f0f0f0"  # Light grey
                status_emoji = "⚫"
                status_text = "LOW CONFIDENCE"
                border_color = "#6c757d"
            else:
                card_color = "#f6d4d4"  # Light red for actual wrong predictions with decent confidence
                status_emoji = "❌"
                status_text = "WRONG"
                border_color = "#dc3545"

            # Provider emojis
            def get_provider_emoji(provider):
                if provider == "AWS":
                    return "🟧"
                elif provider == "GCP":
                    return "🔵"
                elif provider == "Azure":
                    return "🔷"
                elif provider == "Insufficient Data":
                    return "🔍"
                else:
                    return "⚫"

            true_emoji = get_provider_emoji(true_label)
            pred_emoji = get_provider_emoji(predicted_label)

            # Create individual card using native Streamlit markdown
            if is_insufficient_data:
                # Special display for insufficient data cases
                card_html = f"""
                <div class="test-result-card" style="
                    background-color: {card_color};
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid {border_color};
                    margin: 8px 0;
                    font-size: 14px;
                ">
                    <div style="font-weight: bold; margin-bottom: 8px;">
                        {status_emoji} <strong>{domain}</strong> - {status_text}
                    </div>
                    <div style="margin-bottom: 5px;">
                        <strong>Expected:</strong> {true_emoji} {true_label} | 
                        <strong>Result:</strong> {pred_emoji} Insufficient Data (excluded from accuracy)
                    </div>
                    <div style="background-color: white; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px;">
                        <strong>Reason:</strong> {primary_reason}
                    </div>
                </div>
                """
            else:
                # Normal display for classified cases
                card_html = f"""
                <div class="test-result-card" style="
                    background-color: {card_color};
                    padding: 15px;
                    border-radius: 8px;
                    border-left: 4px solid {border_color};
                    margin: 8px 0;
                    font-size: 14px;
                ">
                    <div style="font-weight: bold; margin-bottom: 8px;">
                        {status_emoji} <strong>{domain}</strong> - {status_text}
                    </div>
                    <div style="margin-bottom: 5px;">
                        <strong>Expected:</strong> {true_emoji} {true_label} | 
                        <strong>Predicted:</strong> {pred_emoji} {predicted_label} ({confidence:.1f}%)
                    </div>
                    <div style="background-color: white; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 12px;">
                        <strong>Reason:</strong> {primary_reason}
                    </div>
                </div>
                """

            # Display each card individually
            st.markdown(card_html, unsafe_allow_html=True)

        # Quick stats below the scrollable area
        classified_count = sum(
            1 for r in results if not r.get("is_insufficient_data", False)
        )
        correct_count = sum(
            1
            for r in results
            if r.get("correct", False) and not r.get("is_insufficient_data", False)
        )
        insufficient_count = sum(
            1 for r in results if r.get("is_insufficient_data", False)
        )
        wrong_count = classified_count - correct_count

        if classified_count > 0:
            accuracy_percent = (correct_count / classified_count) * 100
            if wrong_count > 0:
                st.write(
                    f"📈 **Current Stats:** {correct_count} correct, {wrong_count} wrong, {insufficient_count} insufficient data | **Accuracy: {accuracy_percent:.1f}%**"
                )
            else:
                st.write(
                    f"🎉 **Perfect classification!** {correct_count} out of {classified_count} correct, {insufficient_count} insufficient data"
                )
        else:
            st.write(
                f"🔍 **No classifications yet** - {insufficient_count} domains had insufficient data"
            )


def display_final_test_results(test_metrics: dict, results: List[Dict]):
    """Display final test results using cards instead of tables to prevent truncation."""
    st.subheader("🎯 Final Test Results")

    # Enhanced metrics display including classification rate
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            "Accuracy",
            f"{test_metrics['accuracy']:.3f}",
            f"{test_metrics['accuracy'] * 100:.1f}%",
        )
    with col2:
        st.metric(
            "Precision",
            f"{test_metrics['precision']:.3f}",
            f"{test_metrics['precision'] * 100:.1f}%",
        )
    with col3:
        st.metric(
            "Recall",
            f"{test_metrics['recall']:.3f}",
            f"{test_metrics['recall'] * 100:.1f}%",
        )
    with col4:
        st.metric(
            "Classification Rate",
            f"{test_metrics['classification_rate']:.1f}%",
            f"{test_metrics['classified_domains']}/{test_metrics['total_domains']} domains",
        )

    # Key information about insufficient data
    if test_metrics["insufficient_data_count"] > 0:
        st.info(f"""
        📊 **Enhanced Accuracy Calculation:**
        - **Accuracy** is calculated only on domains where sufficient data was available for classification
        - **{test_metrics["insufficient_data_count"]} domains** had insufficient data and were excluded from accuracy metrics
        - **Classification Rate**: {test_metrics["classification_rate"]:.1f}% of domains could be classified
        """)

    # Detailed classification report
    st.subheader("📊 Per-Class Metrics")

    class_metrics = []
    for label, metrics in test_metrics["classification_report"].items():
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
    correct_count = sum(
        1
        for r in results
        if r.get("correct", False) and not r.get("is_insufficient_data", False)
    )
    error_count = sum(1 for r in results if r.get("predicted_label") == "Error")
    insufficient_count = sum(1 for r in results if r.get("is_insufficient_data", False))

    # Provider breakdown
    providers = {}
    for result in results:
        provider = result.get("predicted_label", "Unknown")
        providers[provider] = providers.get(provider, 0) + 1

    # Display summary metrics
    st.subheader("📈 Test Summary")
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Tested", total)
    with col2:
        st.metric("Classified", test_metrics["classified_domains"])
    with col3:
        st.metric("Correct", correct_count)
    with col4:
        st.metric("Insufficient Data", insufficient_count)
    with col5:
        st.metric("Errors", error_count)

    # Detailed test results using cards instead of table
    st.subheader("🔍 Complete Test Results")

    # Provider emoji function
    def get_provider_emoji(provider):
        if provider == "AWS":
            return "🟧"
        elif provider == "GCP":
            return "🔵"
        elif provider == "Azure":
            return "🔷"
        elif provider == "Error":
            return "❌"
        elif provider == "Insufficient Data":
            return "🔍"
        else:
            return "⚫"

    # Display all results as cards
    for i, result in enumerate(results):
        is_correct = result.get("correct", False)
        is_insufficient_data = result.get("is_insufficient_data", False)
        domain = result["domain"]
        true_label = result["true_label"]
        predicted_label = result["predicted_label"]
        confidence = result.get("confidence", 0)
        primary_reason = result.get("primary_reason", "No reason provided")

        # Enhanced color coding to handle "Insufficient Data"
        if is_insufficient_data:
            card_color = "#e8f4fd"  # Light blue for insufficient data
            status_emoji = "🔍"
            status_text = "INSUFFICIENT DATA"
            border_color = "#17a2b8"
        elif is_correct and confidence >= 40:  # Correct with reasonable confidence
            card_color = "#d4f6d4"  # Light green
            status_emoji = "✅"
            status_text = "CORRECT"
            border_color = "#28a745"
        elif (
            is_correct and predicted_label == "Other" and confidence < 40
        ):  # "Other" match but low confidence
            card_color = (
                "#f0f0f0"  # Light grey - not enough info to be confident about "Other"
            )
            status_emoji = "⚫"
            status_text = "LOW CONFIDENCE"
            border_color = "#6c757d"
        elif confidence < 30:  # Low confidence for any result
            card_color = "#f0f0f0"  # Light grey
            status_emoji = "⚫"
            status_text = "LOW CONFIDENCE"
            border_color = "#6c757d"
        else:
            card_color = "#f6d4d4"  # Light red for actual wrong predictions with decent confidence
            status_emoji = "❌"
            status_text = "WRONG"
            border_color = "#dc3545"

        # Provider emojis
        def get_provider_emoji(provider):
            if provider == "AWS":
                return "🟧"
            elif provider == "GCP":
                return "🔵"
            elif provider == "Azure":
                return "🔷"
            else:
                return "⚫"

        true_emoji = get_provider_emoji(true_label)
        pred_emoji = get_provider_emoji(predicted_label)

        # Create test result card with full reason visibility
        st.markdown(
            f"""
        <div style="
            background-color: {card_color};
            padding: 20px;
            border-radius: 10px;
            border-left: 5px solid {border_color};
            margin: 10px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        ">
            <h4 style="margin: 0 0 15px 0; color: #333;">
                {status_emoji} <strong>{domain}</strong> - {status_text}
            </h4>
            <div style="margin-bottom: 10px; font-size: 16px;">
                <strong>Reason:</strong> {primary_reason}
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

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
    🎯 **{test_metrics["accuracy"] * 100:.1f}% overall accuracy**
    📈 **{correct_count} correct predictions**
    ⚡ **{len([p for p in providers.keys() if p != "Error"])} unique providers detected**
    
    💡 Download the results above for further analysis!
    """)

    # Print summary to console/logs
    print("\n🧪 ACCURACY TEST COMPLETE!")
    print(f"📊 Total domains tested: {total}")
    print(f"🎯 Overall accuracy: {test_metrics['accuracy'] * 100:.1f}%")
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
