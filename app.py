#!/usr/bin/env python3
"""
Streamlit Cloud Provider Scanner Application

A web interface for testing cloud provider detection accuracy.
Features:
- Run accuracy tests against labeled data
- Live crawling activity display with complete details
- Real-time summary metrics
- Always-visible history with full details
- Partial matching for multiple cloud providers
- Enhanced backend header analysis
- Single domain crawling
- CSV batch processing with persistent storage
"""

import streamlit as st
import pandas as pd
import asyncio
import time
import copy
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import uuid

# Import our updated detector
from detector import CloudProviderDetector

# Constants
ACTIVITY_UPDATE_DELAY = 0.1  # seconds
TEST_COMPLETION_DELAY = 2.0  # seconds
MAX_ACTIVITY_LINES = 15
MAX_PREVIEW_ITEMS = 3
MAX_PREVIEW_MATCHES = 2

# Storage paths
RESULTS_DIR = "results"
SINGLE_RESULTS_FILE = os.path.join(RESULTS_DIR, "single_domain_results.json")
BATCH_RESULTS_FILE = os.path.join(RESULTS_DIR, "batch_results.json")

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

# Page configuration
st.set_page_config(
    page_title="Cloud Provider Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom CSS for clean styling
st.markdown(
    """
<style>
    .main-header {
        text-align: center;
        padding: 1.5rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 1.5rem;
    }
    .summary-metrics {
        background: #f8f9fa;
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        border: 1px solid #e0e0e0;
    }
    .crawl-activity {
        background: #ffffff;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .crawl-completed {
        background: #f8f9fa;
        border-left: 4px solid #28a745;
    }
    .crawl-active {
        background: #fff3cd;
        border-left: 4px solid #ffc107;
        animation: pulse 2s infinite;
    }
    .crawl-error {
        background: #f8d7da;
        border-left: 4px solid #dc3545;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    .activity-snippet {
        font-family: 'Courier New', monospace;
        font-size: 0.85em;
        background: #f1f3f4;
        padding: 0.5rem;
        border-radius: 4px;
        margin: 0.5rem 0;
        max-height: 200px;
        overflow-y: auto;
    }
    .metric-card {
        text-align: center;
        padding: 1rem;
        background: white;
        border-radius: 8px;
        border: 1px solid #e0e0e0;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        margin: 0;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #666;
        margin: 0;
    }
    .metric-percent {
        font-size: 1.2rem;
        font-weight: bold;
        margin-top: 0.5rem;
    }
    .sidebar-info {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
    .scrollable-results {
        max-height: 70vh;
        overflow-y: auto;
        padding-right: 10px;
    }
    .result-card {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        padding-left: 20px;
        padding-right: 20px;
    }
</style>
""",
    unsafe_allow_html=True,
)


def check_partial_match(
    expected: str, predicted: str, all_providers: Optional[List[str]] = None
) -> bool:
    """Check if prediction partially matches expected, considering multiple providers."""
    if predicted == expected:
        return True

    # Handle multiple providers in prediction
    if all_providers and expected in all_providers:
        return True

    # Handle cases where prediction contains expected provider
    expected_lower = expected.lower()
    predicted_lower = predicted.lower()

    return expected_lower in predicted_lower


def format_detected_providers(
    all_detected_providers: List[str], predicted_label: str
) -> str:
    """Format detected providers for display."""
    if len(all_detected_providers) > 1:
        return " + ".join(all_detected_providers)
    elif len(all_detected_providers) == 1:
        return all_detected_providers[0]
    else:
        return predicted_label


def get_status_info(predicted_label: str, is_correct: bool) -> Tuple[str, str, str]:
    """Get status emoji, CSS class, and text for a result."""
    if predicted_label == "Insufficient Data":
        return "🔍", "info", "INSUFFICIENT DATA"
    elif is_correct:
        return "✅", "success", "CORRECT"
    else:
        return "❌", "error", "WRONG"


def create_deep_copy_result_data(result: Dict) -> Tuple[Dict, Dict, List]:
    """Create deep copies of result data to prevent sharing between results."""
    backend_data = {}
    if result.get("details", {}).get("backend_data"):
        original_backend = result["details"]["backend_data"]
        backend_data = {
            "app_subdomains": list(original_backend.get("app_subdomains", [])),
            "xhr_api_calls": list(original_backend.get("xhr_api_calls", [])),
            "cloud_provider_domains": copy.deepcopy(
                original_backend.get("cloud_provider_domains", [])
            ),
        }

    ip_analysis = {}
    if result.get("ip_analysis"):
        original_ip = result["ip_analysis"]
        ip_analysis = {
            "cloud_ip_matches": copy.deepcopy(original_ip.get("cloud_ip_matches", [])),
            "total_ips_checked": original_ip.get("total_ips_checked", 0),
            "cloud_matches": original_ip.get("cloud_matches", 0),
        }

    # Deep copy evidence data to prevent sharing - ONLY use isolated evidence
    evidence_data = []
    if result.get("evidence"):
        evidence_data = copy.deepcopy(result["evidence"])

    return backend_data, ip_analysis, evidence_data


# Storage utility functions
def load_results(file_path: str) -> List[Dict]:
    """Load results from JSON file."""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def save_results(file_path: str, results: List[Dict]) -> None:
    """Save results to JSON file."""
    try:
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    except IOError as e:
        st.error(f"Failed to save results: {e}")


def add_result_to_storage(file_path: str, result: Dict) -> None:
    """Add a single result to storage."""
    results = load_results(file_path)
    result['timestamp'] = datetime.now().isoformat()
    result['id'] = str(uuid.uuid4())
    results.append(result)
    save_results(file_path, results)


def main() -> None:
    """Main application function."""
    # Header
    st.markdown(
        """
    <div class="main-header">
        <h1>🔍 Cloud Provider Scanner</h1>
        <p>Detect cloud providers with live crawling, batch processing, and accuracy testing</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Create tabs for different modes
    tab1, tab2, tab3 = st.tabs(["🔍 Single Domain", "📊 CSV Batch Processing", "🧪 Accuracy Testing"])
    
    with tab1:
        render_single_domain_tab()
    
    with tab2:
        render_csv_batch_tab()
    
    with tab3:
        render_accuracy_test_tab()


def render_single_domain_tab() -> None:
    """Render the single domain analysis tab."""
    st.markdown("### 🔍 Single Domain Analysis")
    st.markdown("Enter a domain to analyze its cloud provider hosting in real-time.")
    
    # Input section
    col1, col2 = st.columns([3, 1])
    
    with col1:
        domain_input = st.text_input(
            "Domain to analyze",
            placeholder="example.com",
            help="Enter a domain without http:// or https://"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)  # Add spacing
        headless_mode = st.checkbox("Headless browser", value=True, key="single_headless")
    
    # Analysis button
    if st.button("🚀 Analyze Domain", type="primary", use_container_width=True):
        if domain_input.strip():
            run_single_domain_analysis(domain_input.strip(), headless_mode)
        else:
            st.error("Please enter a domain to analyze")
    
    # Display stored results
    st.markdown("### 📋 Recent Results")
    display_single_domain_results()


def render_csv_batch_tab() -> None:
    """Render the CSV batch processing tab."""
    st.markdown("### 📊 CSV Batch Processing")
    st.markdown("Upload a CSV file with domains to analyze multiple sites at once.")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a CSV file",
        type="csv",
        help="CSV should have a 'domain' column. Other columns will be preserved in results."
    )
    
    if uploaded_file is not None:
        try:
            # Read and preview CSV
            df = pd.read_csv(uploaded_file)
            
            if 'domain' not in df.columns:
                st.error("❌ CSV file must contain a 'domain' column")
                return
            
            st.success(f"✅ CSV loaded successfully with {len(df)} domains")
            
            # Preview
            st.markdown("#### Preview:")
            st.dataframe(df.head(), use_container_width=True)
            
            # Processing options
            col1, col2 = st.columns(2)
            with col1:
                headless_mode = st.checkbox("Headless browser", value=True, key="batch_headless")
            with col2:
                max_concurrent = st.slider("Max concurrent analyses", 1, 5, 2)
            
            # Start processing
            if st.button("🚀 Start Batch Analysis", type="primary", use_container_width=True):
                run_csv_batch_analysis(df, headless_mode, max_concurrent)
                
        except Exception as e:
            st.error(f"❌ Error reading CSV file: {str(e)}")
    
    # Display batch results
    st.markdown("### 📋 Batch Results")
    display_batch_results()


def render_accuracy_test_tab() -> None:
    """Render the accuracy testing tab."""
    # Main layout
    col1, col2 = st.columns([3, 1])

    with col2:
        render_sidebar()

    with col1:
        # Summary metrics at top
        display_summary_metrics()

        # Test results area
        if getattr(st.session_state, "test_running", False):
            run_live_accuracy_test()
        else:
            st.info("👆 Click 'Start Accuracy Test' to begin live testing")


def render_sidebar() -> None:
    """Render the sidebar with controls and information."""
    # Sidebar info
    st.markdown(
        """
        <div class="sidebar-info">
            <h3>🎯 Detection Methods</h3>
            <p><strong>XHR API Analysis:</strong> Captures backend API calls from app subdomains</p>
            <p><strong>IP Range Matching:</strong> Matches IPs to official cloud provider ranges</p>
            <p><strong>Backend Header Analysis:</strong> Analyzes HTTP headers for cloud-specific backend indicators (AWS API Gateway, GCP Cloud Functions, Azure App Service, etc.)</p>
            <p><strong>Direct Cloud Calls:</strong> Detects calls to *.amazonaws.com, *.googleapis.com etc.</p>
            <p><strong>Enhanced Subdomain Exploration:</strong> Tests api.domain, app.domain, admin.domain, dashboard.domain, and other common subdomains</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Test controls
    st.markdown("### 🚀 Test Controls")

    # Check for browser availability
    try:
        from detector import BROWSERS_AVAILABLE

        if BROWSERS_AVAILABLE:
            st.success("🚀 **Full Analysis Mode**\nBrowser features available")
        else:
            st.info("🔍 **IP-Only Mode**\nUsing IP range analysis")
    except ImportError:
        st.warning("⚠️ **Limited Mode**\nDetector module not available")

    headless_mode = st.checkbox("Headless browser", value=True)

    if st.button("🧪 Start Accuracy Test", type="primary", use_container_width=True):
        st.session_state.test_running = True
        st.rerun()

    if st.button("🛑 Stop Test", use_container_width=True):
        st.session_state.test_running = False
        st.session_state.test_results = []
        st.rerun()


def display_summary_metrics() -> None:
    """Display summary metrics at the top."""
    results = getattr(st.session_state, "test_results", [])

    if not results:
        # Empty state
        st.markdown(
            """
        <div class="summary-metrics">
            <div style="display: flex; justify-content: space-around;">
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Tested</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Unknown</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Correct</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">0</div>
                    <div class="metric-label">Wrong</div>
                </div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        return

    # Calculate metrics
    total = len(results)
    unknown = sum(1 for r in results if r.get("predicted_label") == "Insufficient Data")
    classified = total - unknown
    correct = sum(
        1
        for r in results
        if r.get("correct", False) and r.get("predicted_label") != "Insufficient Data"
    )
    wrong = classified - correct

    # Calculate percentages
    correct_pct = (correct / classified * 100) if classified > 0 else 0
    wrong_pct = (wrong / classified * 100) if classified > 0 else 0
    unknown_pct = (unknown / total * 100) if total > 0 else 0

    # Display metrics
    st.markdown(
        f"""
    <div class="summary-metrics">
        <div style="display: flex; justify-content: space-around;">
            <div class="metric-card">
                <div class="metric-value">{total}</div>
                <div class="metric-label">Tested</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{unknown}</div>
                <div class="metric-label">Unknown</div>
                <div class="metric-percent">{unknown_pct:.1f}%</div>
            </div>
            <div class="metric-card" style="border-left: 4px solid #28a745;">
                <div class="metric-value" style="color: #28a745;">{correct}</div>
                <div class="metric-label">Correct</div>
                <div class="metric-percent" style="color: #28a745;">{correct_pct:.1f}%</div>
            </div>
            <div class="metric-card" style="border-left: 4px solid #dc3545;">
                <div class="metric-value" style="color: #dc3545;">{wrong}</div>
                <div class="metric-label">Wrong</div>
                <div class="metric-percent" style="color: #dc3545;">{wrong_pct:.1f}%</div>
            </div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def run_live_accuracy_test() -> None:
    """Run live accuracy test with real-time updates."""
    # Initialize session state
    if "test_results" not in st.session_state:
        st.session_state.test_results = []
    if "current_test_index" not in st.session_state:
        st.session_state.current_test_index = 0
    if "test_data" not in st.session_state:
        try:
            # Load and shuffle test data
            test_df = pd.read_csv("data/test.csv")
            st.session_state.test_data = test_df.sample(frac=1).reset_index(drop=True)
        except FileNotFoundError:
            st.error("❌ Test data file 'data/test.csv' not found!")
            st.session_state.test_running = False
            return
        except Exception as e:
            st.error(f"❌ Error loading test data: {str(e)}")
            st.session_state.test_running = False
            return

    test_data = st.session_state.test_data
    current_index = st.session_state.current_test_index

    # Check if test is complete
    if current_index >= len(test_data):
        st.success("🎉 **Test Complete!** All domains have been analyzed.")
        st.session_state.test_running = False
        return

    # Get current domain
    current_row = test_data.iloc[current_index]
    domain = current_row["domain"]
    true_label = current_row["cloud_provider"]

    # Display current test
    st.markdown(
        f"### 🔍 Currently Testing: `{domain}` ({current_index + 1}/{len(test_data)})"
    )

    # Create containers for live updates
    activity_container = st.container()

    # Display all previous results (most recent first) - always visible
    if st.session_state.test_results:
        st.markdown("### 📋 All Results (Most Recent First)")
        with st.container():
            st.markdown('<div class="scrollable-results">', unsafe_allow_html=True)
            for result in reversed(st.session_state.test_results):  # Show ALL results
                display_result_card(result)
            st.markdown("</div>", unsafe_allow_html=True)

    # Run analysis for current domain
    with activity_container:
        run_single_domain_test(domain, true_label)


def run_single_domain_test(domain: str, true_label: str) -> None:
    """Run test for a single domain with live activity display."""
    # Create activity display
    activity_placeholder = st.empty()

    with activity_placeholder.container():
        st.markdown(
            f"""
        <div class="crawl-activity crawl-active">
            <h4>🔄 Analyzing: {domain}</h4>
            <div class="activity-snippet">
                <div>🚀 Starting analysis...</div>
                <div>🌐 Initializing browser...</div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Initialize detector
    try:
        detector = CloudProviderDetector(headless=True)
    except Exception as e:
        st.error(f"❌ Failed to initialize detector: {str(e)}")
        return

    # Activity log
    activity_log = ["🚀 Starting analysis...", "🌐 Initializing browser..."]

    def update_activity(message: str) -> None:
        activity_log.append(message)
        activity_html = "<br>".join(
            activity_log[-MAX_ACTIVITY_LINES:]
        )  # Show last N lines

        with activity_placeholder.container():
            st.markdown(
                f"""
            <div class="crawl-activity crawl-active">
                <h4>🔄 Analyzing: {domain}</h4>
                <div class="activity-snippet">
                    {activity_html}
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )
        time.sleep(ACTIVITY_UPDATE_DELAY)  # Small delay for visual effect

    try:
        # Start analysis with live updates
        update_activity("🔍 Exploring main domain...")

        # Run analysis
        result = asyncio.run(detector.analyze_website(domain))

        # Create deep copies of data to prevent sharing between results
        backend_data, ip_analysis, evidence_data = create_deep_copy_result_data(result)

        # Show analysis progress
        show_analysis_progress(
            update_activity, backend_data, ip_analysis, evidence_data
        )

        # Process final results
        predicted_label = result["primary_cloud_provider"]
        confidence = result.get("confidence_score", 0)
        primary_reason = result.get("primary_reason", "No reason provided")

        # Get all detected providers from result
        all_detected_providers = []
        if result.get("details", {}).get("provider_scores"):
            all_detected_providers = [
                p
                for p, score in result["details"]["provider_scores"].items()
                if score > 0
            ]

        is_correct = check_partial_match(
            true_label, predicted_label, all_detected_providers
        )
        status_emoji = (
            "✅"
            if is_correct
            else "🔍"
            if predicted_label == "Insufficient Data"
            else "❌"
        )

        update_activity(
            f"🎯 Analysis complete: {predicted_label} ({confidence}% confidence)"
        )
        update_activity(
            f"{status_emoji} Expected: {true_label}, Got: {predicted_label}"
        )

        # Create result object with isolated data
        test_result = create_test_result(
            domain,
            true_label,
            predicted_label,
            all_detected_providers,
            confidence,
            primary_reason,
            is_correct,
            activity_log,
            backend_data,
            ip_analysis,
            evidence_data,
        )

        # Add to results and advance
        st.session_state.test_results.append(test_result)
        st.session_state.current_test_index += 1

        # Show completion status
        show_completion_status(
            activity_placeholder,
            domain,
            true_label,
            predicted_label,
            all_detected_providers,
            is_correct,
            status_emoji,
        )

        # Auto-advance to next test after brief pause
        time.sleep(TEST_COMPLETION_DELAY)
        st.rerun()

    except Exception as e:
        handle_analysis_error(update_activity, domain, true_label, activity_log, str(e))


def show_analysis_progress(
    update_activity, backend_data: Dict, ip_analysis: Dict, evidence_data: List
) -> None:
    """Show analysis progress updates."""
    # Show subdomain discovery
    if backend_data.get("app_subdomains"):
        for subdomain in backend_data["app_subdomains"]:
            update_activity(f"🏢 Found subdomain: {subdomain}")
    else:
        update_activity("🏢 No app subdomains discovered")

    # Show XHR calls
    if backend_data.get("xhr_api_calls"):
        update_activity(
            f"🔗 Discovered {len(backend_data['xhr_api_calls'])} XHR API calls"
        )
        for api in backend_data["xhr_api_calls"][:MAX_PREVIEW_ITEMS]:
            update_activity(f"   📡 {api}")

        # Show header analysis
        update_activity("🛡️ Analyzing backend headers...")
    else:
        update_activity("🔗 No XHR API calls found")

    # Show IP analysis
    if ip_analysis.get("cloud_ip_matches"):
        update_activity(
            f"☁️ Found {len(ip_analysis['cloud_ip_matches'])} cloud IP matches"
        )
        for match in ip_analysis["cloud_ip_matches"][:MAX_PREVIEW_MATCHES]:
            update_activity(
                f"   📍 {match['ip']} → {match['provider']} ({match['ip_range']})"
            )
    elif ip_analysis.get("total_ips_checked", 0) > 0:
        update_activity(
            f"🔍 Checked {ip_analysis['total_ips_checked']} IPs - no cloud matches"
        )

    # Show direct cloud calls
    if backend_data.get("cloud_provider_domains"):
        update_activity(
            f"☁️ Found {len(backend_data['cloud_provider_domains'])} direct cloud calls"
        )
        for call in backend_data["cloud_provider_domains"][:MAX_PREVIEW_MATCHES]:
            if isinstance(call, tuple):
                update_activity(f"   🎯 {call[0]} → {call[1]}")

    # Show header analysis results
    if evidence_data:
        header_evidence = [
            e for e in evidence_data if e.get("method") == "XHR API Headers"
        ]
        if header_evidence:
            update_activity(
                f"🛡️ Found backend headers: {len(header_evidence)} endpoints with cloud headers"
            )
            for evidence in header_evidence[:MAX_PREVIEW_MATCHES]:  # Show first 2
                endpoint = evidence.get("details", {}).get("endpoint_url", "unknown")
                provider = evidence.get("provider", "unknown")
                update_activity(f"   🔍 {endpoint} → {provider} headers detected")


def create_test_result(
    domain: str,
    true_label: str,
    predicted_label: str,
    all_detected_providers: List[str],
    confidence: int,
    primary_reason: str,
    is_correct: bool,
    activity_log: List[str],
    backend_data: Dict,
    ip_analysis: Dict,
    evidence_data: List,
) -> Dict:
    """Create a test result object with completely isolated data."""

    # Extract base domain for filtering
    base_domain = domain
    if domain.startswith("www."):
        base_domain = domain[4:]

    # CRITICAL FIX: Filter evidence to only include data for this specific domain
    filtered_evidence = []
    for evidence in evidence_data:
        # Only include evidence that relates to the current domain
        if evidence.get("method") == "XHR API Headers":
            endpoint = evidence.get("details", {}).get("endpoint_url", "")
            if (
                endpoint
                and base_domain
                and (
                    base_domain in endpoint
                    or endpoint.endswith(f".{base_domain}")
                    or endpoint == base_domain
                )
            ):
                # Deep copy the evidence to prevent sharing
                filtered_evidence.append(copy.deepcopy(evidence))
        else:
            # For non-header evidence, include all (IP analysis, etc.)
            filtered_evidence.append(copy.deepcopy(evidence))

    # Filter backend_data to only include domain-specific data
    filtered_backend_data = copy.deepcopy(backend_data)
    if filtered_backend_data.get("xhr_api_calls"):
        filtered_backend_data["xhr_api_calls"] = [
            api for api in filtered_backend_data["xhr_api_calls"] if base_domain in api
        ]
    if filtered_backend_data.get("app_subdomains"):
        filtered_backend_data["app_subdomains"] = [
            sub for sub in filtered_backend_data["app_subdomains"] if base_domain in sub
        ]

    # Filter IP analysis to only include domain-specific matches
    filtered_ip_analysis = copy.deepcopy(ip_analysis)
    if filtered_ip_analysis.get("cloud_ip_matches"):
        filtered_ip_analysis["cloud_ip_matches"] = [
            match
            for match in filtered_ip_analysis["cloud_ip_matches"]
            if base_domain in match.get("api_domain", "")
        ]

    return {
        "domain": domain,
        "true_label": true_label,
        "predicted_label": predicted_label,
        "all_detected_providers": list(all_detected_providers),  # Create new list
        "confidence": confidence,
        "primary_reason": primary_reason,
        "correct": is_correct and predicted_label != "Insufficient Data",
        "activity_log": list(activity_log),  # Create new list
        "backend_data": filtered_backend_data,  # Domain-filtered data
        "ip_analysis": filtered_ip_analysis,  # Domain-filtered data
        "evidence": filtered_evidence,  # Domain-filtered evidence
        "timestamp": time.time(),
    }


def show_completion_status(
    activity_placeholder,
    domain: str,
    true_label: str,
    predicted_label: str,
    all_detected_providers: List[str],
    is_correct: bool,
    status_emoji: str,
) -> None:
    """Show completion status for a domain test."""
    completion_display = format_detected_providers(
        all_detected_providers, predicted_label
    )

    # Show completed state briefly
    status_class = (
        "crawl-completed"
        if is_correct
        else "crawl-activity"
        if predicted_label == "Insufficient Data"
        else "crawl-error"
    )

    with activity_placeholder.container():
        st.markdown(
            f"""
        <div class="crawl-activity {status_class}">
            <h4>{status_emoji} Completed: {domain} → {completion_display}</h4>
            <div style="padding: 0.5rem; background: white; border-radius: 4px; margin: 0.5rem 0;">
                <strong>Expected:</strong> {true_label} | <strong>Detected:</strong> {completion_display}
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )


def handle_analysis_error(
    update_activity,
    domain: str,
    true_label: str,
    activity_log: List[str],
    error_msg: str,
) -> None:
    """Handle analysis errors and create error result."""
    update_activity(f"❌ Error: {error_msg}")

    # Add error result - classify as "Insufficient Data" instead of "Error"
    test_result = {
        "domain": domain,
        "true_label": true_label,
        "predicted_label": "Insufficient Data",
        "all_detected_providers": [],
        "confidence": 0,
        "primary_reason": f"Analysis failed: {error_msg}",
        "correct": False,
        "activity_log": list(activity_log),  # Create new list
        "backend_data": {},
        "ip_analysis": {},
        "evidence": [],  # Empty evidence for error cases
        "timestamp": time.time(),
    }

    st.session_state.test_results.append(test_result)
    st.session_state.current_test_index += 1

    time.sleep(TEST_COMPLETION_DELAY)
    st.rerun()


def display_result_card(result: Dict) -> None:
    """Display a single result card with all content properly contained."""
    # CRITICAL: Clear any potential cached state for this domain
    domain_key = f"cache_{result['domain']}_{result.get('timestamp', time.time())}"
    if domain_key in st.session_state:
        del st.session_state[domain_key]

    domain = result["domain"]
    true_label = result["true_label"]
    predicted_label = result["predicted_label"]
    all_detected_providers = result.get("all_detected_providers", [])
    confidence = result["confidence"]
    is_correct = result.get("correct", False)
    backend_data = result.get("backend_data", {})
    ip_analysis = result.get("ip_analysis", {})

    # Get status information
    status_emoji, status_type, status_text = get_status_info(
        predicted_label, is_correct
    )
    detected_display = format_detected_providers(
        all_detected_providers, predicted_label
    )

    # Extract base domain for filtering
    base_domain = domain
    if domain.startswith("www."):
        base_domain = domain[4:]

    # Create a single card using Streamlit's container with unique key to prevent contamination
    with st.container(
        key=f"result_card_{domain}_{result.get('timestamp', time.time())}"
    ):
        # Header with status
        if status_type == "success":
            st.success(
                f"{status_emoji} **{domain}** → {detected_display} ({status_text})"
            )
        elif status_type == "error":
            st.error(
                f"{status_emoji} **{domain}** → {detected_display} ({status_text})"
            )
        else:
            st.info(f"{status_emoji} **{domain}** → {detected_display} ({status_text})")

        # Expected vs Detected
        st.markdown(f"**Expected:** {true_label} | **Detected:** {detected_display}")

        # Show all detected providers if multiple
        if len(all_detected_providers) > 1:
            providers_text = ", ".join(all_detected_providers)
            st.markdown(f"**🔍 All Detected Providers:** {providers_text}")

        # Show primary reason
        st.markdown(f"**💡 Primary Reason:** {result['primary_reason']}")

        # Create expandable sections for details
        with st.expander(
            "📊 Detailed Analysis",
            expanded=True,
            key=f"expander_{domain}_{result.get('timestamp', time.time())}",
        ):
            col1, col2 = st.columns([1, 1])

            with col1:
                # Subdomains section
                st.markdown("**🏢 Subdomains Explored:**")
                if backend_data.get("app_subdomains"):
                    domain_filtered_subdomains = [
                        sub
                        for sub in backend_data["app_subdomains"]
                        if base_domain
                        and (
                            base_domain in sub
                            or sub.endswith(f".{base_domain}")
                            or sub == base_domain
                        )
                        and not sub.startswith("www.")
                    ]
                    if domain_filtered_subdomains:
                        for subdomain in domain_filtered_subdomains:
                            st.markdown(f"• 📍 {subdomain}")
                    else:
                        st.markdown(f"*No subdomains discovered for {domain}*")
                else:
                    st.markdown("*No subdomains discovered*")

                st.markdown("---")

                # XHR API calls section
                st.markdown("**🔗 XHR API Calls:**")
                if backend_data.get("xhr_api_calls"):
                    domain_filtered_calls = [
                        api
                        for api in backend_data["xhr_api_calls"]
                        if base_domain
                        and (
                            base_domain in api
                            or api.endswith(f".{base_domain}")
                            or api == base_domain
                        )
                    ]
                    if domain_filtered_calls:
                        for api in domain_filtered_calls:
                            st.markdown(f"• 📡 {api}")
                    else:
                        st.markdown(f"*No XHR API calls found for {domain}*")
                else:
                    st.markdown("*No XHR API calls found*")

            with col2:
                # IP Analysis section
                st.markdown("**📍 IP Analysis & Cloud Matches:**")
                if ip_analysis.get("cloud_ip_matches"):
                    domain_filtered_matches = [
                        match
                        for match in ip_analysis["cloud_ip_matches"]
                        if base_domain
                        and (
                            base_domain in match.get("api_domain", "")
                            or match.get("api_domain", "").endswith(f".{base_domain}")
                            or match.get("api_domain", "") == base_domain
                        )
                    ]
                    if domain_filtered_matches:
                        for match in domain_filtered_matches:
                            api_domain = match.get("api_domain", "unknown")
                            ip = match.get("ip", "unknown")
                            provider = match.get("provider", "unknown")
                            ip_range = match.get("ip_range", "unknown")
                            st.markdown(f"• ☁️ **{api_domain}**")
                            st.markdown(f"  IP: {ip} → {provider}")
                            st.markdown(f"  Range: {ip_range}")
                    else:
                        st.markdown(f"*No cloud IP matches found for {domain}*")
                elif ip_analysis.get("total_ips_checked", 0) > 0:
                    st.markdown(
                        f"*Checked {ip_analysis['total_ips_checked']} IPs - no cloud matches*"
                    )
                else:
                    st.markdown("*No IP analysis performed*")

                st.markdown("---")

                # Direct cloud calls section
                st.markdown("**☁️ Direct Cloud Provider Calls:**")
                if backend_data.get("cloud_provider_domains"):
                    for call in backend_data["cloud_provider_domains"]:
                        if isinstance(call, tuple) and len(call) >= 2:
                            domain_call, provider_name = call[0], call[1]
                            service_type = call[2] if len(call) > 2 else ""
                            service_text = f" ({service_type})" if service_type else ""
                            st.markdown(
                                f"• 🎯 {domain_call} → {provider_name}{service_text}"
                            )
                        else:
                            st.markdown(f"• 🎯 {call}")
                else:
                    st.markdown("*No direct cloud provider calls detected*")

                st.markdown("---")

                # Backend headers section - STRICT domain filtering to prevent contamination
                st.markdown("**🛡️ Backend Headers Analysis:**")
                header_evidence = []

                # CRITICAL: Only process evidence that strictly belongs to this domain
                if result.get("evidence"):
                    for evidence in result["evidence"]:
                        if evidence.get("method") == "XHR API Headers":
                            endpoint = evidence.get("details", {}).get(
                                "endpoint_url", ""
                            )
                            # STRICT filtering: endpoint must contain the exact base domain
                            if (
                                endpoint
                                and base_domain
                                and (
                                    base_domain in endpoint
                                    or endpoint.endswith(f".{base_domain}")
                                    or endpoint == base_domain
                                )
                                # ADDITIONAL CHECK: Ensure no contamination from other domains
                                and not any(
                                    other_domain in endpoint
                                    for other_domain in [
                                        "vetup.com",
                                        "thalesaleniaspace.com",
                                        "everping.eu",
                                    ]
                                    if other_domain != base_domain
                                )
                            ):
                                header_evidence.append(evidence)

                # Only show header evidence if we have valid, domain-specific evidence
                if header_evidence and len(header_evidence) > 0:
                    for evidence in header_evidence:
                        endpoint = evidence.get("details", {}).get(
                            "endpoint_url", "Unknown endpoint"
                        )
                        headers = evidence.get("details", {}).get("headers_found", [])
                        provider = evidence.get("provider", "Unknown")

                        # Double-check endpoint belongs to current domain
                        if base_domain in endpoint:
                            st.markdown(f"• 🛡️ **{endpoint}**")
                            st.markdown(f"  Provider: {provider}")
                            st.markdown(f"  Headers: {len(headers)} found")
                            if headers:
                                st.markdown(f"  **Headers from {endpoint}:**")
                                for header in headers:
                                    st.code(header, language="text")
                else:
                    # EXPLICIT: Only show "no headers" message for current domain
                    st.markdown(f"*No backend-specific headers detected for {domain}*")

        # Separator between cards
        st.markdown("---")


def run_single_domain_analysis(domain: str, headless: bool) -> None:
    """Run analysis on a single domain and store results."""
    # Clean domain input
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    if "/" in domain:
        domain = domain.split("/")[0]
    
    # Create progress indicators
    progress_bar = st.progress(0)
    status_text = st.empty()
    activity_container = st.container()
    
    try:
        status_text.text("🔍 Initializing detector...")
        progress_bar.progress(10)
        
        # Initialize detector
        detector = CloudProviderDetector(headless=headless)
        
        status_text.text(f"🌐 Analyzing {domain}...")
        progress_bar.progress(30)
        
        # Run analysis
        url = f"https://{domain}"
        result = asyncio.run(detector.analyze_website(url))
        
        progress_bar.progress(80)
        status_text.text("💾 Saving results...")
        
        # Prepare result for storage
        storage_result = {
            'domain': domain,
            'url': url,
            'predicted_label': result.get('predicted_label', 'Unknown'),
            'all_detected_providers': result.get('all_detected_providers', []),
            'confidence': result.get('confidence', 0),
            'primary_reason': result.get('primary_reason', 'Unknown'),
            'backend_data': result.get('details', {}).get('backend_data', {}),
            'ip_analysis': result.get('ip_analysis', {}),
            'evidence': result.get('evidence', []),
            'analysis_type': 'single_domain'
        }
        
        # Save to storage
        add_result_to_storage(SINGLE_RESULTS_FILE, storage_result)
        
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")
        
        # Display result immediately
        st.success(f"✅ Analysis complete for {domain}")
        display_single_result_card(storage_result)
        
    except Exception as e:
        st.error(f"❌ Error analyzing {domain}: {str(e)}")
        progress_bar.progress(100)
        status_text.text("❌ Analysis failed")


def run_csv_batch_analysis(df: pd.DataFrame, headless: bool, max_concurrent: int) -> None:
    """Run batch analysis on CSV data."""
    if 'batch_processing' not in st.session_state:
        st.session_state.batch_processing = False
    
    if st.session_state.batch_processing:
        st.warning("⚠️ Batch processing already in progress")
        return
    
    st.session_state.batch_processing = True
    
    # Create progress tracking
    total_domains = len(df)
    progress_bar = st.progress(0)
    status_text = st.empty()
    results_container = st.container()
    
    # Initialize detector
    detector = CloudProviderDetector(headless=headless)
    
    processed = 0
    batch_results = []
    
    try:
        for index, row in df.iterrows():
            domain = str(row['domain']).strip()
            
            # Clean domain
            domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
            if "/" in domain:
                domain = domain.split("/")[0]
            
            if not domain:
                continue
            
            status_text.text(f"🔍 Analyzing {domain} ({processed + 1}/{total_domains})")
            
            try:
                # Run analysis
                url = f"https://{domain}"
                result = asyncio.run(detector.analyze_website(url))
                
                # Prepare result with original CSV data
                storage_result = {
                    'domain': domain,
                    'url': url,
                    'predicted_label': result.get('predicted_label', 'Unknown'),
                    'all_detected_providers': result.get('all_detected_providers', []),
                    'confidence': result.get('confidence', 0),
                    'primary_reason': result.get('primary_reason', 'Unknown'),
                    'backend_data': result.get('details', {}).get('backend_data', {}),
                    'ip_analysis': result.get('ip_analysis', {}),
                    'evidence': result.get('evidence', []),
                    'analysis_type': 'batch',
                    'original_data': row.to_dict()  # Preserve original CSV data
                }
                
                # Save to storage
                add_result_to_storage(BATCH_RESULTS_FILE, storage_result)
                batch_results.append(storage_result)
                
                # Show progress
                with results_container:
                    st.success(f"✅ {domain} → {result.get('predicted_label', 'Unknown')}")
                
            except Exception as e:
                error_result = {
                    'domain': domain,
                    'url': f"https://{domain}",
                    'predicted_label': 'Error',
                    'error': str(e),
                    'analysis_type': 'batch',
                    'original_data': row.to_dict()
                }
                add_result_to_storage(BATCH_RESULTS_FILE, error_result)
                
                with results_container:
                    st.error(f"❌ {domain} → Error: {str(e)}")
            
            processed += 1
            progress_bar.progress(processed / total_domains)
        
        status_text.text(f"✅ Batch analysis complete! Processed {processed} domains")
        st.success(f"🎉 Batch analysis complete! Processed {processed} domains")
        
    except Exception as e:
        st.error(f"❌ Batch processing error: {str(e)}")
    finally:
        st.session_state.batch_processing = False


def display_single_domain_results() -> None:
    """Display stored single domain results."""
    results = load_results(SINGLE_RESULTS_FILE)
    
    if not results:
        st.info("No single domain analyses yet. Analyze a domain above to see results here.")
        return
    
    # Sort by timestamp (newest first)
    results.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Show recent results
    for result in results[:10]:  # Show last 10 results
        display_single_result_card(result)
    
    if len(results) > 10:
        st.info(f"Showing 10 most recent results. Total: {len(results)} analyses stored.")


def display_batch_results() -> None:
    """Display stored batch results."""
    results = load_results(BATCH_RESULTS_FILE)
    
    if not results:
        st.info("No batch analyses yet. Upload and process a CSV above to see results here.")
        return
    
    # Group by timestamp/batch
    batch_groups = {}
    for result in results:
        timestamp = result.get('timestamp', '')
        date_key = timestamp.split('T')[0] if 'T' in timestamp else 'Unknown'
        if date_key not in batch_groups:
            batch_groups[date_key] = []
        batch_groups[date_key].append(result)
    
    # Display by batch
    for date_key in sorted(batch_groups.keys(), reverse=True):
        batch_results = batch_groups[date_key]
        
        with st.expander(f"📊 Batch from {date_key} ({len(batch_results)} domains)", expanded=True):
            # Create summary
            providers = {}
            errors = 0
            for result in batch_results:
                if result.get('predicted_label') == 'Error':
                    errors += 1
                else:
                    provider = result.get('predicted_label', 'Unknown')
                    providers[provider] = providers.get(provider, 0) + 1
            
            # Show summary
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Provider Distribution:**")
                for provider, count in sorted(providers.items()):
                    st.markdown(f"• {provider}: {count}")
            with col2:
                st.markdown("**Batch Stats:**")
                st.markdown(f"• Total: {len(batch_results)}")
                st.markdown(f"• Successful: {len(batch_results) - errors}")
                st.markdown(f"• Errors: {errors}")
            
            # Download results as CSV
            if st.button(f"📥 Download Results CSV", key=f"download_{date_key}"):
                download_batch_results(batch_results, date_key)


def display_single_result_card(result: Dict) -> None:
    """Display a single result card."""
    domain = result.get('domain', 'Unknown')
    predicted = result.get('predicted_label', 'Unknown')
    providers = result.get('all_detected_providers', [])
    confidence = result.get('confidence', 0)
    reason = result.get('primary_reason', 'Unknown')
    timestamp = result.get('timestamp', '')
    
    # Format timestamp
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            time_str = timestamp
    else:
        time_str = 'Unknown'
    
    with st.container():
        # Header
        if predicted == 'Error':
            st.error(f"❌ **{domain}** → Error")
            if 'error' in result:
                st.markdown(f"**Error:** {result['error']}")
        elif predicted == 'Insufficient Data':
            st.info(f"🔍 **{domain}** → Insufficient Data")
        else:
            provider_display = " + ".join(providers) if len(providers) > 1 else predicted
            st.success(f"✅ **{domain}** → {provider_display}")
        
        # Details
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Confidence:** {confidence}%")
            st.markdown(f"**Primary Reason:** {reason}")
        with col2:
            st.markdown(f"**Analyzed:** {time_str}")
            if len(providers) > 1:
                st.markdown(f"**All Providers:** {', '.join(providers)}")
        
        # Expandable details
        if predicted != 'Error':
            with st.expander("📊 Detailed Analysis"):
                backend_data = result.get('backend_data', {})
                ip_analysis = result.get('ip_analysis', {})
                
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**🏢 Subdomains:**")
                    subdomains = backend_data.get('app_subdomains', [])
                    if subdomains:
                        for sub in subdomains[:5]:  # Show first 5
                            st.markdown(f"• {sub}")
                        if len(subdomains) > 5:
                            st.markdown(f"... and {len(subdomains) - 5} more")
                    else:
                        st.markdown("*None found*")
                
                with col2:
                    st.markdown("**☁️ Cloud Matches:**")
                    matches = ip_analysis.get('cloud_ip_matches', [])
                    if matches:
                        for match in matches[:3]:  # Show first 3
                            st.markdown(f"• {match.get('api_domain', 'Unknown')} → {match.get('provider', 'Unknown')}")
                        if len(matches) > 3:
                            st.markdown(f"... and {len(matches) - 3} more")
                    else:
                        st.markdown("*None found*")
        
        st.markdown("---")


def download_batch_results(results: List[Dict], date_key: str) -> None:
    """Create downloadable CSV from batch results."""
    # Flatten results for CSV
    csv_data = []
    for result in results:
        row = {
            'domain': result.get('domain', ''),
            'predicted_provider': result.get('predicted_label', ''),
            'confidence': result.get('confidence', 0),
            'primary_reason': result.get('primary_reason', ''),
            'all_providers': ', '.join(result.get('all_detected_providers', [])),
            'timestamp': result.get('timestamp', ''),
        }
        
        # Add original CSV data if available
        if 'original_data' in result:
            for key, value in result['original_data'].items():
                if key not in row:  # Don't overwrite our analysis columns
                    row[key] = value
        
        csv_data.append(row)
    
    # Create DataFrame and download
    df = pd.DataFrame(csv_data)
    csv = df.to_csv(index=False)
    
    st.download_button(
        label=f"📥 Download {date_key} Results",
        data=csv,
        file_name=f"cloud_provider_analysis_{date_key}.csv",
        mime="text/csv",
        key=f"download_csv_{date_key}"
    )


if __name__ == "__main__":
    main()
